# emulation-mcp

MCP server for CPU and binary emulation in reverse engineering workflows. Four
pluggable backends cover everything from raw shellcode to full binaries to
symbolic execution; each is loaded lazily, so you only install the ones you use.

## Engines

Call `emu_list_engines` at any time to see which backends are installed and what
each can do.

### Unicorn Engine — lightweight CPU emulation
- Emulate shellcode and code snippets across architectures (x86, x64, ARM, ARM64, MIPS)
- Map and manage memory, read/write memory and registers
- Single-step or run to an address, instruction/memory tracing, address hooks
- Snapshot and restore emulation state

### Qiling Framework — full binary emulation
- Load and run full ELF/PE binaries with OS-level support (Linux, Windows, ...)
- Syscall and API hooking — intercept and inspect OS interactions
- Filesystem/registry/network emulation; rootfs overlays for shared libraries
- Persistent sessions with state preservation between tool calls

### Icicle — SLEIGH-based CPU emulation *(new)*
- CPU emulator built on Ghidra's SLEIGH instruction semantics
- Reaches architectures Unicorn does not, including **RISC-V (32/64)**, **PowerPC
  (32/64)**, and **MSP430**, plus x86/x64/ARM/ARM64/MIPS
- An entirely independent implementation — use `emu_compare_engines` to
  cross-check a Unicorn result when it looks suspicious
- Same shellcode workflow as Unicorn: memory, registers, tracing, hooks, snapshots
- Self-modifying code is detected and reported (not transparently re-translated)
- **Wraps the full `icicle-emu` Python binding:** runtime memory management
  (`emu_memory_unmap`, `emu_memory_protect`), execution breakpoints
  (`emu_breakpoint_add`/`_remove`, halt-and-resume), free run (leave `end_addr`
  empty), full register-file introspection (`emu_list_registers` — all ~839
  x86-64 registers, offsets and sizes), and VM constructor knobs via
  `engine_options` (`jit`, `shadow_stack`, `track_uninitialized`, `mem_capacity`, …).

#### Extended Icicle binding (`icicle_ext/`) — reaching the rest of the framework

The PyPI `icicle-emu` wheel exposes only a slice of Icicle. Building the
extended binding (`./icicle_ext/build.sh <python>`, needs Rust + maturin) unlocks
much more of the framework, and the wrapper detects it automatically:

- **Reverse execution & time-travel** — `emu_step_back`, `emu_goto_icount`
  (rewind instructions or jump to any instruction count).
- **Native VM snapshots** — complete register+memory snapshots (faster and more
  complete than the per-region fallback).
- **SLEIGH-native disassembly** — `emu_disassemble` straight from the emulator's
  own semantics, no external disassembler.
- **Call stack** — `emu_callstack`.
- **Linux userspace emulation** — create a session with `engine_options={"os":
  "linux"}` and a `binary_path`; the emulated kernel loads the ELF (argv/env)
  and services syscalls, so you can run a whole Linux program, not just a
  snippet. Static binaries work directly; see `icicle_ext/README.md`.

The stock wheel remains fully supported — these features simply light up when
the extended binding is present (`emu_list_engines` / a session's capabilities
show which are active).

### angr — symbolic execution *(new)*
- Make a register or region of memory **symbolic**, then explore every path
- `emu_explore` drives execution toward a target address (and away from others)
  and `emu_solve` recovers the concrete inputs that get there
- Works on raw shellcode (shellcode mode) or whole binaries (binary mode)
- Also supports the ordinary concrete workflow (run, step, read state, snapshots)

### Shared features
- Session management with unique IDs, auto-cleanup after idle timeout
- Memory search across the emulated address space
- Export evidence (register dumps, trace summaries) for reporting
- A common memory layout across the CPU engines, so addresses are interchangeable

## Engine capabilities at a glance

| Capability          | unicorn | qiling | icicle | angr |
|---------------------|:-------:|:------:|:------:|:----:|
| shellcode           |   ✓     |        |   ✓    |  ✓   |
| binary loading      |         |   ✓    |        |  ✓   |
| OS emulation        |         |   ✓    |        |      |
| syscall / API hooks |         |   ✓    |        |      |
| address hooks       |   ✓     |   ✓    |   ✓    |  ✓   |
| instruction trace   |   ✓     |        |   ✓    |  ✓   |
| memory trace        |   ✓     |        |        |      |
| snapshots           |   ✓     |   ✓    |   ✓    |  ✓   |
| symbolic execution  |         |        |        |  ✓   |
| memory management   |         |        |   ✓    |      |
| breakpoints         |         |        |   ✓    |      |
| register introspection |      |        |   ✓    |      |
| reverse execution   |         |        |  ✓ †   |      |
| native disassembly  |         |        |  ✓ †   |      |
| call stack          |         |        |  ✓ †   |      |
| Linux OS emulation  |         |   ✓    |  ✓ †   |      |

† Icicle feature available with the extended binding (`icicle_ext/`); see below.

## Requirements

- Python 3.10+
- Unicorn Engine 2.x (`pip install unicorn`) and Capstone (`pip install capstone`)
- Optional: Qiling (`pip install qiling`), Icicle (`pip install icicle-emu`),
  angr (`pip install angr`)

## Setup

```bash
pip install -r requirements.txt            # core + Unicorn + Qiling
pip install -r requirements-optional.txt   # adds Icicle and angr
python server.py
```

For Qiling binary emulation you also need a rootfs matching the target OS and
architecture. See the [Qiling documentation](https://docs.qiling.io/) for setup.

## Typical workflows

**Shellcode (unicorn / icicle):**
1. `emu_create_session` with `engine="unicorn"` (or `"icicle"`) and an `arch`
2. `emu_memory_write` the code, set registers, `emu_run`
3. Inspect registers / memory / trace; snapshot to explore branches

**Full binary (qiling):**
1. `emu_create_session` with `engine="qiling"`, `binary_path`, `rootfs`
2. `emu_hook_syscall` / `emu_hook_api`, then `emu_run`

**Symbolic (angr):**
1. `emu_create_session` with `engine="angr"` (shellcode or `binary_path`)
2. `emu_memory_write` the code (shellcode mode), set the start address
3. `emu_set_symbolic_register` / `emu_set_symbolic_memory` for the inputs
4. `emu_explore` toward the interesting address, then `emu_solve` for the input

**Cross-checking a result:**
- `emu_compare_engines` runs the same shellcode on two CPU engines (Unicorn and
  Icicle) and reports any registers that disagree.

## Tools

Session/exec/memory/register/hook/snapshot/trace tools are shared across engines
(`emu_create_session`, `emu_run`, `emu_step`, `emu_memory_*`, `emu_registers_read`,
`emu_register_write`, `emu_hook_address`, `emu_snapshot_*`, `emu_get_trace`, ...).
Engine-specific tools:

- `emu_list_engines` — discover installed engines and capabilities
- `emu_hook_syscall`, `emu_hook_api` — Qiling only
- `emu_set_symbolic_register`, `emu_set_symbolic_memory`, `emu_explore`, `emu_solve` — angr only
- `emu_memory_unmap`, `emu_memory_protect` — runtime memory management (Icicle)
- `emu_breakpoint_add`, `emu_breakpoint_remove` — execution breakpoints (Icicle)
- `emu_list_registers` — full register-file introspection (Icicle)
- `emu_step_back`, `emu_goto_icount` — reverse execution / time-travel (extended Icicle)
- `emu_disassemble`, `emu_callstack` — native disassembly and call stack (extended Icicle)
- `emu_compare_engines` — Unicorn vs. Icicle differential check

## Architecture

```
emulation/
  server.py              # MCP server, tool definitions
  session_manager.py     # Session lifecycle, ID management
  engines/
    __init__.py          # Lazy engine registry + capability discovery
    base.py              # Shared types, layout constants, capability flags
    unicorn_engine.py    # Unicorn wrapper
    qiling_engine.py     # Qiling wrapper
    icicle_engine.py     # Icicle (SLEIGH) wrapper
    angr_engine.py       # angr symbolic/concrete wrapper
  icicle_ext/            # Extended Icicle PyO3 binding (optional, built from source)
    lib.rs               # Full-surface binding source
    build.sh             # Clone-pinned, overlay, maturin build + install
  tests/
```

Adding another engine is a matter of writing an `engines/<name>_engine.py` that
subclasses `BaseEngine`, declaring its `CAPABILITIES`, and registering it in
`engines/__init__.py` — the server tools pick it up through the registry and the
capability checks.

## License

CC BY-NC-SA 4.0 — see [LICENSE](LICENSE).
