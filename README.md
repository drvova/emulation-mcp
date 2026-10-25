# emulation-mcp

MCP server for CPU and binary emulation in reverse engineering workflows. Five
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
- Syscall and API hooking — intercept, inspect, or **observe** (`when="enter"/"exit"`)
  OS interactions without replacing them
- **Filesystem mapping** (`emu_fs_map`) — serve a host file/dir for a guest path
  (configs, device nodes, a `/flag` the target reads); rootfs overlays for libraries
- **Standard I/O** — feed the guest's stdin (`emu_set_stdin`) and capture its
  stdout/stderr (`emu_capture_output`)
- **Bottom-level instrumentation** — `engine.add_mem_hook` (read/write/unmapped),
  `add_code_hook`, `add_block_hook`, `add_intr_hook` (via `emu_eval`) fire Python
  callbacks on memory access, every instruction/block, or interrupts
- **Native disassembly** (`emu_disassemble`), **full register introspection**
  (`emu_list_registers`), **memory-map listing** (`emu_memory_maps`) and
  C-string reads (`emu_read_string`)
- **Behavioural stats** — `emu_syscall_stats` reports a syscall histogram and the
  strings the program passed to the OS; `engine.hook_insn` (via `emu_eval`) fires
  on specific instructions (`syscall`/`cpuid`/`in`/`out`)
- **Multithreading** — create the session with `engine_options={"multithread":
  true}` and inspect threads with `emu_list_threads` (scheduling is best-effort)
- Persistent sessions with state preservation; native snapshot/restore
- Beyond Linux, the engine also accepts `ostype` `windows`/`uefi`/`dos`/`macos`/
  `freebsd` — those need a matching rootfs (e.g. Windows DLLs) you supply; only
  Linux is exercised by the bundled tests

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
- **Block coverage** — `emu_coverage` (enable / get / clear) records the basic
  blocks executed, for triage and fuzzing-style analysis.
- **Python-callback hooks** — `engine.add_callback_hook(fn, address=None)` (via
  `emu_eval`) runs arbitrary Python on every basic block or at a specific
  address *during* emulation — the bottom-level primitive for custom coverage,
  tracing, taint, etc.
- **Memory-access hooks / data watchpoints** — `engine.add_mem_hook(fn,
  kind="write"|"read", start, end)` (via `emu_eval`) fires a Python callback on
  every guest read or write in an address range (`write` → `fn(addr, data)`,
  `read` → `fn(addr, size)`) — the primitive for data watchpoints, taint, and
  memory tracing. Remove with `engine.hook_remove(id)`.
- **Wide registers** — `emu_register_read_wide` / `emu_register_write_wide`
  read/write registers wider than 64 bits (XMM/YMM/vector/flag aggregates).
- **P-code IL** — `emu_pcode` lifts a block to the SLEIGH intermediate language
  (the semantic IR the VM actually executes, instructions interleaved) — the
  basis for taint, symbolic reasoning, and semantic diffing.
- **MMIO regions** — `engine.map_mmio(start, size, read_cb, write_cb)` (via
  `emu_eval`) maps memory-mapped I/O whose reads/writes are *serviced* by Python
  callbacks rather than backed by RAM — device/peripheral registers, not just
  observed like a watchpoint.
- **Compare logging (RedQueen)** — `emu_cmplog` records the concrete operand
  pairs seen at each comparison during a run (input-to-state): it tells a fuzzer
  exactly which bytes a magic-value or checksum check wants.
- **Symbolization** — `emu_load_symbols` reads an ELF's symbol table (and DWARF),
  then `emu_symbolize` (address → `name+offset`), `emu_lookup_symbol`
  (name → address) and `emu_list_symbols` make traces and crashes readable.
- **GDB remote stub** — `emu_gdb_serve` serves a GDB stub so you can attach a
  real `gdb` (`target remote host:port`). By default it runs the stub in a
  **detached subprocess** seeded from a full snapshot of the session (all mapped
  memory + registers, enumerated from the MMU so loader/Linux mappings are
  included), so the call returns immediately and the MCP session stays
  responsive; `emu_gdb_stop` ends it. The background target has no live kernel,
  so for a Linux program you can inspect and single-step but continuing through
  a syscall needs `background=false` (in-process, with the live kernel).

The stock wheel remains fully supported — these features simply light up when
the extended binding is present (`emu_list_engines` / a session's capabilities
show which are active).

### angr — symbolic execution *(new)*
- Make a register or region of memory **symbolic**, then explore every path
- `emu_explore` drives execution toward a target address (and away from others),
  optionally with exploration techniques (`dfs`, `loopseer`, `lengthlimiter`) or
  Veritesting; `emu_solve` recovers the concrete inputs that get there
- **Constraints & solver introspection** — `emu_constrain` narrows a symbolic
  variable (`==, !=, <, <=, >, >=`) and `emu_value_range` reports its min/max and
  whether it is now unique or over-constrained
- **Function hooking / SimProcedures** — `emu_hook_function` replaces a function
  with a stub that returns a fixed (or unconstrained) value, and `emu_hook_skip`
  no-ops bytes, so exploration skips checksums/libc/irrelevant code
- **Decompiler** — `emu_decompile` lifts a function to pseudo-C; `emu_function_info`
  reports its flags (returning/PLT/syscall), block count, callers and callees
- **Data-flow analyses** — `emu_reaching_definitions`, `emu_data_dependencies`
  (data-dependence graph) and `emu_backward_slice` (which blocks a target
  instruction depends on). Scoped per-function so they stay tractable in large
  binaries
- `emu_cfg` recovers a control-flow graph and lists functions; `emu_call_function`
  runs a function with concrete args (calling-convention aware) and returns the result
- **Fine-grained event inspection** — `engine.add_inspect_hook(event, fn)` (via
  `emu_eval`) fires a Python callback on any angr `state.inspect` event
  (`mem_read`/`mem_write`/`reg_read`/`reg_write`/`instruction`/`call`/`return`/…) —
  the bottom-level primitive for watchpoints, taint and custom analyses
- Works on raw shellcode (shellcode mode) or whole binaries (binary mode)
- Also supports the ordinary concrete workflow (run, step, read state, snapshots)

### Sogen — Windows / Linux user-mode emulation *(new)*
- Runs real PE (and ELF) binaries by loading the **genuine** system libraries
  (ntdll/kernel32/user32 on Windows, the ELF loader + libc on Linux) and
  emulating at the CPU + syscall level — so PE loading, SEH, the PEB/TEB,
  threading, the registry and the filesystem behave as the real loader would
- **Selectable CPU backend** — `engine_options={"backend": "unicorn"}` (default)
  or `{"backend": "icicle"}`; x86-64 and ARM64 guests. Both backends work out of
  the box — the engine points the icicle backend at the Ghidra SLEIGH specs that
  ship inside the sogen package
- Create a session with `engine="sogen"`, `ostype="windows"|"linux"`, a
  `binary_path` (or omit it for an empty emulator) and `rootfs` = the emulation
  root. Then `emu_run` / `emu_step`, read/write/map/protect/unmap memory,
  read/write registers, and `emu_snapshot_*` (snapshots use Sogen's
  `serialize_state`/`deserialize_state`)
- **Real OS emulation** — loads the genuine loader + libraries and emulates
  syscalls; `emu_syscall_stats` reports the syscall histogram from a run,
  `emu_modules` lists the modules the loader brought in (exe + shared objects)
- **Symbolization** — `emu_load_symbols` / `emu_symbolize` / `emu_lookup_symbol`
  / `emu_list_symbols` resolve addresses ↔ names from loaded modules' export
  tables (e.g. a libc address → `malloc+0x4`)
- **Disassembly** — `emu_disassemble` disassembles guest code with capstone
  (x86-64 / ARM64)
- **API / symbol interception** — `engine.hook_api("kernel32!Sleep", fn)` on
  Windows or `engine.hook_api("libc!strcmp", fn)` on Linux (via `emu_eval`)
- **Callback hooks** — per-instruction (`add_code_hook`), basic-block
  (`add_block_hook`), memory read/write/violation over a range (`add_mem_hook`),
  interrupt (`add_intr_hook`) and instruction-type (`hook_insn`) callbacks
- **I/O capture** — `emu_capture_output` tees the guest's stdout/stderr
- **Register introspection** — `emu_list_registers` dumps the full register file
- Capabilities are feature-detected at session creation, so a session advertises
  only what the installed Sogen build actually exposes
- Install with the helper `./scripts/build-sogen.sh /path/to/venv/bin/python` —
  it installs the prebuilt wheel on CPython 3.9/3.10 and otherwise builds from
  source with the SDL3/tools CMake options off. Windows needs an emulation root
  (`https://sogen.dev/root.zip`); Linux can use the host `/`. Sogen is GPL-2.0-only

### Shared features
- Session management with unique IDs, auto-cleanup after idle timeout
- Memory search across the emulated address space
- Export evidence (register dumps, trace summaries) for reporting
- A common memory layout across the CPU engines, so addresses are interchangeable

## Engine capabilities at a glance

| Capability          | unicorn | qiling | icicle | angr | sogen |
|---------------------|:-------:|:------:|:------:|:----:|:-----:|
| shellcode           |   ✓     |        |   ✓    |  ✓   |       |
| binary loading      |         |   ✓    |        |  ✓   |  ✓    |
| OS emulation        |         |   ✓    |        |      |  ✓    |
| syscall / API hooks |         |   ✓    |        |      |  ✓    |
| address hooks       |   ✓     |   ✓    |   ✓    |  ✓   |  ✓    |
| instruction trace   |   ✓     |        |   ✓    |  ✓   |       |
| memory trace        |   ✓     |        |        |      |       |
| snapshots           |   ✓     |   ✓    |   ✓    |  ✓   |  ✓    |
| symbolic execution  |         |        |        |  ✓   |       |
| constraints / solver|         |        |        |  ✓   |       |
| data-flow analyses  |         |        |        |  ✓   |       |
| CFG / functions     |         |        |        |  ✓   |       |
| function calls      |         |        |        |  ✓   |       |
| decompiler          |         |        |        |  ✓   |       |
| function hooks      |         |        |        |  ✓   |       |
| event inspection    |         |        |        |  ✓   |       |
| memory management   |         |        |   ✓    |      |  ✓    |
| breakpoints         |         |        |   ✓    |      |       |
| register introspection |      |   ✓    |   ✓    |      |  ✓    |
| native disassembly  |         |   ✓    |  ✓ †   |      |  ✓ ‡  |
| callback hooks      |         |   ✓    |  ✓ †   |      |  ✓    |
| memory hooks        |         |   ✓    |  ✓ †   |      |  ✓    |
| p-code IL           |         |        |  ✓ †   |      |       |
| MMIO regions        |         |        |  ✓ †   |      |       |
| compare logging     |         |        |  ✓ †   |      |       |
| symbolization       |         |        |  ✓ †   |      |  ✓ ‡  |
| filesystem mapping  |         |   ✓    |        |      |       |
| stdin / stdout I/O  |         |   ✓    |        |      |  ✓ §  |
| memory-map listing  |         |   ✓    |        |      |  ✓ ‡  |
| syscall statistics  |         |   ✓    |        |      |  ✓    |
| instruction hooks   |         |   ✓    |        |      |  ✓    |
| multithreading      |         |   ✓    |        |      |       |
| reverse execution   |         |        |  ✓ †   |      |       |
| call stack          |         |        |  ✓ †   |      |       |
| wide registers      |         |        |  ✓ †   |      |       |
| Linux OS emulation  |         |   ✓    |  ✓ †   |      |  ✓    |
| block coverage      |         |        |  ✓ †   |      |       |
| GDB remote stub     |         |        |  ✓ †   |      |       |

† Icicle feature available with the extended binding (`icicle_ext/`); see below.
‡ Sogen: disassembly is via capstone; symbolization and memory-map listing come
from loaded modules' export tables / image bases (run the program first).
§ Sogen I/O is stdout/stderr capture; feeding stdin is not exposed by its API.

### Known boundaries

Each engine's common reverse-engineering surface is wired in. A few specialist
corners are reachable only with extra setup, or deliberately left to the
framework:

- **Qiling non-Linux targets** (Windows/UEFI/DOS/macOS/FreeBSD) are accepted via
  `ostype`, but need a matching rootfs you supply (e.g. Windows DLLs); only Linux
  is exercised by the bundled tests.
- **angr concrete/symbolic (`Symbion`)** needs an external concrete executor
  (a real process via `avatar2`/gdb) that isn't part of this server; use
  `emu_call`/`emu_eval` to drive it if you have one attached.
- **Icicle JIT internals and the native AFL trace format** have no useful Python
  mapping (the server ships its own `emu_fuzz` loop); see `icicle_ext/README.md`.
- **Sogen** emulates Windows and Linux user mode. Windows targets need a prepared
  emulation root (system DLLs + registry, e.g. `https://sogen.dev/root.zip`);
  Linux can use the host `/`. A few things are bounded by Sogen's Python API, not
  by this wrapper: feeding **stdin** isn't exposed (stdout/stderr capture is), and
  it offers no full memory-region enumeration — so `emu_memory_maps` /
  `emu_memory_search` cover the loaded-module regions, and a byte-pattern search of
  anonymous allocations/stack means reading a known range yourself. Symbolization
  resolves exported/dynamic symbols from loaded modules.

Anything not yet a first-class tool is still reachable through the reflective
tools (`emu_describe` / `emu_call` / `emu_eval`, below).

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

See [CAPABILITIES.md](CAPABILITIES.md) for the full reference: every tool grouped
by category, the per-engine capability matrix, and which engine each tool
targets.

Session/exec/memory/register/hook/snapshot/trace tools are shared across engines
(`emu_create_session`, `emu_run`, `emu_step`, `emu_memory_*`, `emu_registers_read`,
`emu_register_write`, `emu_hook_address`, `emu_snapshot_*`, `emu_get_trace`, ...).
Engine-specific tools:

- `emu_list_engines` — discover installed engines and capabilities
- `emu_hook_syscall`, `emu_hook_api` — Qiling only (with `when="call"/"enter"/"exit"`)
- `emu_fs_map`, `emu_set_stdin`, `emu_capture_output` — filesystem mapping and stdin/stdout I/O (Qiling)
- `emu_memory_maps`, `emu_read_string` — list mapped regions / read a C string (Qiling)
- `emu_syscall_stats`, `emu_list_threads` — syscall histogram / thread listing (Qiling)
- `emu_set_symbolic_register`, `emu_set_symbolic_memory`, `emu_explore`, `emu_solve` — angr only
- `emu_constrain`, `emu_value_range` — add solver constraints / query a variable's range (angr)
- `emu_cfg`, `emu_call_function` — CFG/function listing and function execution (angr)
- `emu_decompile`, `emu_function_info` — pseudo-C decompilation and function metadata (angr)
- `emu_hook_function`, `emu_hook_skip` — replace/skip functions with SimProcedures (angr)
- `emu_register_read_wide`, `emu_register_write_wide` — >64-bit registers (extended Icicle)
- `emu_memory_unmap`, `emu_memory_protect` — runtime memory management (Icicle)
- `emu_breakpoint_add`, `emu_breakpoint_remove` — execution breakpoints (Icicle)
- `emu_list_registers` — full register-file introspection (Icicle, Qiling)
- `emu_step_back`, `emu_goto_icount` — reverse execution / time-travel (extended Icicle)
- `emu_disassemble` — native disassembly (extended Icicle, Qiling); `emu_callstack` — call stack (extended Icicle)
- `emu_pcode` — lift a block to SLEIGH p-code IL (extended Icicle)
- `emu_cmplog` — compare logging / RedQueen operand capture (extended Icicle)
- `emu_load_symbols`, `emu_symbolize`, `emu_lookup_symbol`, `emu_list_symbols` — ELF/DWARF symbolization (extended Icicle)
- `emu_coverage` — basic-block coverage enable/get/clear (extended Icicle)
- `emu_gdb_serve` / `emu_gdb_stop` — serve a GDB remote stub (non-blocking by
  default) to attach a real debugger (extended Icicle)
- `emu_fuzz` — coverage-guided fuzzing loop (any engine; see below)
- `emu_compare_engines` — Unicorn vs. Icicle differential check

### Coverage-guided fuzzing

`emu_fuzz` turns the primitives into a small coverage-guided fuzzer, no external
framework: it snapshots a baseline, then repeatedly restores it, writes a
mutated input to a chosen address, runs a code range, keeps inputs that reach
new coverage, and reports inputs that fault. It uses Icicle's native block
coverage when available (very fast) and falls back to the instruction trace on
any engine that can trace, so it works on Unicorn too. Memory is reset between
runs on both engines (Unicorn snapshots now capture mapped memory, not just
registers).

### Reaching the whole engine surface

The curated tools cover the common workflow. For anything they don't, three
reflective tools expose the *entire* engine API without a dedicated tool per
call:

- `emu_describe` — list every method/attribute reachable on a session, for the
  underlying emulator object (`target="native"`: icicle VM, unicorn `Uc`,
  qiling `Ql`, angr `SimState`) or the wrapper (`target="engine"`).
- `emu_call` — invoke any of those methods (or read any attribute) by name.
  Arguments are JSON with convenience coercions: `"0x1000"` → int,
  `{"hex": "deadbeef"}` or `{"bytes": [...]}` → bytes. Private members are
  blocked.
- `emu_eval` — run a Python snippet against the session (`engine` and `native`
  in scope). This executes arbitrary Python in the server process, so it is
  **off by default**; enable it only in a trusted local setup by starting the
  server with `EMU_ENABLE_EVAL=1`.

Together these mean a capability that isn't yet a first-class tool is still
reachable — call it directly, or script it with `emu_eval`.

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
