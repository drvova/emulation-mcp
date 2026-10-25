# Capabilities reference

A complete map of what this MCP server exposes: the engines, the per-engine
capability flags, and all `emu_*` tools grouped by what they do. Call
`emu_list_engines` at runtime to see which engines are installed and which
capabilities are live in the current environment.

Tools that are **shared** work on every engine (some are gated by a capability
and return a clear error on engines that lack it). Tools tied to one engine are
marked. Capability names in parentheses (e.g. `'coverage'`) are the flags a
session advertises; a tool checks the flag and reports if the engine doesn't
have it.

## Tool surface: one universal tool

A fixed catalog of typed tools is not the interface. Engines, archs and installs
each support a different subset of capabilities, and models differ in which
tools they have and how well they use them, so privileging any hand-picked set
biases the system. By **default the server advertises exactly one tool, `emu`**,
and a model builds whatever working set it needs on top of it:

```
emu(action="describe")                      # installed engines + how to start
emu(action="create", options={...})         # -> session_id (engine+arch, or binary+rootfs)
emu(action="describe", session_id=sid)       # that engine's LIVE capabilities + signatures
emu(action="call", session_id=sid, method=..., args=[...], target="engine"|"native")
emu(action="sessions") | emu(action="close", session_id=sid) | emu(action="eval", ...)
```

- **`emu(action="describe", session_id=…)`** reports the session's **live
  capabilities** and every method's **signature** (from `inspect`, or the
  docstring for native methods), so the model knows exactly what this
  engine/arch supports and how to call it.
- **`emu(action="call", …)`** then invokes any of those methods (JSON args, hex/bytes
  coercions) — reaching the full engine API (hooks, snapshots, symbolization,
  CFG, fuzzing, …) with no dedicated tool per capability.

Set **`EMU_EXPOSE_TYPED_TOOLS=1`** to *also* advertise the full catalog of
explicit `emu_*` verbs documented below (for clients or models that prefer
discoverable, typed verbs). The flag only changes what is **advertised** — every
`emu_*` function exists regardless, `emu` dispatches to it, and it stays
reachable through `emu(action="call", …)`. The rest of this document lists that
full catalog; each entry maps to a `method` you can invoke via `emu`.

## Engines

| Engine | Role | Typical input | Notes |
|---|---|---|---|
| **Unicorn** | Lightweight CPU emulation | shellcode | x86, x64, ARM, ARM64, MIPS |
| **Icicle** | SLEIGH-based CPU emulation | shellcode, Linux ELF | also RISC-V 32/64, PowerPC 32/64, MSP430; the deep features need the extended binding (`icicle_ext/`) |
| **angr** | Symbolic execution + static analysis | shellcode, binary | the only engine with `symbolic`, CFG/decompiler/data-flow |
| **Qiling** | Full binary / OS emulation | binary + rootfs | Linux (tested); Windows/UEFI/DOS/macOS/FreeBSD accepted with a matching rootfs |
| **Sogen** | Windows / Linux user-mode emulation | PE/ELF + emulation root | loads the **real** system libraries (ntdll/kernel32/…); selectable Unicorn or Icicle CPU backend; x86-64 and ARM64 guests |

The CPU engines (Unicorn, Icicle, angr) share one memory layout, so addresses are
interchangeable and `emu_compare_engines` can run the same shellcode on two of
them and diff the result. Qiling and Sogen are OS-level emulators with their own
layouts.

**Installing Sogen:** prebuilt wheels exist for CPython 3.9 and 3.10 only; on
other interpreters it builds from source (CMake + C++/Rust). Use the helper,
which picks a wheel when one exists and otherwise does the source build with the
SDL3 GUI/audio and standalone tools turned off (so no X11/audio dev packages are
needed):

```bash
./scripts/build-sogen.sh /path/to/your/venv/bin/python
```

Windows emulation needs a prepared emulation root (system DLLs + registry, e.g.
`https://sogen.dev/root.zip`); Linux emulation can use the host `/`. Sogen is
GPL-2.0-only and, like every engine here, is optional and loaded lazily — the
server runs without it. See `requirements-optional.txt`.

## Capability matrix

| Capability | unicorn | qiling | icicle | angr | sogen |
|---|:--:|:--:|:--:|:--:|:--:|
| shellcode | ✓ | | ✓ | ✓ | |
| binary loading | | ✓ | | ✓ | ✓ |
| OS emulation | | ✓ | ✓ † | | ✓ |
| syscall / API hooks | | ✓ | | | ✓ |
| address hooks | ✓ | ✓ | ✓ | ✓ | ✓ |
| instruction trace | ✓ | | ✓ | ✓ | |
| memory trace | ✓ | | | | |
| snapshots | ✓ | ✓ | ✓ | ✓ | ✓ |
| memory management | | | ✓ | | ✓ |
| breakpoints | | | ✓ | | |
| register introspection | | ✓ | ✓ | | ✓ |
| native disassembly | | ✓ | ✓ † | | ✓ ‡ |
| callback hooks | | ✓ | ✓ † | | ✓ |
| memory hooks | | ✓ | ✓ † | | ✓ |
| reverse execution | | | ✓ † | | |
| call stack | | | ✓ † | | |
| wide registers | | | ✓ † | | |
| block coverage | | | ✓ † | | |
| GDB remote stub | | | ✓ † | | |
| p-code IL | | | ✓ † | | |
| MMIO regions | | | ✓ † | | |
| compare logging (RedQueen) | | | ✓ † | | |
| symbolization | | | ✓ † | | ✓ ‡ |
| filesystem mapping | | ✓ | | | |
| stdin / stdout I/O | | ✓ | | | ✓ § |
| syscall statistics | | ✓ | | | ✓ |
| instruction hooks | | ✓ | | | ✓ |
| multithreading | | ✓ | | | |
| symbolic execution | | | | ✓ | |
| constraints / solver | | | | ✓ | |
| CFG / functions | | | | ✓ | |
| function calls | | | | ✓ | |
| decompiler | | | | ✓ | |
| function hooks | | | | ✓ | |
| event inspection | | | | ✓ | |
| data-flow analyses | | | | ✓ | |

† Icicle feature available with the extended binding (`icicle_ext/`, built from
source). The stock `icicle-emu` wheel supports the un-daggered Icicle rows.

‡ Sogen guest ARM64 is supported alongside x86-64. Native disassembly is done
with capstone on guest bytes (Sogen has no Python disassembler). Symbolization
resolves against the export tables of loaded modules, so names become available
once the target and its libraries have loaded (run the program first); it covers
exported/dynamic symbols, not every static-only local symbol.

§ Sogen I/O is stdout/stderr capture (via `on_stdout`/`on_stderr` callbacks);
feeding stdin is not exposed by Sogen's Python API, so it is not wired.

## Tools by category

### Sessions & execution (shared)
- `emu_create_session` — open a session for an engine/arch (or binary + rootfs)
- `emu_list_sessions` / `emu_close_session` — manage active sessions
- `emu_emulate_shellcode` — one-shot: temp session, run code, return results
- `emu_load_function` — load a function from a binary into a ready-to-run session
- `emu_run` — run (begin/end/timeout)
- `emu_step` — step N instructions

### Memory (shared; some Icicle-gated)
- `emu_memory_read` / `emu_memory_write` / `emu_memory_map` — read/write/map
- `emu_memory_search` — find a byte pattern across mapped memory
- `emu_memory_unmap` / `emu_memory_protect` — runtime mgmt (`'memory_management'`, Icicle)
- `emu_memory_maps` — list mapped regions (Qiling)
- `emu_read_string` — read a NUL-terminated string (Qiling)

### Registers (shared; some gated)
- `emu_registers_read` / `emu_register_write` — common registers
- `emu_list_registers` — full register file (`'register_introspection'`; Icicle, Qiling)
- `emu_register_read_wide` / `emu_register_write_wide` — >64-bit vector/flag regs (`'wide_registers'`, Icicle)

### Hooks & instrumentation
- `emu_hook_address` — log/trace at an address (shared)
- `emu_list_hooks` / `emu_remove_hook` — manage hooks (shared)
- `emu_hook_syscall` / `emu_hook_api` — intercept OS calls, `when=call/enter/exit` (Qiling)
- Callback hooks (block/address/memory/interrupt/instruction) and **MMIO regions**
  are reachable via `emu_eval` (they take Python callables): Icicle
  `add_callback_hook` / `add_mem_hook` / `map_mmio`; Qiling `add_code_hook` /
  `add_block_hook` / `add_intr_hook` / `hook_insn`; angr `add_inspect_hook`

### Breakpoints & time-travel (Icicle)
- `emu_breakpoint_add` / `emu_breakpoint_remove` — halt-and-resume (`'breakpoints'`)
- `emu_step_back` / `emu_goto_icount` — reverse execution / time-travel (`'reverse_execution'`)

### Disassembly, IL & symbols
- `emu_disassemble` — native disassembly (Icicle SLEIGH, Qiling capstone)
- `emu_pcode` — lift a block to SLEIGH p-code IL (`'pcode_il'`, Icicle)
- `emu_callstack` — return-address call stack (`'callstack'`, Icicle)
- `emu_load_symbols` / `emu_symbolize` / `emu_lookup_symbol` / `emu_list_symbols` — ELF + DWARF symbolization (`'symbols'`, Icicle)

### Coverage & fuzzing
- `emu_coverage` — enable/get/clear basic-block coverage (`'coverage'`, Icicle)
- `emu_cmplog` — compare-operand logging, RedQueen / input-to-state (`'cmplog'`, Icicle)
- `emu_fuzz` — coverage-guided fuzz loop over a code region (any engine that can trace/cover)

### Debugging (Icicle)
- `emu_gdb_serve` / `emu_gdb_stop` — serve a GDB remote stub (non-blocking by default) so a real `gdb` can attach (`'gdb'`)

### Snapshots & tracing (shared)
- `emu_snapshot_save` / `emu_snapshot_restore` / `emu_snapshot_list`
- `emu_get_trace` / `emu_enable_trace` / `emu_clear_trace`
- `emu_export_evidence` — structured state dump for reporting

### Qiling binary/OS extras
- `emu_fs_map` — map a host file/dir into the guest FS (`'filesystem'`)
- `emu_set_stdin` / `emu_capture_output` — feed stdin, capture stdout/stderr (`'io'`)
- `emu_syscall_stats` — syscall histogram + observed strings
- `emu_list_threads` — thread listing (multithread mode)

### Sogen Windows/Linux user-mode
Sogen drives the shared tools: `emu_create_session` (`engine="sogen"`,
`ostype="windows"|"linux"`, `binary_path`, `rootfs`=emulation root,
`engine_options={"backend": "unicorn"|"icicle"}`), then `emu_run` / `emu_step`,
`emu_memory_read` / `emu_memory_write` / `emu_memory_map` / `emu_memory_protect`
/ `emu_memory_unmap`, `emu_registers_read` / `emu_register_write`,
`emu_snapshot_*`. In addition it exposes:
- `emu_list_registers` — full x86-64 / ARM64 register file (`'register_introspection'`)
- `emu_disassemble` — native disassembly (capstone) of guest code (`'disassembly'`)
- `emu_load_symbols` / `emu_symbolize` / `emu_lookup_symbol` / `emu_list_symbols`
  — resolve addresses ↔ names from loaded modules' exports (`'symbols'`)
- `emu_modules` — list loaded modules (exe + shared objects/DLLs) with base/exports
- `emu_syscall_stats` — syscall histogram gathered during the run
- `emu_memory_maps` — loaded-module regions; `emu_read_string` — NUL-terminated strings
- `emu_hook_api` — intercept a Windows API (`kernel32!Sleep`) or Linux symbol (`'api_hooks'`)
- `emu_capture_output` — capture the guest's stdout/stderr (`'io'`)
- `emu_hook_address` and the callback hooks (`add_code_hook` / `add_block_hook` /
  `add_mem_hook` (incl. `kind="violation"`) / `add_intr_hook` / `hook_insn`) via
  `emu_eval` (`'callback_hooks'`, `'memory_hooks'`)

### Symbolic execution & static analysis (angr)
- `emu_set_symbolic_register` / `emu_set_symbolic_memory` — make inputs symbolic
- `emu_explore` — explore paths to a target (techniques: dfs/loopseer/lengthlimiter; veritesting)
- `emu_solve` — recover concrete inputs
- `emu_constrain` / `emu_value_range` — add constraints, query a variable's range (`'constraints'`)
- `emu_cfg` / `emu_function_info` — control-flow graph and function metadata (`'cfg'`)
- `emu_decompile` — lift a function to pseudo-C (`'decompiler'`)
- `emu_call_function` — run a function with concrete args (`'function_call'`)
- `emu_reaching_definitions` / `emu_data_dependencies` / `emu_backward_slice` — data-flow analyses (`'dataflow'`)
- `emu_hook_function` / `emu_hook_skip` — replace/skip functions with SimProcedures (`'sim_procedures'`)

### Cross-engine & discovery
- `emu_list_engines` — installed engines and live capabilities
- `emu_compare_engines` — Unicorn vs Icicle differential on the same shellcode

### The one tool (always advertised)
`emu` (see **Tool surface** above) is the primary interface: it reaches the full
engine API without a dedicated tool per capability, and is all a model needs
even when the typed catalog is not advertised. Its actions:
- `describe` — with no session, lists installed engines + how to start; with a
  session, reports its **live capabilities** plus every method's **signature**
  and one-line doc. Start here to learn what an engine/arch supports.
- `create` — open a session (`options={"engine": …, "arch": …}` or
  `{"engine": "sogen", "ostype": …, "binary_path": …}`).
- `call` — invoke any method by name (JSON args with hex/bytes coercions;
  private members blocked; `target="engine"|"native"`). Drives hooks, snapshots,
  symbolization, CFG, fuzzing, … on any engine.
- `sessions` / `close` — list or close sessions.
- `eval` — run a Python snippet against the session. This executes arbitrary
  Python in the server process, so it is **off by default**; enable it only in a
  trusted local setup with `EMU_ENABLE_EVAL=1`. It is the way to drive the
  callback-based APIs (hooks, MMIO) that can't cross the JSON tool boundary.

The typed `emu_*` verbs listed throughout this document are advertised only when
`EMU_EXPOSE_TYPED_TOOLS=1`; otherwise invoke them (or the engine methods behind
them) through `emu(action="call", …)`.

## See also

- `README.md` — overview, setup, typical workflows
- `icicle_ext/README.md` — the extended Icicle binding (what it adds, how to
  build it, and what is deliberately left unexposed)
