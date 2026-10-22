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

## Engines

| Engine | Role | Typical input | Notes |
|---|---|---|---|
| **Unicorn** | Lightweight CPU emulation | shellcode | x86, x64, ARM, ARM64, MIPS |
| **Icicle** | SLEIGH-based CPU emulation | shellcode, Linux ELF | also RISC-V 32/64, PowerPC 32/64, MSP430; the deep features need the extended binding (`icicle_ext/`) |
| **angr** | Symbolic execution + static analysis | shellcode, binary | the only engine with `symbolic`, CFG/decompiler/data-flow |
| **Qiling** | Full binary / OS emulation | binary + rootfs | Linux (tested); Windows/UEFI/DOS/macOS/FreeBSD accepted with a matching rootfs |

The CPU engines share one memory layout, so addresses are interchangeable and
`emu_compare_engines` can run the same shellcode on two of them and diff the
result.

## Capability matrix

| Capability | unicorn | qiling | icicle | angr |
|---|:--:|:--:|:--:|:--:|
| shellcode | ✓ | | ✓ | ✓ |
| binary loading | | ✓ | | ✓ |
| OS emulation | | ✓ | ✓ † | |
| syscall / API hooks | | ✓ | | |
| address hooks | ✓ | ✓ | ✓ | ✓ |
| instruction trace | ✓ | | ✓ | ✓ |
| memory trace | ✓ | | | |
| snapshots | ✓ | ✓ | ✓ | ✓ |
| memory management | | | ✓ | |
| breakpoints | | | ✓ | |
| register introspection | | ✓ | ✓ | |
| native disassembly | | ✓ | ✓ † | |
| callback hooks | | ✓ | ✓ † | |
| memory hooks | | ✓ | ✓ † | |
| reverse execution | | | ✓ † | |
| call stack | | | ✓ † | |
| wide registers | | | ✓ † | |
| block coverage | | | ✓ † | |
| GDB remote stub | | | ✓ † | |
| p-code IL | | | ✓ † | |
| MMIO regions | | | ✓ † | |
| compare logging (RedQueen) | | | ✓ † | |
| symbolization | | | ✓ † | |
| filesystem mapping | | ✓ | | |
| stdin / stdout I/O | | ✓ | | |
| syscall statistics | | ✓ | | |
| instruction hooks | | ✓ | | |
| multithreading | | ✓ | | |
| symbolic execution | | | | ✓ |
| constraints / solver | | | | ✓ |
| CFG / functions | | | | ✓ |
| function calls | | | | ✓ |
| decompiler | | | | ✓ |
| function hooks | | | | ✓ |
| event inspection | | | | ✓ |
| data-flow analyses | | | | ✓ |

† Icicle feature available with the extended binding (`icicle_ext/`, built from
source). The stock `icicle-emu` wheel supports the un-daggered Icicle rows.

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

### Reaching the rest (any engine)
Anything not yet a first-class tool is still reachable:
- `emu_describe` — list every method/attribute on a session's engine object
- `emu_call` — invoke any of them by name (JSON args with hex/bytes coercions; private members blocked)
- `emu_eval` — run a Python snippet against the session. This executes arbitrary
  Python in the server process, so it is **off by default**; enable it only in a
  trusted local setup with `EMU_ENABLE_EVAL=1`. It is the way to drive the
  callback-based APIs (hooks, MMIO) that can't cross the JSON tool boundary.

## See also

- `README.md` — overview, setup, typical workflows
- `icicle_ext/README.md` — the extended Icicle binding (what it adds, how to
  build it, and what is deliberately left unexposed)
