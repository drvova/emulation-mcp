# Extended Icicle binding

The `icicle-emu` wheel on PyPI exposes only a thin slice of the Icicle
framework. This directory rebuilds the binding from source with an extended
`src/lib.rs` that reaches far more of Icicle, so the `icicle` engine in this
server can use it.

## What it adds beyond the stock wheel

| Feature | Binding surface | Server capability |
|---|---|---|
| Native VM snapshot/restore | `snapshot`, `restore`, `snapshot_count` | faster, complete snapshots |
| Reverse execution & time-travel | `save_snapshot`, `step_back`, `goto_icount` | `reverse_execution` |
| Call stack | `get_callstack` | `callstack` |
| SLEIGH-native disassembly | `get_disasm`, `get_block_info` | `disassembly` (no capstone needed) |
| Linux userspace emulation | `os="linux"`, `linux_load` | `os_emulation` (load an ELF, emulate syscalls) |
| Block coverage | `enable_coverage`, `get_coverage`, `clear_coverage` | `coverage` |
| GDB remote stub | `gdb_serve` | `gdb` (attach a real debugger; server runs it non-blocking via a detached subprocess, see `gdb_server_runner.py`) |
| Memory-map enumeration | `mem_map_ranges` | lets the server snapshot any session's real mappings (incl. Linux) for background GDB |
| Python-callback hooks | `add_py_hook`, `add_py_block_hook` | `callback_hooks` — run arbitrary Python during emulation (observe-only) |
| Memory-access hooks | `add_mem_write_hook`, `add_mem_read_hook` (+ `remove_*`) | `memory_hooks` — observe guest reads/writes in a range (data watchpoints, taint, memory tracing) |
| Wide registers | `reg_read_bytes`, `reg_write_bytes` | `wide_registers` — XMM/YMM/vector/flag aggregates |

The stock wheel is still fully supported — the Python wrapper
(`engines/icicle_engine.py`) feature-detects these methods and only advertises
the extra capabilities when the extended binding is installed.

## Build

Requirements: a Rust toolchain (`rustc`/`cargo` via <https://rustup.rs>), a C
compiler, and `maturin` (`pip install maturin`). The build takes a couple of
minutes and produces an abi3 wheel.

```bash
./icicle_ext/build.sh /path/to/your/venv/bin/python
```

The script clones `icicle-python` at a pinned commit (with its `icicle-emu`
submodule), overlays `lib.rs`, builds the wheel, and installs it into the given
interpreter. Install it into the environment that runs the MCP server.

## How it's maintained

`lib.rs` and `Cargo.toml` are complete replacements for `icicle-python`'s at the
pinned commit (`ICICLE_PYTHON_COMMIT` in `build.sh`); `build.sh` overlays both
onto a fresh checkout. `Cargo.toml` adds the `icicle-gdb` path dependency for
the GDB stub. The additions in `lib.rs` are grouped under an "Extended surface"
comment block plus Linux/coverage/GDB sections. To track a newer upstream, bump
the pinned commit and re-apply the same additions.

## Linux mode notes

- `os="linux"` builds the emulated Linux kernel with a VFS rooted at `sysroot`
  (default `/`). `linux_load(path, argv, env)` maps the ELF, sets up argv/env
  and the stack, and positions the entry point.
- Statically linked binaries work directly. Dynamically linked binaries need
  their interpreter and libraries reachable under `sysroot`.
- Execution is still bounded by the instruction budget / wall-clock timeout in
  the engine wrapper.
