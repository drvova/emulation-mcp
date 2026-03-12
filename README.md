# emulation-mcp

MCP server for CPU and binary emulation in reverse engineering workflows. Supports two backends: Unicorn Engine for lightweight code emulation and Qiling Framework for full OS-level binary emulation.

## What it does

### Unicorn Engine (lightweight CPU emulation)
- Emulate shellcode and code snippets across architectures (x86, x64, ARM, ARM64, MIPS)
- Map and manage memory regions, read/write memory and registers
- Single-step or run to address with configurable step limits
- Instruction tracing with register and memory change logging
- Hook arbitrary addresses with custom callbacks
- Snapshot and restore emulation state for exploration

### Qiling Framework (full binary emulation)
- Load and run full ELF/PE binaries with OS-level support (Linux, Windows)
- Syscall and API hooking -- intercept and inspect OS interactions
- Filesystem, registry, and network emulation
- Supports rootfs overlays for shared library resolution
- Persistent sessions with state preservation between tool calls

### Shared features
- Session management with unique IDs, auto-cleanup after idle timeout
- Memory search across emulated address space
- Export evidence (register dumps, memory snapshots, traces) for reporting

## Requirements

- Python 3.10+
- Unicorn Engine 2.x (`pip install unicorn`)
- Qiling Framework 1.4+ (`pip install qiling`) -- optional, only needed for full binary emulation
- Capstone disassembler (`pip install capstone`)

## Setup

```bash
pip install -r requirements.txt
python server.py
```

For Qiling binary emulation, you need a rootfs matching the target OS and architecture. See the [Qiling documentation](https://docs.qiling.io/) for rootfs setup.

## Typical workflow

1. Create a session: `emu_create_session` with engine choice (`unicorn` or `qiling`)
2. For Unicorn: map memory, write code bytes, set registers, run
3. For Qiling: point at a binary + rootfs, hook syscalls/APIs, run
4. Inspect registers, memory, trace output
5. Use snapshots to save and restore state for branch exploration

## Architecture

```
emulation/
  server.py              # MCP server, tool definitions
  session_manager.py     # Session lifecycle, ID management
  engines/
    unicorn_engine.py    # Unicorn wrapper
    qiling_engine.py     # Qiling wrapper
    base.py              # Shared types (HookInfo, TraceEntry, etc.)
  tests/
```

## License

CC BY-NC-SA 4.0 -- see [LICENSE](LICENSE).
