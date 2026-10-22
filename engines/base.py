"""Abstract base class for emulation engines."""

from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable
import uuid
import time


@dataclass
class HookInfo:
    """Metadata about an installed hook."""
    hook_id: str
    hook_type: str          # "address", "syscall", "api", "memory", "code"
    target: str             # address, syscall name, api name, etc.
    description: str = ""
    _handle: Any = field(default=None, repr=False)


@dataclass
class SnapshotInfo:
    """Metadata about a saved snapshot."""
    snapshot_id: str
    label: str
    created_at: float
    _data: Any = field(default=None, repr=False)


@dataclass(slots=True)
class TraceEntry:
    """Single entry in an execution trace.

    slots=True eliminates the per-instance __dict__, cutting ~200 bytes of overhead
    per entry.  With up to 100k entries in the trace deque this saves ~20 MB peak.

    args uses default_factory=list because it is mutated by callers that append
    syscall/API arguments; the factory cost is paid only when args are actually
    needed (rare in the instruction hot-path where args stays empty).
    """
    address: int = 0
    instruction: str = ""
    size: int = 0
    trace_type: str = "instruction"   # "instruction", "syscall", "api", "memory"
    name: str = ""
    args: list = field(default_factory=list)
    return_value: Any = None


MAX_TRACE_ENTRIES = 100_000

# Default memory layout shared by the CPU-level engines (unicorn, icicle, angr)
# so that addresses are interchangeable between them.
CODE_BASE = 0x1000000
CODE_SIZE = 4 * 1024 * 1024      # 4 MB
STACK_BASE = 0x7000000
STACK_SIZE = 1 * 1024 * 1024     # 1 MB
STACK_TOP = STACK_BASE + STACK_SIZE  # 0x7100000
HEAP_BASE = 0x8000000
HEAP_SIZE = 2 * 1024 * 1024      # 2 MB
DATA_BASE = 0x2000000
DATA_SIZE = 2 * 1024 * 1024      # 2 MB - for user data (strings, buffers)

# Capability flags an engine can advertise via BaseEngine.CAPABILITIES.
CAPABILITY_DESCRIPTIONS: dict[str, str] = {
    "shellcode": "Run raw code bytes in a blank address space",
    "binary_loading": "Load ELF/PE binaries",
    "os_emulation": "Emulate OS services (syscalls, libraries, filesystem)",
    "address_hooks": "Hook execution of a specific address",
    "syscall_hooks": "Hook syscalls by name",
    "api_hooks": "Hook library API calls by name",
    "instruction_trace": "Record every executed instruction",
    "memory_trace": "Record memory reads and writes",
    "snapshots": "Save and restore emulation state",
    "symbolic": "Symbolic execution: symbolic inputs, path exploration, constraint solving",
    "memory_management": "Unmap regions and change guest page permissions at runtime",
    "breakpoints": "Set execution breakpoints that halt a run for inspection/resume",
    "register_introspection": "Enumerate the full register file with offsets and sizes",
    "reverse_execution": "Step backwards / travel to any instruction count",
    "callstack": "Read the current return-address call stack",
    "disassembly": "Disassemble using the engine's own instruction semantics",
    "coverage": "Record the set of basic blocks executed (for fuzzing/triage)",
    "gdb": "Serve a GDB remote stub so a real debugger can attach",
    "cfg": "Recover a control-flow graph and list functions",
    "function_call": "Execute a function with concrete args (calling-convention aware)",
    "decompiler": "Decompile a function to pseudo-C",
    "constraints": "Add solver constraints and query value ranges/satisfiability",
    "inspection": "Register callbacks on fine-grained events (mem/reg/instruction breakpoints)",
    "sim_procedures": "Replace or skip functions with Python stubs (SimProcedures)",
    "callback_hooks": "Register Python callbacks that fire during emulation",
    "memory_hooks": "Register Python callbacks on guest memory reads/writes (watchpoints)",
    "filesystem": "Map host files/directories into the emulated filesystem",
    "io": "Feed the guest's stdin and capture its stdout/stderr",
    "wide_registers": "Read/write registers wider than 64 bits (vector/flag aggregates)",
}


class BaseEngine(ABC):
    """Abstract base for all emulation engines."""

    # Subset of CAPABILITY_DESCRIPTIONS keys supported by the engine.
    CAPABILITIES: frozenset[str] = frozenset()

    def __init__(self, arch: str, **kwargs: Any):
        self.arch = arch
        self.engine_type: str = "base"
        self.hooks: dict[str, HookInfo] = {}
        self.snapshots: dict[str, SnapshotInfo] = {}
        self.trace: deque[TraceEntry] = deque(maxlen=MAX_TRACE_ENTRIES)
        self.tracing_enabled: bool = False
        self.last_activity: float = time.time()
        # Pre-computed address hook lookup for O(1) dispatch
        self._addr_hooks: dict[int, HookInfo] = {}

    def _touch(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = time.time()

    def _gen_id(self, prefix: str = "") -> str:
        return f"{prefix}{uuid.uuid4().hex[:8]}"

    def has_capability(self, capability: str) -> bool:
        return capability in self.CAPABILITIES

    # -- Execution --

    @abstractmethod
    def start(self, begin: int, end: int, timeout_ms: int = 10000) -> dict[str, Any]:
        """Start emulation from begin to end address. Returns execution summary."""
        ...

    @abstractmethod
    def step(self, count: int = 1) -> list[TraceEntry]:
        """Step N instructions. Returns trace of stepped instructions."""
        ...

    @abstractmethod
    def stop(self) -> None:
        """Stop current emulation."""
        ...

    # -- Memory --

    @abstractmethod
    def memory_read(self, address: int, size: int) -> bytes:
        """Read size bytes from address."""
        ...

    @abstractmethod
    def memory_write(self, address: int, data: bytes) -> None:
        """Write data to address."""
        ...

    @abstractmethod
    def memory_map(self, address: int, size: int, perms: int = 7) -> None:
        """Map a memory region. perms: rwx bitmask (7=rwx, 5=rx, etc)."""
        ...

    @abstractmethod
    def memory_search(self, pattern: bytes) -> list[int]:
        """Search all mapped memory for pattern. Returns list of addresses."""
        ...

    def memory_unmap(self, address: int, size: int) -> None:
        """Unmap a memory region. Engines with the 'memory_management' capability."""
        raise NotImplementedError(f"memory_unmap is not supported by the '{self.engine_type}' engine")

    def memory_protect(self, address: int, size: int, perms: int) -> None:
        """Change guest page permissions (rwx bitmask). 'memory_management' capability."""
        raise NotImplementedError(f"memory_protect is not supported by the '{self.engine_type}' engine")

    # -- Registers --

    @abstractmethod
    def register_read(self, name: str) -> int:
        """Read a single register by name."""
        ...

    @abstractmethod
    def register_write(self, name: str, value: int) -> None:
        """Write a value to a register by name."""
        ...

    @abstractmethod
    def registers_read_all(self) -> dict[str, int]:
        """Read all general-purpose registers. Returns {name: value}."""
        ...

    # -- Hooks --

    @abstractmethod
    def hook_address(self, address: int, callback: Callable | None = None) -> str:
        """Install a hook at a specific address. Returns hook_id."""
        ...

    def hook_syscall(self, name: str, callback: Callable | None = None) -> str:
        """Hook a syscall by name. Only engines with the 'syscall_hooks' capability."""
        raise NotImplementedError(f"Syscall hooks are not supported by the '{self.engine_type}' engine")

    def hook_api(self, func_name: str, callback: Callable | None = None) -> str:
        """Hook a library API by name. Only engines with the 'api_hooks' capability."""
        raise NotImplementedError(f"API hooks are not supported by the '{self.engine_type}' engine")

    def breakpoint_add(self, address: int) -> None:
        """Set an execution breakpoint. Engines with the 'breakpoints' capability."""
        raise NotImplementedError(f"Breakpoints are not supported by the '{self.engine_type}' engine")

    def breakpoint_remove(self, address: int) -> bool:
        """Remove an execution breakpoint. Returns True if one was removed."""
        raise NotImplementedError(f"Breakpoints are not supported by the '{self.engine_type}' engine")

    def list_registers(self) -> dict[str, dict[str, int]]:
        """Enumerate all registers as {name: {offset, size}}. 'register_introspection'."""
        raise NotImplementedError(f"Register introspection is not supported by the '{self.engine_type}' engine")

    def step_back(self, count: int = 1) -> dict[str, Any]:
        """Reverse-execute `count` instructions. 'reverse_execution' capability."""
        raise NotImplementedError(f"Reverse execution is not supported by the '{self.engine_type}' engine")

    def goto_icount(self, target: int) -> dict[str, Any]:
        """Time-travel to an absolute instruction count. 'reverse_execution' capability."""
        raise NotImplementedError(f"Time-travel is not supported by the '{self.engine_type}' engine")

    def get_callstack(self) -> list[int]:
        """Return the current return-address call stack. 'callstack' capability."""
        raise NotImplementedError(f"Call stack is not supported by the '{self.engine_type}' engine")

    def disassemble(self, address: int, count: int = 1) -> list[dict[str, Any]]:
        """Disassemble `count` instructions from `address`. 'disassembly' capability."""
        raise NotImplementedError(f"Native disassembly is not supported by the '{self.engine_type}' engine")

    def enable_coverage(self) -> None:
        """Start recording executed basic blocks. 'coverage' capability."""
        raise NotImplementedError(f"Coverage is not supported by the '{self.engine_type}' engine")

    def get_coverage(self) -> list[int]:
        """Return the sorted set of basic-block addresses executed. 'coverage' capability."""
        raise NotImplementedError(f"Coverage is not supported by the '{self.engine_type}' engine")

    def clear_coverage(self) -> None:
        """Clear the recorded coverage set. 'coverage' capability."""
        raise NotImplementedError(f"Coverage is not supported by the '{self.engine_type}' engine")

    def gdb_serve(self, address: str = "127.0.0.1:1234", timeout_secs: int = 30) -> str:
        """Serve a GDB remote stub for a debugger to attach. 'gdb' capability."""
        raise NotImplementedError(f"A GDB stub is not supported by the '{self.engine_type}' engine")

    def recover_cfg(self, fast: bool = True) -> dict[str, Any]:
        """Recover a control-flow graph and list functions. 'cfg' capability."""
        raise NotImplementedError(f"CFG recovery is not supported by the '{self.engine_type}' engine")

    def list_functions(self) -> list[dict[str, Any]]:
        """List recovered functions. 'cfg' capability."""
        raise NotImplementedError(f"Function listing is not supported by the '{self.engine_type}' engine")

    def call_function(self, address: int, args: list[int] | None = None) -> dict[str, Any]:
        """Execute a function with concrete args. 'function_call' capability."""
        raise NotImplementedError(f"Function calls are not supported by the '{self.engine_type}' engine")

    def decompile_function(self, address: int) -> dict[str, Any]:
        """Decompile a function to pseudo-C. 'decompiler' capability."""
        raise NotImplementedError(f"Decompilation is not supported by the '{self.engine_type}' engine")

    def function_info(self, address: int) -> dict[str, Any]:
        """Return metadata about one recovered function. 'cfg' capability."""
        raise NotImplementedError(f"Function info is not supported by the '{self.engine_type}' engine")

    def add_constraint(self, var_name: str, op: str, value: int) -> dict[str, Any]:
        """Constrain a symbolic variable (op in ==,!=,<,<=,>,>=). 'constraints'."""
        raise NotImplementedError(f"Constraints are not supported by the '{self.engine_type}' engine")

    def value_range(self, var_name: str) -> dict[str, Any]:
        """Return the min/max concrete value of a symbolic variable. 'constraints'."""
        raise NotImplementedError(f"Constraints are not supported by the '{self.engine_type}' engine")

    def is_satisfiable(self) -> bool:
        """Whether the current state's constraints are satisfiable. 'constraints'."""
        raise NotImplementedError(f"Constraints are not supported by the '{self.engine_type}' engine")

    def add_inspect_hook(self, event: str, callback: Callable, when: str = "before") -> str:
        """Register a callback on a fine-grained event (mem/reg/instruction). 'inspection'."""
        raise NotImplementedError(f"Event inspection is not supported by the '{self.engine_type}' engine")

    def hook_function(self, address: int, return_value: int | None = None) -> str:
        """Replace a function with a stub that returns immediately. 'sim_procedures'."""
        raise NotImplementedError(f"Function hooks are not supported by the '{self.engine_type}' engine")

    def hook_skip(self, address: int, length: int = 0) -> str:
        """Skip `length` bytes at `address` (no-op them). 'sim_procedures'."""
        raise NotImplementedError(f"Skip hooks are not supported by the '{self.engine_type}' engine")

    def add_callback_hook(self, callback: Callable, address: int | None = None) -> str:
        """Register a Python callback fired during emulation. 'callback_hooks'."""
        raise NotImplementedError(f"Callback hooks are not supported by the '{self.engine_type}' engine")

    def add_mem_hook(
        self,
        callback: Callable,
        kind: str = "write",
        start: int | None = None,
        end: int | None = None,
    ) -> str:
        """Register a Python callback fired on guest memory access. 'memory_hooks'.

        kind="write" fires callback(addr, data: bytes) on each write in the
        watched range; kind="read" fires callback(addr, size: int) on each read.
        start/end bound the range, end-exclusive and matched on the access's
        starting address; None widens to (nearly) the whole space.
        """
        raise NotImplementedError(f"Memory-access hooks are not supported by the '{self.engine_type}' engine")

    def add_code_hook(self, callback: Callable, start: int | None = None, end: int | None = None) -> str:
        """Fire a callback on every instruction (optionally in a range). 'callback_hooks'."""
        raise NotImplementedError(f"Code hooks are not supported by the '{self.engine_type}' engine")

    def add_block_hook(self, callback: Callable, start: int | None = None, end: int | None = None) -> str:
        """Fire a callback on every basic block (optionally in a range). 'callback_hooks'."""
        raise NotImplementedError(f"Block hooks are not supported by the '{self.engine_type}' engine")

    def add_intr_hook(self, callback: Callable) -> str:
        """Fire a callback on every interrupt/exception. 'callback_hooks'."""
        raise NotImplementedError(f"Interrupt hooks are not supported by the '{self.engine_type}' engine")

    def memory_maps(self) -> list[dict[str, Any]]:
        """List the guest's mapped memory regions (start/end/perms/label)."""
        raise NotImplementedError(f"Memory-map listing is not supported by the '{self.engine_type}' engine")

    def read_string(self, address: int, max_len: int = 1024) -> str:
        """Read a NUL-terminated string from guest memory."""
        raise NotImplementedError(f"String reads are not supported by the '{self.engine_type}' engine")

    def add_fs_mapper(self, guest_path: str, host_path: str) -> None:
        """Map a host file/dir into the emulated filesystem. 'filesystem' capability."""
        raise NotImplementedError(f"Filesystem mapping is not supported by the '{self.engine_type}' engine")

    def set_stdin(self, data: bytes) -> None:
        """Feed bytes to the guest's standard input. 'io' capability."""
        raise NotImplementedError(f"stdin injection is not supported by the '{self.engine_type}' engine")

    def capture_output(self) -> None:
        """Start capturing the guest's stdout/stderr. 'io' capability."""
        raise NotImplementedError(f"Output capture is not supported by the '{self.engine_type}' engine")

    def get_output(self) -> dict[str, str]:
        """Return the captured stdout/stderr so far. 'io' capability."""
        raise NotImplementedError(f"Output capture is not supported by the '{self.engine_type}' engine")

    def register_read_bytes(self, name: str) -> bytes:
        """Read a register's full backing bytes (wide registers). 'wide_registers'."""
        raise NotImplementedError(f"Wide-register access is not supported by the '{self.engine_type}' engine")

    def register_write_bytes(self, name: str, data: bytes) -> None:
        """Write a register's full backing bytes (wide registers). 'wide_registers'."""
        raise NotImplementedError(f"Wide-register access is not supported by the '{self.engine_type}' engine")

    def hook_remove(self, hook_id: str) -> bool:
        """Remove a hook by ID. Returns True if removed."""
        if hook_id in self.hooks:
            del self.hooks[hook_id]
            return True
        return False

    def list_hooks(self) -> list[dict[str, str]]:
        """List all active hooks."""
        return [
            {"hook_id": h.hook_id, "type": h.hook_type, "target": h.target, "description": h.description}
            for h in self.hooks.values()
        ]

    # -- Snapshots --

    @abstractmethod
    def snapshot_save(self, label: str = "") -> str:
        """Save current emulation state. Returns snapshot_id."""
        ...

    @abstractmethod
    def snapshot_restore(self, snapshot_id: str) -> None:
        """Restore emulation state from snapshot."""
        ...

    def snapshot_list(self) -> list[dict[str, Any]]:
        """List all saved snapshots."""
        return [
            {"snapshot_id": s.snapshot_id, "label": s.label, "created_at": s.created_at}
            for s in self.snapshots.values()
        ]

    # -- Trace --

    def _append_trace(self, entry: TraceEntry) -> None:
        """Append a trace entry. deque automatically drops oldest when full."""
        self.trace.append(entry)

    def enable_tracing(self) -> None:
        self.tracing_enabled = True

    def disable_tracing(self) -> None:
        self.tracing_enabled = False

    def clear_trace(self) -> None:
        self.trace.clear()

    def get_trace(self, limit: int = 200) -> list[dict[str, Any]]:
        """Get the last N trace entries as dicts.

        Avoids copying the entire deque when limit is smaller than its length.
        deque supports O(1) indexed access, so we index directly into the tail
        instead of materialising list(self.trace) first.
        """
        n = len(self.trace)
        if limit and limit < n:
            # Index directly into the deque tail — no full copy.
            entries = [self.trace[i] for i in range(n - limit, n)]
        else:
            entries = list(self.trace)
        return [
            {
                "address": f"0x{e.address:x}",
                "instruction": e.instruction,
                "size": e.size,
                "type": e.trace_type,
                "name": e.name,
                "args": e.args,
                "return_value": e.return_value,
            }
            for e in entries
        ]

    # -- Lifecycle --

    @abstractmethod
    def close(self) -> None:
        """Clean up all resources."""
        ...

    def get_info(self) -> dict[str, Any]:
        """Return engine metadata."""
        return {
            "engine_type": self.engine_type,
            "arch": self.arch,
            "hooks": len(self.hooks),
            "snapshots": len(self.snapshots),
            "trace_entries": len(self.trace),
            "tracing_enabled": self.tracing_enabled,
            "capabilities": sorted(self.CAPABILITIES),
        }
