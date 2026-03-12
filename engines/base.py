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


class BaseEngine(ABC):
    """Abstract base for all emulation engines."""

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
        }
