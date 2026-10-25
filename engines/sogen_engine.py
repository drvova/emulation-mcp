"""Sogen emulation engine wrapper.

Sogen (https://github.com/momo5502/sogen) is a high-performance Windows and
Linux *user-mode* emulator.  Rather than reimplementing OS APIs, it emulates the
target at the CPU + syscall level and loads the real system libraries (ntdll /
kernel32 / user32 on Windows, the ELF loader + libc on Linux), so it handles PE
loading, SEH, the PEB/TEB, threading, the registry and the filesystem the way
the real loader would.  It drives a selectable CPU backend underneath -- the
portable software backends are Unicorn (default) and Icicle, and on supported
hosts it can use hardware acceleration (WHP on Windows, KVM on Linux).

This wrapper exposes Sogen through the same BaseEngine surface as the other
engines.  It is the server's answer to "run a real Windows PE" -- Qiling also
emulates Windows, but Sogen loads the genuine system DLLs and tends to carry
far more of the real OS behaviour, while still being scriptable from Python.

Binding notes (the official ``sogen`` PyPI package, ``import sogen``):

* The API is namespaced into ``sogen.windows.*`` and ``sogen.linux.*``.  An
  "application" is created directly from a binary path -- there is no separate
  load step -- or an empty emulator is created with ``create_empty``.
* ``app.start(n)`` runs ``n`` instructions (or runs to completion with no
  argument), which maps cleanly onto ``step``; there is no address-bounded
  top-level run like Unicorn's ``emu_start(begin, end)``, so ``start`` runs the
  loaded program under an instruction budget.
* Memory/register accessors, the ``hooks`` namespace and the ``callbacks``
  namespace live on the application object; their exact placement is probed at
  construction so the wrapper tracks the installed binding rather than assuming.
* Snapshots use ``serialize_state()``/``deserialize_state()`` (opaque bytes),
  which gives the many-named-snapshots semantics BaseEngine expects.
* Both CPU backends work.  The ``icicle`` backend needs Ghidra's SLEIGH
  processor specs reachable from the working directory
  (``./Ghidra/Processors/.../*.ldefs``); those ship inside the sogen package, so
  the wrapper constructs the icicle emulator with the CWD pointed at them.
* Sogen has no Python disassembler (its debugger facade has no constructor), so
  ``disassemble`` uses capstone on guest bytes.  Symbolization is served from the
  export tables of loaded modules (``on_module_load``); syscalls are counted by an
  always-on ``on_syscall`` observer.  Both are collected automatically.
* Capabilities are feature-detected per instance: the wrapper advertises a
  capability only when the installed binding actually exposes the backing API
  (e.g. ``memory_management`` when the MMU has ``protect_memory``/``release_memory``).

The package ships prebuilt wheels for CPython 3.9 and 3.10 only; on other
interpreters it must be built from source (see requirements-optional.txt).  The
engine is loaded lazily, so the rest of the server is unaffected when Sogen is
not installed.
"""

import time
import contextlib
import os
from typing import Any, Callable

import sogen

from .base import BaseEngine, HookInfo, SnapshotInfo, TraceEntry

# Capstone is a core dependency; Sogen has no native disassembler reachable from
# Python (its debugger facade has no constructor), so we disassemble guest bytes
# ourselves.  x86-64 and ARM64 are the Sogen guest architectures.
try:
    from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_MODE_64, CS_MODE_ARM
    _HAS_CAPSTONE = True
except ImportError:  # pragma: no cover - capstone is in requirements.txt
    _HAS_CAPSTONE = False


# Architecture string -> (register-enum module attribute on `sogen`).
# Sogen's guests are x86-64 and ARM64; register enums live at sogen.Register
# (x86-64) and sogen.arm64.Register (ARM64).
ARCH_REG_MODULE: dict[str, str] = {
    "x86_64": "",        # top-level sogen.Register
    "x8664": "",
    "arm64": "arm64",    # sogen.arm64.Register
    "aarch64": "arm64",
}

# Capstone arch/mode per Sogen guest arch, for disassemble().
_CS_MAP: dict[str, tuple] = {}
if _HAS_CAPSTONE:
    _CS_MAP = {
        "x86_64": (CS_ARCH_X86, CS_MODE_64),
        "x8664": (CS_ARCH_X86, CS_MODE_64),
        "arm64": (CS_ARCH_ARM64, CS_MODE_ARM),
        "aarch64": (CS_ARCH_ARM64, CS_MODE_ARM),
    }

# Common registers per architecture for registers_read_all().
COMMON_REGS: dict[str, list[str]] = {
    "x86_64": ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rflags"],
    "arm64": [f"x{i}" for i in range(31)] + ["sp", "pc", "nzcv"],
}
COMMON_REGS["x8664"] = COMMON_REGS["x86_64"]
COMMON_REGS["aarch64"] = COMMON_REGS["arm64"]

# Default instruction budget for a top-level run (bounds runaway programs; the
# Python API has no wall-clock stop).  Overridable per call / per engine option.
DEFAULT_INSN_LIMIT = 50_000_000


@contextlib.contextmanager
def _chdir(path: str):
    """Temporarily change the working directory (restored on exit)."""
    old = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(old)


def _norm_arch(arch: str) -> str:
    key = (arch or "x86_64").lower().strip()
    if key in ("x64", "amd64", "x86-64"):
        key = "x86_64"
    if key in ("aarch64",):
        key = "arm64"
    if key not in ARCH_REG_MODULE:
        supported = ", ".join(sorted(set(ARCH_REG_MODULE)))
        raise ValueError(f"Unsupported architecture '{arch}' for Sogen. Supported: {supported}")
    return key


def _resolve_backend(name: str) -> Any:
    """Map a backend string to a sogen.Backend member, if the enum exists."""
    backend_enum = getattr(sogen, "Backend", None)
    if backend_enum is None:
        return None
    key = (name or "unicorn").lower().strip()
    member = getattr(backend_enum, key, None)
    if member is None:
        available = [n for n in dir(backend_enum) if not n.startswith("_")]
        raise ValueError(f"Unsupported Sogen backend '{name}'. Available: {', '.join(available)}")
    return member


class SogenEngine(BaseEngine):
    """Sogen wrapper for Windows/Linux user-mode emulation."""

    # Baseline capabilities; narrowed/extended per instance in __init__ once the
    # installed binding has been probed (see _detect_features).
    CAPABILITIES = frozenset({
        "binary_loading", "os_emulation", "address_hooks", "api_hooks",
        "callback_hooks", "memory_hooks", "snapshots", "register_introspection",
        "io",
    })
    SUPPORTED_ARCHS = ("x86_64", "arm64")

    def __init__(
        self,
        arch: str = "x86_64",
        binary_path: str = "",
        rootfs: str = "",
        ostype: str = "windows",
        args: list[str] | None = None,
        enable_trace: bool = False,
        backend: str = "unicorn",
        emulation_root: str = "",
        insn_limit: int = DEFAULT_INSN_LIMIT,
    ):
        super().__init__(arch=_norm_arch(arch))
        self.engine_type = "sogen"
        self.ostype = (ostype or "windows").lower().strip()
        self.binary_path = binary_path
        self._args = list(args or [])
        self._backend_name = backend
        self._insn_limit = int(insn_limit) if insn_limit else DEFAULT_INSN_LIMIT
        self._has_run = False
        # Output-capture buffers populated by capture_output().
        self._cap_stdout: bytearray | None = None
        self._cap_stderr: bytearray | None = None
        # Always-on observers (cheap): syscall histogram + loaded-module list.
        self._syscall_counts: dict[str, int] = {}
        self._syscall_total = 0
        self._modules: list[Any] = []

        if self.ostype not in ("windows", "linux"):
            raise ValueError(f"Sogen ostype must be 'windows' or 'linux', got '{ostype}'")

        # emulation_root wins; rootfs is the BaseEngine/Qiling-style alias.
        root = emulation_root or rootfs
        if self.ostype == "linux" and not root:
            root = "/"   # Linux mode can run against the host filesystem.

        # Sogen resolves the executable path *inside* the emulation root, so a
        # host binary under root "/" must be given as an absolute host path.
        bpath = self.binary_path
        if bpath and self.ostype == "linux" and root == "/" and os.path.exists(bpath):
            bpath = os.path.abspath(bpath)
        self._bpath = bpath

        self._os_mod = sogen.linux if self.ostype == "linux" else sogen.windows
        backend_member = _resolve_backend(backend)

        try:
            self.app = self._construct_app(root, backend_member)
        except Exception as e:
            raise RuntimeError(
                f"Failed to initialize Sogen ({self.ostype}/{self.arch}, "
                f"backend={backend}): {type(e).__name__}: {e}\n"
                f"binary='{bpath}', emulation_root='{root}'. "
                f"Windows emulation needs a prepared root (system DLLs + registry, "
                f"e.g. https://sogen.dev/root.zip); Linux emulation can use '/'."
            ) from e

        # Probe where the binding puts its accessors / namespaces.
        self._emu = self._resolve_emulator(self.app)
        self._install_observers()
        self._detect_features()

        if enable_trace:
            self.enable_tracing()

    # -- Construction helpers --

    # The icicle backend loads Ghidra SLEIGH specs from "./Ghidra/..." relative
    # to the working directory; they ship inside the sogen package, so construct
    # the emulator with the CWD pointed there.
    _PKG_DIR = os.path.dirname(sogen.__file__)

    def _construct_app(self, root: str, backend_member: Any) -> Any:
        """Create the application/empty emulator via the os-specific factory."""
        needs_ghidra_cwd = (
            backend_member is not None
            and str(getattr(backend_member, "name", backend_member)).lower().find("icicle") != -1
            and os.path.isdir(os.path.join(self._PKG_DIR, "Ghidra"))
        )
        ctx = _chdir(self._PKG_DIR) if needs_ghidra_cwd else contextlib.nullcontext()
        with ctx:
            return self._do_construct(root, backend_member)

    def _do_construct(self, root: str, backend_member: Any) -> Any:
        kwargs: dict[str, Any] = {}
        if root:
            kwargs["emulation_root"] = root
        if backend_member is not None:
            kwargs["backend"] = backend_member

        if self._bpath:
            if self.ostype == "windows" and self._args:
                return self._os_mod.create_application(self._bpath, args=self._args, **kwargs)
            return self._os_mod.create_application(self._bpath, **kwargs)
        return self._os_mod.create_empty(**kwargs)

    @staticmethod
    def _resolve_emulator(app: Any) -> Any:
        """Return the object that carries read_memory/read_register.

        The binding exposes these on the application object directly, but some
        builds nest them under `.emulator` / `.emu`; probe so the wrapper does
        not assume one layout.
        """
        for attr in ("read_memory", "read_register"):
            if hasattr(app, attr):
                return app
        for nested in ("emulator", "emu", "e"):
            obj = getattr(app, nested, None)
            if obj is not None and hasattr(obj, "read_memory"):
                return obj
        return app  # fall back to the app itself; errors surface on first use

    def _detect_features(self) -> None:
        """Set instance-level capabilities from what the binding actually offers."""
        caps = set(self.CAPABILITIES)
        hooks = getattr(self.app, "hooks", None)
        callbacks = getattr(self.app, "callbacks", None)
        memory = getattr(self.app, "memory", None)

        self._has_hooks = hooks is not None
        self._has_callbacks = callbacks is not None

        if not self._has_hooks:
            caps -= {"address_hooks", "callback_hooks", "memory_hooks"}
        if not self._has_callbacks:
            caps -= {"io"}
        # High-level API/symbol interception lives on hooks.apis (Windows) or
        # hooks.symbols (Linux).
        apis = getattr(hooks, "apis", None) if hooks else None
        symbols = getattr(hooks, "symbols", None) if hooks else None
        if apis is None and symbols is None:
            caps -= {"api_hooks"}
        # Snapshots need the serialize/deserialize pair.
        if not (hasattr(self.app, "serialize_state") and hasattr(self.app, "deserialize_state")):
            caps -= {"snapshots"}
        # Runtime memory management (protect/release) when the MMU exposes it.
        if memory is not None and hasattr(memory, "protect_memory") and hasattr(memory, "release_memory"):
            caps.add("memory_management")
        # Disassembly is done with capstone (Sogen has no Python disassembler).
        if _HAS_CAPSTONE and self.arch in _CS_MAP:
            caps.add("disassembly")
        # Symbolization is served from loaded modules' export tables.
        if self._has_callbacks:
            caps.add("symbols")

        self.CAPABILITIES = frozenset(caps)
        self._apis = apis
        self._symbols = symbols

    def _install_observers(self) -> None:
        """Wire always-on, low-cost callbacks: syscall counts + module list.

        Registering these at construction means syscall_stats() and
        symbolization work after any run without extra setup.  Callback shapes
        (validated against the real binding): on_syscall(number:int, name:str),
        on_module_load(module).
        """
        cb = getattr(self.app, "callbacks", None)
        if cb is None:
            return
        if hasattr(cb, "on_syscall"):
            def _on_syscall(number: int = 0, name: str = "", *rest: Any) -> None:
                key = name or f"syscall_{number}"
                self._syscall_counts[key] = self._syscall_counts.get(key, 0) + 1
                self._syscall_total += 1
                if self.tracing_enabled:
                    self._append_trace(TraceEntry(trace_type="syscall", name=key))
            cb.on_syscall = _on_syscall
        if hasattr(cb, "on_module_load"):
            def _on_module(module: Any = None, *rest: Any) -> None:
                if module is not None:
                    self._modules.append(module)
            cb.on_module_load = _on_module

    # -- Register resolution --

    def _reg_enum(self, name: str) -> Any:
        """Resolve a register name string to the sogen register-enum member."""
        mod_attr = ARCH_REG_MODULE.get(self.arch, "")
        reg_mod = getattr(sogen, mod_attr) if mod_attr else sogen
        reg_cls = getattr(reg_mod, "Register", None)
        if reg_cls is None:
            raise RuntimeError("This Sogen binding exposes no Register enum")
        member = getattr(reg_cls, name.lower(), None)
        if member is None:
            raise ValueError(f"Unknown register '{name}' for Sogen arch '{self.arch}'")
        return member

    # -- Execution --

    def start(self, begin: int = 0, end: int = 0, timeout_ms: int = 10000) -> dict[str, Any]:
        """Run the loaded program under an instruction budget.

        Sogen runs the loaded program from its entry point; begin/end address
        bounds (a Unicorn concept) do not apply, so they are ignored.  The run
        is bounded by the engine's instruction limit instead of a wall clock.
        """
        self._touch()
        try:
            self._run(self._insn_limit)
            self._has_run = True
        except Exception as e:
            crash_addr = None
            try:
                crash_addr = self._read_pc()
            except Exception:
                pass
            return {
                "status": "error",
                "error": str(e),
                "crash_address": f"0x{crash_addr:x}" if crash_addr else None,
                "trace_entries": len(self.trace),
            }
        return {
            "status": "stopped",
            "exit_status": self._exit_status(),
            "executed_instructions": self._executed_instructions(),
            "stop_reason": self._stop_reason(),
            "trace_entries": len(self.trace),
        }

    def _run(self, limit: int | None) -> None:
        """Run the loaded program; start(count) with count=0 runs to completion."""
        self.app.start(int(limit) if limit and limit > 0 else 0)

    def _stop_reason(self) -> str | None:
        reason = getattr(self.app, "last_stop_reason", None)
        detail = getattr(self.app, "last_stop_detail", None)
        if reason is None:
            return None
        return f"{reason}" + (f" ({detail})" if detail else "")

    def step(self, count: int = 1) -> list[TraceEntry]:
        """Execute `count` instructions (Sogen's start(n) runs n instructions)."""
        self._touch()
        stepped: list[TraceEntry] = []
        for _ in range(max(count, 1)):
            addr = None
            try:
                addr = self._read_pc()
            except Exception:
                pass
            try:
                self._run(1)
            except Exception:
                break
            entry = TraceEntry(address=addr or 0, size=0, trace_type="instruction")
            try:
                after = self._read_pc()
                if addr is not None and after is not None and after > addr:
                    entry.size = after - addr
                    entry.instruction = self._emu.read_memory(addr, entry.size).hex()
            except Exception:
                pass
            stepped.append(entry)
            if self.tracing_enabled:
                self._append_trace(entry)
        self._has_run = True
        return stepped

    def stop(self) -> None:
        self._touch()
        try:
            self.app.stop()
        except Exception:
            pass

    def _read_pc(self) -> int | None:
        name = "pc" if self.arch == "arm64" else "rip"
        try:
            return int(self._emu.read_register(self._reg_enum(name)))
        except Exception:
            return None

    def _exit_status(self) -> Any:
        proc = getattr(self.app, "process", None)
        return getattr(proc, "exit_status", None) if proc is not None else None

    def _executed_instructions(self) -> Any:
        return getattr(self.app, "executed_instructions", None)

    # -- Memory --

    def memory_read(self, address: int, size: int) -> bytes:
        try:
            return bytes(self._emu.read_memory(address, size))
        except Exception as e:
            raise RuntimeError(f"Memory read failed at 0x{address:x} (size={size}): {e}") from e

    def memory_write(self, address: int, data: bytes) -> None:
        try:
            self._emu.write_memory(address, bytes(data))
        except Exception as e:
            raise RuntimeError(f"Memory write failed at 0x{address:x}: {e}") from e

    # rwx bitmask (4=r/2=w/1=x) -> sogen.MemoryPermission member name.
    _PERM_NAMES: dict[int, str] = {
        0: "none", 1: "exec", 2: "write", 4: "read",
        5: "read_exec", 6: "read_write", 7: "all",
    }

    def _perm_member(self, perms: int) -> Any:
        """Map an rwx bitmask to a sogen.MemoryPermission member."""
        mp = getattr(sogen, "MemoryPermission", None)
        if mp is None:
            return perms
        name = self._PERM_NAMES.get(perms & 7, "read_write")
        member = getattr(mp, name, None)
        if member is None:
            member = getattr(mp, "read_write", None)
        return member if member is not None else perms

    def memory_map(self, address: int, size: int, perms: int = 7) -> None:
        mem = getattr(self.app, "memory", None)
        if mem is None or not hasattr(mem, "allocate_memory"):
            raise NotImplementedError("This Sogen binding exposes no memory allocation API")
        try:
            mem.allocate_memory(size, self._perm_member(perms), start=address)
        except Exception as e:
            raise RuntimeError(f"Memory map failed at 0x{address:x} (size=0x{size:x}): {e}") from e

    def memory_unmap(self, address: int, size: int) -> None:
        mem = getattr(self.app, "memory", None)
        if mem is None or not hasattr(mem, "release_memory"):
            raise NotImplementedError("This Sogen binding exposes no memory release API")
        if not mem.release_memory(address, size):
            raise RuntimeError(f"Memory release failed at 0x{address:x} (size=0x{size:x})")

    def memory_protect(self, address: int, size: int, perms: int) -> None:
        mem = getattr(self.app, "memory", None)
        if mem is None or not hasattr(mem, "protect_memory"):
            raise NotImplementedError("This Sogen binding exposes no memory protect API")
        if not mem.protect_memory(address, size, self._perm_member(perms)):
            raise RuntimeError(f"Memory protect failed at 0x{address:x} (size=0x{size:x})")

    def memory_search(self, pattern: bytes) -> list[int]:
        """Search the loaded-module regions for `pattern`.

        Sogen's Python API exposes no full region list, so this scans the
        regions of the loaded modules (exe + shared objects) reported via
        memory_maps().  Anonymous allocations and the stack/heap are not
        enumerable and so are not covered; read a known range with memory_read
        and search it yourself for those.
        """
        self._touch()
        found: list[int] = []
        for region in self.memory_maps():
            start, end = region.get("start"), region.get("end")
            if not start or not end or end <= start:
                continue
            try:
                blob = bytes(self._emu.read_memory(start, end - start))
            except Exception:
                continue
            off = blob.find(pattern)
            while off != -1:
                found.append(start + off)
                off = blob.find(pattern, off + 1)
        return found

    def memory_maps(self) -> list[dict[str, Any]]:
        """List the loaded modules as mapped regions (exe + shared objects).

        Sogen exposes no general region enumeration, but every loaded module
        reports its image base and size, which is where the binary and its
        libraries landed -- the most useful part of a memory map.
        """
        self._touch()
        out: list[dict[str, Any]] = []
        for m in self._modules:
            base = getattr(m, "image_base", None)
            size = getattr(m, "size_of_image", None)
            if base is None:
                continue
            out.append({
                "start": base,
                "end": (base + size) if size else base,
                "perms": "r-x",
                "label": str(getattr(m, "name", "")),
                "path": str(getattr(m, "path", "") or ""),
            })
        return out

    def memory_stats(self) -> dict[str, Any]:
        """Return Sogen's memory summary (region_count, mapped/executable bytes)."""
        self._touch()
        mem = getattr(self.app, "memory", None)
        if mem is None or not hasattr(mem, "compute_memory_stats"):
            raise NotImplementedError("This Sogen binding exposes no memory stats")
        return dict(mem.compute_memory_stats())

    def region_info(self, address: int) -> dict[str, Any] | None:
        """Describe the mapped region that contains `address` (Sogen-specific).

        Returns None when `address` is not mapped.
        """
        self._touch()
        mem = getattr(self.app, "memory", None)
        if mem is None or not hasattr(mem, "get_region_info"):
            raise NotImplementedError("This Sogen binding exposes no region info")
        ri = mem.get_region_info(address)
        if ri is None:
            return None
        start = getattr(ri, "start", None)
        length = getattr(ri, "length", None)
        return {
            "start": start,
            "length": length,
            "end": (start + length) if (start is not None and length is not None) else None,
            "allocation_base": getattr(ri, "allocation_base", None),
            "allocation_length": getattr(ri, "allocation_length", None),
            "permissions": str(getattr(ri, "permissions", "")),
            "kind": str(getattr(ri, "kind", "")),
            "is_committed": getattr(ri, "is_committed", None),
            "is_reserved": getattr(ri, "is_reserved", None),
        }

    def read_string(self, address: int, max_len: int = 1024) -> str:
        self._touch()
        try:
            raw = bytes(self._emu.read_memory(address, max_len))
        except Exception as e:
            raise RuntimeError(f"String read failed at 0x{address:x}: {e}") from e
        nul = raw.find(b"\x00")
        if nul != -1:
            raw = raw[:nul]
        return raw.decode("utf-8", errors="replace")

    # -- Syscalls, modules, symbolization (OS-emulation introspection) --

    def syscall_stats(self) -> dict[str, Any]:
        """Return the syscall histogram gathered during the run(s).

        Counts are accumulated by the always-on on_syscall observer, so this
        works after any emu_run/emu_step without extra setup.
        """
        self._touch()
        return {
            "syscalls": dict(self._syscall_counts),
            "total": self._syscall_total,
            "strings": [],
        }

    def list_modules(self) -> list[dict[str, Any]]:
        """List the modules loaded so far (exe + shared objects/DLLs)."""
        self._touch()
        out: list[dict[str, Any]] = []
        for m in self._modules:
            exports = getattr(m, "exports", None)
            try:
                nexp = len(exports) if exports is not None else 0
            except Exception:
                nexp = 0
            out.append({
                "name": str(getattr(m, "name", "")),
                "image_base": getattr(m, "image_base", None),
                "entry_point": getattr(m, "entry_point", None),
                "size": getattr(m, "size_of_image", None),
                "path": str(getattr(m, "path", "") or ""),
                "exports": nexp,
            })
        return out

    def _iter_exports(self):
        """Yield (module, ExportedSymbol) for every export of every module."""
        for m in self._modules:
            exports = getattr(m, "exports", None)
            if not exports:
                continue
            for s in exports:
                yield m, s

    def load_symbols(self, path: str = "", load_address: int = 0) -> int:
        """Report the number of symbols available from loaded modules.

        Sogen collects symbols automatically as modules load (the always-on
        observer), so no explicit load step is needed.  Returns the current
        export count across all loaded modules.
        """
        self._touch()
        return sum(1 for _ in self._iter_exports())

    def symbolize(self, address: int) -> dict[str, Any] | None:
        """Resolve an address to {name, offset, address, source} via module exports."""
        self._touch()
        best = None  # (export_addr, name, module_name)
        for m, s in self._iter_exports():
            sa = getattr(s, "address", None)
            if sa is None or sa > address:
                continue
            if best is None or sa > best[0]:
                best = (sa, str(getattr(s, "name", "")), str(getattr(m, "name", "")))
        if best is None:
            return None
        return {
            "name": best[1],
            "offset": address - best[0],
            "address": best[0],
            "source": best[2],   # owning module name
        }

    def lookup_symbol(self, name: str) -> int | None:
        """Resolve a symbol name to its address via module exports."""
        self._touch()
        for _m, s in self._iter_exports():
            if str(getattr(s, "name", "")) == name:
                return getattr(s, "address", None)
        return None

    def list_symbols(self) -> list[dict[str, Any]]:
        """List exported symbols from loaded modules as {address, name, size, kind}."""
        self._touch()
        out: list[dict[str, Any]] = []
        for m, s in self._iter_exports():
            addr = getattr(s, "address", None)
            if addr is None:
                continue
            out.append({
                "address": f"0x{addr:x}",
                "name": str(getattr(s, "name", "")),
                "size": 0,                       # export tables carry no size
                "kind": str(getattr(m, "name", "")),  # owning module
            })
        return out

    # -- Disassembly (via capstone; Sogen has no Python disassembler) --

    def disassemble(self, address: int, count: int = 1) -> list[dict[str, Any]]:
        self._touch()
        if not _HAS_CAPSTONE or self.arch not in _CS_MAP:
            raise NotImplementedError(f"No capstone disassembler for Sogen arch '{self.arch}'")
        arch, mode = _CS_MAP[self.arch]
        md = Cs(arch, mode)
        try:
            code = bytes(self._emu.read_memory(address, max(count, 1) * 15 + 16))
        except Exception as e:
            raise RuntimeError(f"Disassembly read failed at 0x{address:x}: {e}") from e
        out: list[dict[str, Any]] = []
        for insn in md.disasm(code, address):
            out.append({
                "address": f"0x{insn.address:x}",
                "instruction": f"{insn.mnemonic} {insn.op_str}".strip(),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "size": insn.size,
                "bytes": insn.bytes.hex(),
            })
            if len(out) >= count:
                break
        return out

    def list_threads(self) -> dict[str, Any]:
        """Report the guest's process/thread state (fields are OS-dependent)."""
        self._touch()
        p = getattr(self.app, "process", None)
        count = getattr(p, "live_thread_count", None) if p is not None else None
        if count is None:
            return {"note": "Sogen exposes only exit status on this OS "
                            f"(exit_status={self._exit_status()})",
                    "multithread": None}
        return {
            "count": count,
            "current": getattr(self.app, "current_thread_id", None),
            "threads": [],
            "spawned": getattr(p, "spawned_thread_count", None),
        }

    # -- Registers --

    def register_read(self, name: str) -> int:
        return int(self._emu.read_register(self._reg_enum(name)))

    def register_write(self, name: str, value: int) -> None:
        self._emu.write_register(self._reg_enum(name), value)

    def registers_read_all(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for name in COMMON_REGS.get(self.arch, []):
            try:
                out[name] = int(self._emu.read_register(self._reg_enum(name)))
            except Exception:
                continue
        return out

    def list_registers(self) -> dict[str, dict[str, int]]:
        """Enumerate the architecture's register enum with current values."""
        self._touch()
        mod_attr = ARCH_REG_MODULE.get(self.arch, "")
        reg_mod = getattr(sogen, mod_attr) if mod_attr else sogen
        reg_cls = getattr(reg_mod, "Register", None)
        if reg_cls is None:
            raise NotImplementedError("This Sogen binding exposes no Register enum")
        out: dict[str, dict[str, int]] = {}
        for attr in dir(reg_cls):
            if attr.startswith("_") or attr == "invalid":
                continue
            member = getattr(reg_cls, attr)
            try:
                out[attr] = {"value": int(self._emu.read_register(member))}
            except Exception:
                continue
        return out

    # -- Hooks --

    def _store_hook(self, hook_type: str, target: str, description: str, handle: Any) -> str:
        hook_id = self._gen_id(f"{hook_type[:4]}-")
        self.hooks[hook_id] = HookInfo(
            hook_id=hook_id, hook_type=hook_type, target=target,
            description=description, _handle=handle,
        )
        return hook_id

    def hook_address(self, address: int, callback: Callable | None = None) -> str:
        self._touch()
        if not self._has_hooks or not hasattr(self.app.hooks, "memory_execution_at"):
            raise NotImplementedError("This Sogen binding exposes no execution hooks")

        if callback is None:
            def callback(*args: Any) -> None:
                self._append_trace(TraceEntry(
                    address=address, trace_type="instruction",
                    name=f"hook@0x{address:x}"))

        handle = self.app.hooks.memory_execution_at(address, callback)
        return self._store_hook("address", f"0x{address:x}",
                                f"Address hook at 0x{address:x}", handle)

    def add_code_hook(self, callback: Callable, start: int | None = None, end: int | None = None) -> str:
        """Fire a callback on every executed instruction (memory_execution hook)."""
        self._touch()
        if not self._has_hooks or not hasattr(self.app.hooks, "memory_execution"):
            raise NotImplementedError("This Sogen binding exposes no per-instruction hook")
        handle = self.app.hooks.memory_execution(callback)
        return self._store_hook("code", "all", "Per-instruction execution hook", handle)

    def add_block_hook(self, callback: Callable, start: int | None = None, end: int | None = None) -> str:
        """Fire a callback on every basic block."""
        self._touch()
        if not self._has_hooks or not hasattr(self.app.hooks, "basic_block"):
            raise NotImplementedError("This Sogen binding exposes no basic-block hook")
        handle = self.app.hooks.basic_block(callback)
        return self._store_hook("block", "all", "Per-block hook", handle)

    def add_intr_hook(self, callback: Callable) -> str:
        """Fire a callback on every interrupt."""
        self._touch()
        if not self._has_hooks or not hasattr(self.app.hooks, "interrupt"):
            raise NotImplementedError("This Sogen binding exposes no interrupt hook")
        handle = self.app.hooks.interrupt(callback)
        return self._store_hook("interrupt", "all", "Interrupt hook", handle)

    def add_mem_hook(self, callback: Callable, kind: str = "write",
                     start: int | None = None, end: int | None = None) -> str:
        """Fire a callback on guest memory read/write over a range.

        Sogen's memory_read/memory_write hooks take an (address, size) range, so
        start is required and size defaults to one page when end is omitted.
        """
        self._touch()
        if not self._has_hooks:
            raise NotImplementedError("This Sogen binding exposes no memory hooks")
        # kind="violation" fires on access faults (no range); it takes just a cb.
        if kind == "violation":
            vfn = getattr(self.app.hooks, "memory_violation", None)
            if vfn is None:
                raise NotImplementedError("This Sogen binding exposes no memory-violation hook")
            handle = vfn(callback)
            return self._store_hook("mem_violation", "all", "Memory violation hook", handle)
        hookfn = {
            "read": getattr(self.app.hooks, "memory_read", None),
            "write": getattr(self.app.hooks, "memory_write", None),
        }.get(kind)
        if hookfn is None:
            raise ValueError(f"kind must be 'read', 'write' or 'violation' (Sogen), got {kind!r}")
        base = start if start is not None else 0
        size = (end - base) if (end is not None and end > base) else 0x1000
        handle = hookfn(base, size, callback)
        return self._store_hook(f"mem_{kind}", f"0x{base:x}+0x{size:x}",
                                f"Memory {kind} hook", handle)

    def hook_insn(self, callback: Callable, insn: str) -> str:
        """Fire a callback whenever a specific instruction type executes."""
        self._touch()
        if not self._has_hooks or not hasattr(self.app.hooks, "instruction"):
            raise NotImplementedError("This Sogen binding exposes no instruction-type hook")
        insn_enum = getattr(sogen, "Instruction", None)
        member = getattr(insn_enum, insn.lower(), None) if insn_enum else None
        if member is None:
            raise ValueError(f"Unknown Sogen instruction type '{insn}'")
        handle = self.app.hooks.instruction(member, callback)
        return self._store_hook("insn", insn.lower(), f"Instruction hook on '{insn}'", handle)

    def hook_api(self, func_name: str, callback: Callable | None = None, when: str = "call") -> str:
        """Intercept a Windows API / Linux symbol by name.

        Windows uses hooks.apis["Name" | "module!Name"]; Linux uses
        hooks.symbols["module!symbol"].  The callback receives Sogen's native
        call object; return sogen.ApiContinuation.intercept to override.
        """
        self._touch()
        table = self._apis if self.ostype == "windows" else self._symbols
        if table is None:
            raise NotImplementedError(f"This Sogen binding exposes no {self.ostype} API hooks")

        if callback is None:
            def callback(*args: Any) -> None:
                self._append_trace(TraceEntry(
                    trace_type="api", name=func_name, args=[repr(a) for a in args[:4]]))

        table[func_name] = callback
        return self._store_hook("api", func_name, f"API hook on '{func_name}'", None)

    def hook_remove(self, hook_id: str) -> bool:
        info = self.hooks.get(hook_id)
        if info is None:
            return False
        handle = info._handle
        if handle is not None and hasattr(handle, "remove"):
            try:
                handle.remove()
            except Exception:
                pass
        elif info.hook_type == "api":
            table = self._apis if self.ostype == "windows" else self._symbols
            try:
                if table is not None and info.target in table:
                    del table[info.target]
            except Exception:
                pass
        del self.hooks[hook_id]
        return True

    # -- I/O (stdout/stderr capture via callbacks) --

    def capture_output(self) -> None:
        """Begin capturing the guest's stdout and stderr (call before run)."""
        self._touch()
        if not self._has_callbacks:
            raise NotImplementedError("This Sogen binding exposes no output callbacks")
        self._cap_stdout = bytearray()
        self._cap_stderr = bytearray()

        def _mk(buf: bytearray) -> Callable:
            def _cb(text: Any) -> None:
                try:
                    buf.extend(text.encode() if isinstance(text, str) else bytes(text))
                except Exception:
                    pass
            return _cb

        self.app.callbacks.on_stdout = _mk(self._cap_stdout)
        if hasattr(self.app.callbacks, "on_stderr"):
            self.app.callbacks.on_stderr = _mk(self._cap_stderr)

    def get_output(self) -> dict[str, str]:
        """Return the stdout/stderr captured since capture_output()."""
        self._touch()
        if self._cap_stdout is None:
            raise RuntimeError("Output capture not started; call capture_output() first.")
        return {
            "stdout": bytes(self._cap_stdout).decode("utf-8", errors="replace"),
            "stderr": bytes(self._cap_stderr).decode("utf-8", errors="replace"),
        }

    # -- Snapshots (serialize_state / deserialize_state) --

    def snapshot_save(self, label: str = "") -> str:
        self._touch()
        snap_id = self._gen_id("snap-")
        try:
            data = self.app.serialize_state()
        except Exception as e:
            raise RuntimeError(f"Snapshot save failed: {e}") from e
        self.snapshots[snap_id] = SnapshotInfo(
            snapshot_id=snap_id,
            label=label or f"snapshot_{len(self.snapshots)}",
            created_at=time.time(),
            _data=data,
        )
        return snap_id

    def snapshot_restore(self, snapshot_id: str) -> None:
        self._touch()
        snap = self.snapshots.get(snapshot_id)
        if snap is None:
            raise KeyError(f"Snapshot '{snapshot_id}' not found")
        try:
            self.app.deserialize_state(snap._data)
        except Exception as e:
            raise RuntimeError(f"Snapshot restore failed: {e}") from e

    # -- Lifecycle --

    def close(self) -> None:
        try:
            self.app.stop()
        except Exception:
            pass
        self.app = None
        self._emu = None

    def get_info(self) -> dict[str, Any]:
        info = super().get_info()
        info.update({
            "ostype": self.ostype,
            "backend": self._backend_name,
            "binary": self.binary_path or None,
        })
        return info
