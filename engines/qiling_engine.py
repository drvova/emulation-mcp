"""Qiling Framework emulation engine wrapper."""

import os
import threading
from typing import Any, Callable

from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE, QL_INTERCEPT
from qiling.exception import QlErrorFileNotFound, QlErrorArch, QlErrorOsType

from .base import BaseEngine, HookInfo, SnapshotInfo, TraceEntry

import time

# EM-6: Default timeout for Qiling execution (seconds)
QILING_TIMEOUT_S = int(os.getenv("EMU_QILING_TIMEOUT", "60"))

# Architecture string -> Qiling constant
ARCH_MAP: dict[str, QL_ARCH] = {
    "x86": QL_ARCH.X86,
    "x86_64": QL_ARCH.X8664,
    "x8664": QL_ARCH.X8664,
    "arm": QL_ARCH.ARM,
    "arm64": QL_ARCH.ARM64,
    "aarch64": QL_ARCH.ARM64,
    "mips": QL_ARCH.MIPS,
    "a8086": QL_ARCH.A8086,
    "cortex_m": QL_ARCH.CORTEX_M,
    "riscv": QL_ARCH.RISCV,
    "riscv64": QL_ARCH.RISCV64,
    "ppc": QL_ARCH.PPC,
}

# OS string -> Qiling constant
OS_MAP: dict[str, QL_OS] = {
    "linux": QL_OS.LINUX,
    "windows": QL_OS.WINDOWS,
    "freebsd": QL_OS.FREEBSD,
    "macos": QL_OS.MACOS,
    "uefi": QL_OS.UEFI,
    "dos": QL_OS.DOS,
    "qnx": QL_OS.QNX,
    "blob": QL_OS.BLOB,
}

# Common registers by architecture for registers_read_all
COMMON_REGS: dict[str, list[str]] = {
    "x86": ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags"],
    "x86_64": ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eflags"],
    "x8664": ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eflags"],
    "arm": ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9",
            "r10", "r11", "r12", "sp", "lr", "pc", "cpsr"],
    "arm64": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
              "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18",
              "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
              "x28", "x29", "x30", "sp", "pc"],
    "aarch64": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
                "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18",
                "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
                "x28", "x29", "x30", "sp", "pc"],
    "mips": ["zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
             "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
             "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
             "t8", "t9", "gp", "sp", "fp", "ra", "pc"],
}


def resolve_arch(arch: str) -> QL_ARCH:
    """Resolve architecture string to Qiling constant."""
    key = arch.lower().strip()
    if key not in ARCH_MAP:
        supported = ", ".join(sorted(ARCH_MAP.keys()))
        raise ValueError(f"Unsupported architecture '{arch}'. Supported: {supported}")
    return ARCH_MAP[key]


def resolve_os(ostype: str) -> QL_OS:
    """Resolve OS type string to Qiling constant."""
    key = ostype.lower().strip()
    if key not in OS_MAP:
        supported = ", ".join(sorted(OS_MAP.keys()))
        raise ValueError(f"Unsupported OS type '{ostype}'. Supported: {supported}")
    return OS_MAP[key]


class QilingEngine(BaseEngine):
    """Qiling Framework wrapper for full binary emulation."""

    CAPABILITIES = frozenset({
        "binary_loading", "os_emulation", "address_hooks", "syscall_hooks", "api_hooks", "snapshots",
        "memory_hooks", "callback_hooks", "disassembly", "register_introspection",
        "filesystem", "io",
    })
    SUPPORTED_ARCHS = tuple(ARCH_MAP)

    def __init__(
        self,
        binary_path: str,
        rootfs: str,
        arch: str,
        ostype: str = "linux",
        args: list[str] | None = None,
        enable_trace: bool = False,
        multithread: bool = False,
    ):
        super().__init__(arch=arch)
        self.engine_type = "qiling"
        self.binary_path = binary_path
        self.rootfs = rootfs
        self.ostype = ostype
        self._ql_arch = resolve_arch(arch)
        self._ql_os = resolve_os(ostype)
        self._has_run = False
        self._multithread = bool(multithread)
        # Output-capture buffers, populated by capture_output().
        self._cap_stdout: bytearray | None = None
        self._cap_stderr: bytearray | None = None

        if args is None:
            args = []

        verbose = QL_VERBOSE.DEBUG if enable_trace else QL_VERBOSE.DISABLED
        if enable_trace:
            self.tracing_enabled = True

        try:
            self.ql = Qiling(
                argv=[binary_path] + args,
                rootfs=rootfs,
                verbose=verbose,
                multithread=self._multithread,
            )
        except QlErrorFileNotFound as e:
            raise RuntimeError(
                f"Qiling file not found: {e}\n"
                f"Ensure the binary exists at '{binary_path}' and the rootfs at "
                f"'{rootfs}' contains the required shared libraries (e.g. "
                f"lib/ld-linux*.so, lib/libc.so.6 for Linux targets)."
            ) from e
        except QlErrorArch as e:
            raise RuntimeError(
                f"Qiling architecture error: {e}\n"
                f"The binary at '{binary_path}' may not match arch='{arch}'."
            ) from e
        except QlErrorOsType as e:
            raise RuntimeError(
                f"Qiling OS type error: {e}\n"
                f"The binary may not match ostype='{ostype}'."
            ) from e
        except Exception as e:
            raise RuntimeError(
                f"Failed to initialize Qiling: {type(e).__name__}: {e}\n"
                f"Binary: '{binary_path}', rootfs: '{rootfs}', "
                f"arch: '{arch}', os: '{ostype}'"
            ) from e

    # -- Execution --

    def start(self, begin: int = 0, end: int = 0, timeout_ms: int = 10000) -> dict[str, Any]:
        self._touch()
        timeout_us = timeout_ms * 1000  # Qiling/Unicorn timeout is in microseconds
        try:
            kwargs: dict[str, Any] = {"timeout": timeout_us}
            if begin:
                kwargs["begin"] = begin
            if end:
                kwargs["end"] = end

            # EM-6: Cross-platform timeout enforcement via threading.Timer
            hard_timeout = min(timeout_ms / 1000.0, QILING_TIMEOUT_S)
            timer = threading.Timer(hard_timeout, self._force_stop)
            timer.daemon = True
            timer.start()
            try:
                self.ql.run(**kwargs)
            finally:
                timer.cancel()
            self._has_run = True
        except Exception as e:
            err_msg = str(e)
            # Try to capture crash address
            crash_addr = None
            try:
                crash_addr = self._read_pc()
            except Exception:
                pass
            return {
                "status": "error",
                "error": err_msg,
                "crash_address": f"0x{crash_addr:x}" if crash_addr else None,
                "trace_entries": len(self.trace),
            }

        return {
            "status": "stopped",
            "trace_entries": len(self.trace),
        }

    def _force_stop(self) -> None:
        """Force-stop emulation from a timer thread (EM-6)."""
        try:
            self.ql.stop()
        except Exception:
            pass

    def step(self, count: int = 1) -> list[TraceEntry]:
        self._touch()
        stepped: list[TraceEntry] = []
        remaining = count

        def _step_hook(ql: Qiling, address: int, size: int) -> None:
            nonlocal remaining
            if remaining <= 0:
                ql.stop()
                return
            remaining -= 1
            entry = TraceEntry(
                address=address,
                size=size,
                trace_type="instruction",
            )
            # Try to read the instruction bytes for display
            try:
                insn_bytes = ql.mem.read(address, size)
                entry.instruction = insn_bytes.hex()
            except Exception:
                pass
            stepped.append(entry)
            if self.tracing_enabled:
                self._append_trace(entry)
            if remaining <= 0:
                ql.stop()

        hook_handle = self.ql.hook_code(_step_hook)
        # EM-6: Cross-platform timeout enforcement via threading.Timer
        timer = threading.Timer(QILING_TIMEOUT_S, self._force_stop)
        timer.daemon = True
        timer.start()
        try:
            self.ql.run(count=count)
        except Exception:
            pass
        finally:
            timer.cancel()
            self.ql.hook_del(hook_handle)

        return stepped

    def stop(self) -> None:
        self._touch()
        try:
            self.ql.stop()
        except Exception:
            pass

    # -- Hooks: syscall --

    _INTERCEPT = None  # lazily built {when: QL_INTERCEPT}

    @classmethod
    def _resolve_intercept(cls, when: str):
        if cls._INTERCEPT is None:
            cls._INTERCEPT = {
                "call": QL_INTERCEPT.CALL,
                "enter": QL_INTERCEPT.ENTER,
                "exit": QL_INTERCEPT.EXIT,
            }
        key = str(when).lower().strip()
        if key not in cls._INTERCEPT:
            raise ValueError(f"when must be one of call/enter/exit, got {when!r}")
        return cls._INTERCEPT[key]

    def hook_syscall(self, name: str, callback: Callable | None = None, when: str = "call") -> str:
        """Intercept a syscall. when='call' replaces it; 'enter'/'exit' observe
        it around the real handler (leaving behaviour intact)."""
        self._touch()
        hook_id = self._gen_id("hsys-")
        intercept = self._resolve_intercept(when)

        if callback is None:
            def callback(ql: Qiling, *args: Any, **kwargs: Any) -> Any:
                entry = TraceEntry(
                    trace_type="syscall",
                    name=f"{name}:{when}",
                    args=list(args),
                )
                try:
                    entry.address = self._read_pc()
                except Exception:
                    pass
                self._append_trace(entry)

        self.ql.os.set_syscall(name, callback, intercept)
        self.hooks[hook_id] = HookInfo(
            hook_id=hook_id,
            hook_type="syscall",
            target=name,
            description=f"Syscall hook on '{name}' ({when})",
        )
        return hook_id

    # -- Hooks: API --

    def hook_api(self, func_name: str, callback: Callable | None = None, when: str = "call") -> str:
        """Intercept a library/API call. when='call' replaces it; 'enter'/'exit'
        observe it around the real implementation."""
        self._touch()
        hook_id = self._gen_id("hapi-")
        intercept = self._resolve_intercept(when)

        if callback is None:
            def callback(ql: Qiling, *args: Any, **kwargs: Any) -> Any:
                entry = TraceEntry(
                    trace_type="api",
                    name=f"{func_name}:{when}",
                    args=list(args),
                )
                try:
                    entry.address = self._read_pc()
                except Exception:
                    pass
                self._append_trace(entry)

        self.ql.os.set_api(func_name, callback, intercept)
        self.hooks[hook_id] = HookInfo(
            hook_id=hook_id,
            hook_type="api",
            target=func_name,
            description=f"API hook on '{func_name}' ({when})",
        )
        return hook_id

    # -- Hooks: address --

    def hook_address(self, address: int, callback: Callable | None = None) -> str:
        self._touch()
        hook_id = self._gen_id("haddr-")

        if callback is None:
            def callback(ql: Qiling) -> None:
                entry = TraceEntry(
                    address=address,
                    trace_type="instruction",
                    name=f"hook@0x{address:x}",
                )
                self._append_trace(entry)

        handle = self.ql.hook_address(callback, address)
        self.hooks[hook_id] = HookInfo(
            hook_id=hook_id,
            hook_type="address",
            target=f"0x{address:x}",
            description=f"Address hook at 0x{address:x}",
            _handle=handle,
        )
        return hook_id

    # -- Hooks: fine-grained instrumentation (bottom-level) --

    def _mem_hook_fn(self, kind: str):
        return {
            "read": self.ql.hook_mem_read,
            "write": self.ql.hook_mem_write,
            "unmapped": self.ql.hook_mem_unmapped,
            "invalid": self.ql.hook_mem_invalid,
        }.get(kind)

    def add_mem_hook(self, callback: Callable, kind: str = "write",
                     start: int | None = None, end: int | None = None) -> str:
        """Fire a callback on guest memory access.

        kind is "read", "write", "unmapped" or "invalid". The callback has
        Qiling's native signature `cb(ql, access, address, size, value)`. start/end
        bound the watched range (inclusive); omit both to watch everything. Returns
        a hook id; remove with hook_remove(). Install before running.
        """
        self._touch()
        hook_fn = self._mem_hook_fn(kind)
        if hook_fn is None:
            raise ValueError(f"kind must be read/write/unmapped/invalid, got {kind!r}")
        # Qiling treats begin>end as "no range filter" (whole space).
        begin = 1 if start is None else start
        stop = 0 if end is None else end
        handle = hook_fn(callback, begin=begin, end=stop)
        hook_id = self._gen_id("hmem-")
        self.hooks[hook_id] = HookInfo(
            hook_id=hook_id, hook_type=f"mem_{kind}",
            target=(f"0x{begin:x}-0x{stop:x}" if start is not None else "all"),
            description=f"Memory {kind} hook", _handle=handle,
        )
        return hook_id

    def add_code_hook(self, callback: Callable,
                      start: int | None = None, end: int | None = None) -> str:
        """Fire `cb(ql, address, size)` on every instruction (optionally in a range)."""
        self._touch()
        begin = 1 if start is None else start
        stop = 0 if end is None else end
        handle = self.ql.hook_code(callback, begin=begin, end=stop)
        hook_id = self._gen_id("hcode-")
        self.hooks[hook_id] = HookInfo(
            hook_id=hook_id, hook_type="code",
            target=(f"0x{begin:x}-0x{stop:x}" if start is not None else "all"),
            description="Per-instruction code hook", _handle=handle,
        )
        return hook_id

    def add_block_hook(self, callback: Callable,
                       start: int | None = None, end: int | None = None) -> str:
        """Fire `cb(ql, address, size)` on every basic block (optionally in a range)."""
        self._touch()
        begin = 1 if start is None else start
        stop = 0 if end is None else end
        handle = self.ql.hook_block(callback, begin=begin, end=stop)
        hook_id = self._gen_id("hblk-")
        self.hooks[hook_id] = HookInfo(
            hook_id=hook_id, hook_type="block",
            target=(f"0x{begin:x}-0x{stop:x}" if start is not None else "all"),
            description="Per-block hook", _handle=handle,
        )
        return hook_id

    def add_intr_hook(self, callback: Callable) -> str:
        """Fire `cb(ql, intno)` on every interrupt/exception."""
        self._touch()
        handle = self.ql.hook_intr(callback)
        hook_id = self._gen_id("hintr-")
        self.hooks[hook_id] = HookInfo(
            hook_id=hook_id, hook_type="interrupt", target="all",
            description="Interrupt hook", _handle=handle,
        )
        return hook_id

    @staticmethod
    def _resolve_insn(insn: str) -> int:
        """Map an x86 instruction name to its Unicorn instruction id."""
        from unicorn import x86_const
        key = str(insn).lower().strip()
        table = {
            "syscall": "UC_X86_INS_SYSCALL", "sysenter": "UC_X86_INS_SYSENTER",
            "cpuid": "UC_X86_INS_CPUID", "in": "UC_X86_INS_IN", "out": "UC_X86_INS_OUT",
        }
        const = table.get(key)
        if const is None or not hasattr(x86_const, const):
            raise ValueError(f"Unsupported instruction '{insn}'. Supported: {sorted(table)}")
        return getattr(x86_const, const)

    def hook_insn(self, callback: Callable, insn: str) -> str:
        """Fire a callback whenever a specific instruction executes.

        insn is one of syscall/sysenter/cpuid/in/out (x86/x64). The callback gets
        Qiling's native signature for that instruction type; returning True skips
        the instruction. Install before running; remove with hook_remove().
        """
        self._touch()
        insn_id = self._resolve_insn(insn)
        handle = self.ql.hook_insn(callback, insn_id)
        hook_id = self._gen_id("hinsn-")
        self.hooks[hook_id] = HookInfo(
            hook_id=hook_id, hook_type="insn", target=str(insn).lower(),
            description=f"Instruction hook on '{insn}'", _handle=handle,
        )
        return hook_id

    def syscall_stats(self) -> dict[str, Any]:
        """Return syscall usage counts and observed strings gathered during a run."""
        self._touch()
        stats = getattr(self.ql.os, "stats", None)
        if stats is None:
            return {"syscalls": {}, "strings": [], "note": "stats unavailable"}
        syscalls: dict[str, int] = {}
        for k, v in dict(getattr(stats, "syscalls", {}) or {}).items():
            # Qiling records each syscall as a list of call entries; use the count.
            syscalls[str(k)] = len(v) if isinstance(v, (list, tuple, set, dict)) else int(v)
        strings = [str(s) for s in (getattr(stats, "strings", []) or [])][:64]
        return {"syscalls": syscalls, "total": sum(syscalls.values()), "strings": strings}

    def list_threads(self) -> dict[str, Any]:
        """Report the guest's thread state (populated for multithreaded runs)."""
        self._touch()
        tm = getattr(self.ql.os, "thread_management", None)
        if tm is None:
            return {"multithread": self._multithread, "threads": [],
                    "note": "single-threaded (or run not started)"}
        threads = getattr(tm, "threads", None) or []
        out = []
        for t in threads:
            out.append({"id": getattr(t, "id", getattr(t, "get_id", lambda: None)()),
                        "status": str(getattr(t, "status", ""))})
        cur = getattr(tm, "cur_thread", None)
        return {"multithread": self._multithread, "count": len(out),
                "current": getattr(cur, "id", None), "threads": out}

    def hook_remove(self, hook_id: str) -> bool:
        info = self.hooks.get(hook_id)
        if info is None:
            return False
        if info._handle is not None:
            try:
                self.ql.hook_del(info._handle)
            except Exception:
                pass
        del self.hooks[hook_id]
        return True

    # -- Memory --

    def memory_read(self, address: int, size: int) -> bytes:
        try:
            return bytes(self.ql.mem.read(address, size))
        except Exception as e:
            raise RuntimeError(f"Memory read failed at 0x{address:x} (size={size}): {e}") from e

    def memory_write(self, address: int, data: bytes) -> None:
        try:
            self.ql.mem.write(address, data)
        except Exception as e:
            raise RuntimeError(f"Memory write failed at 0x{address:x}: {e}") from e

    def memory_map(self, address: int, size: int, perms: int = 7) -> None:
        try:
            self.ql.mem.map(address, size, perms)
        except Exception as e:
            raise RuntimeError(f"Memory map failed at 0x{address:x} (size=0x{size:x}): {e}") from e

    def memory_search(self, pattern: bytes) -> list[int]:
        try:
            return list(self.ql.mem.search(pattern))
        except Exception as e:
            raise RuntimeError(f"Memory search failed: {e}") from e

    def memory_maps(self) -> list[dict[str, Any]]:
        """List the mapped regions as (start, end, perms, label, path)."""
        self._touch()
        out: list[dict[str, Any]] = []
        try:
            rows = self.ql.mem.get_mapinfo()
        except Exception as e:
            raise RuntimeError(f"Memory-map listing failed: {e}") from e
        for row in rows:
            start, end, perms, label = row[0], row[1], row[2], row[3]
            path = row[4] if len(row) > 4 else ""
            out.append({"start": start, "end": end, "perms": perms,
                        "label": label, "path": path})
        return out

    def read_string(self, address: int, max_len: int = 1024) -> str:
        """Read a NUL-terminated string (decoding undecodable bytes leniently)."""
        self._touch()
        try:
            raw = bytes(self.ql.mem.read(address, max_len))
        except Exception as e:
            raise RuntimeError(f"String read failed at 0x{address:x}: {e}") from e
        nul = raw.find(b"\x00")
        if nul != -1:
            raw = raw[:nul]
        return raw.decode("utf-8", errors="replace")

    # -- Disassembly --

    def disassemble(self, address: int, count: int = 1) -> list[dict[str, Any]]:
        """Disassemble `count` instructions at `address` using Qiling's capstone."""
        self._touch()
        md = self.ql.arch.disassembler
        # Read enough bytes for `count` instructions (max x86 insn is 15 bytes).
        try:
            code = bytes(self.ql.mem.read(address, max(count, 1) * 15 + 16))
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

    # -- Registers --

    def register_read(self, name: str) -> int:
        try:
            return getattr(self.ql.arch.regs, name.lower())
        except AttributeError:
            raise ValueError(f"Unknown register '{name}' for arch '{self.arch}'")

    def register_write(self, name: str, value: int) -> None:
        try:
            setattr(self.ql.arch.regs, name.lower(), value)
        except AttributeError:
            raise ValueError(f"Unknown register '{name}' for arch '{self.arch}'")

    def registers_read_all(self) -> dict[str, int]:
        reg_names = COMMON_REGS.get(self.arch.lower(), [])
        result: dict[str, int] = {}
        for name in reg_names:
            try:
                result[name] = getattr(self.ql.arch.regs, name)
            except (AttributeError, Exception):
                pass
        return result

    def list_registers(self) -> dict[str, dict[str, int]]:
        """Enumerate the architecture's full register file with current values."""
        self._touch()
        out: dict[str, dict[str, int]] = {}
        mapping = getattr(self.ql.arch.regs, "register_mapping", {}) or {}
        for name in mapping:
            try:
                out[name] = {"value": int(getattr(self.ql.arch.regs, name))}
            except Exception:
                continue
        return out

    # -- Snapshots --

    def snapshot_save(self, label: str = "") -> str:
        self._touch()
        snap_id = self._gen_id("snap-")
        try:
            data = self.ql.save(reg=True, mem=True)
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
            self.ql.restore(snap._data)
        except Exception as e:
            raise RuntimeError(f"Snapshot restore failed: {e}") from e

    # -- Filesystem & I/O (Qiling's binary-emulation power) --

    def add_fs_mapper(self, guest_path: str, host_path: str) -> None:
        """Map a host file or directory to a path inside the emulated FS.

        The guest sees `host_path`'s contents when it opens `guest_path`. Use it
        to supply config files, device nodes, or a /flag the target reads.
        """
        self._touch()
        if not os.path.exists(host_path):
            raise FileNotFoundError(f"Host path does not exist: {host_path}")
        try:
            self.ql.add_fs_mapper(guest_path, host_path)
        except Exception as e:
            raise RuntimeError(f"Filesystem mapping failed ({guest_path} -> {host_path}): {e}") from e

    def set_stdin(self, data: bytes) -> None:
        """Preload the guest's standard input with `data`."""
        self._touch()
        from qiling.os.posix.filestruct import ql_pipe
        rd, wr = ql_pipe.open()
        try:
            wr.write(bytes(data))
        except Exception as e:
            raise RuntimeError(f"stdin injection failed: {e}") from e
        self.ql.os.stdin = rd

    def capture_output(self) -> None:
        """Begin capturing the guest's stdout and stderr (call before run)."""
        self._touch()
        self._cap_stdout = bytearray()
        self._cap_stderr = bytearray()
        self._wrap_stream(self.ql.os.stdout, self._cap_stdout)
        self._wrap_stream(self.ql.os.stderr, self._cap_stderr)

    @staticmethod
    def _wrap_stream(stream: Any, buffer: bytearray) -> None:
        # Qiling may share one stdout/stderr object across instances, so save the
        # true original once and always re-point the tee to the current buffer
        # (the latest capture_output wins). Restored in close().
        original = getattr(stream, "_emu_orig_write", None) or stream.write
        stream._emu_orig_write = original

        def _tee(data: Any) -> Any:
            try:
                buffer.extend(bytes(data))
            except Exception:
                pass
            return original(data)

        stream.write = _tee

    @staticmethod
    def _unwrap_stream(stream: Any) -> None:
        original = getattr(stream, "_emu_orig_write", None)
        if original is not None:
            stream.write = original
            try:
                del stream._emu_orig_write
            except Exception:
                pass

    def get_output(self) -> dict[str, str]:
        """Return the stdout/stderr captured since capture_output()."""
        self._touch()
        if self._cap_stdout is None:
            raise RuntimeError("Output capture not started; call capture_output() first.")
        return {
            "stdout": bytes(self._cap_stdout).decode("utf-8", errors="replace"),
            "stderr": bytes(self._cap_stderr).decode("utf-8", errors="replace"),
        }

    # -- Lifecycle --

    def close(self) -> None:
        try:
            self.ql.stop()
        except Exception:
            pass
        # Restore any stdout/stderr write wrappers installed by capture_output().
        if self._cap_stdout is not None:
            try:
                self._unwrap_stream(self.ql.os.stdout)
                self._unwrap_stream(self.ql.os.stderr)
            except Exception:
                pass
        self.hooks.clear()
        self.snapshots.clear()
        self.trace.clear()

    # -- Helpers --

    def _read_pc(self) -> int:
        """Read the program counter for the current architecture."""
        arch_lower = self.arch.lower()
        if arch_lower in ("x86",):
            return self.ql.arch.regs.eip
        elif arch_lower in ("x86_64", "x8664"):
            return self.ql.arch.regs.rip
        elif arch_lower in ("arm", "arm64", "aarch64"):
            return self.ql.arch.regs.pc
        elif arch_lower in ("mips",):
            return self.ql.arch.regs.pc
        else:
            return self.ql.arch.regs.pc
