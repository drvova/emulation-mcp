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
    ):
        super().__init__(arch=arch)
        self.engine_type = "qiling"
        self.binary_path = binary_path
        self.rootfs = rootfs
        self.ostype = ostype
        self._ql_arch = resolve_arch(arch)
        self._ql_os = resolve_os(ostype)
        self._has_run = False

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

    def hook_syscall(self, name: str, callback: Callable | None = None) -> str:
        self._touch()
        hook_id = self._gen_id("hsys-")

        if callback is None:
            def callback(ql: Qiling, *args: Any, **kwargs: Any) -> Any:
                entry = TraceEntry(
                    trace_type="syscall",
                    name=name,
                    args=list(args),
                )
                try:
                    entry.address = self._read_pc()
                except Exception:
                    pass
                self._append_trace(entry)

        self.ql.os.set_syscall(name, callback, QL_INTERCEPT.CALL)
        self.hooks[hook_id] = HookInfo(
            hook_id=hook_id,
            hook_type="syscall",
            target=name,
            description=f"Syscall hook on '{name}'",
        )
        return hook_id

    # -- Hooks: API --

    def hook_api(self, func_name: str, callback: Callable | None = None) -> str:
        self._touch()
        hook_id = self._gen_id("hapi-")

        if callback is None:
            def callback(ql: Qiling, *args: Any, **kwargs: Any) -> Any:
                entry = TraceEntry(
                    trace_type="api",
                    name=func_name,
                    args=list(args),
                )
                try:
                    entry.address = self._read_pc()
                except Exception:
                    pass
                self._append_trace(entry)

        self.ql.os.set_api(func_name, callback, QL_INTERCEPT.CALL)
        self.hooks[hook_id] = HookInfo(
            hook_id=hook_id,
            hook_type="api",
            target=func_name,
            description=f"API hook on '{func_name}'",
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

    # -- Lifecycle --

    def close(self) -> None:
        try:
            self.ql.stop()
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
