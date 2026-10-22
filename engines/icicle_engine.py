"""Icicle emulation engine wrapper.

Icicle (https://github.com/icicle-emu/icicle-emu) is a CPU emulator built on
Ghidra's SLEIGH instruction semantics.  It covers the same shellcode/snippet
workflow as Unicorn but reaches more architectures (RISC-V, PowerPC, MSP430,
...) and, because it is an entirely independent implementation, is useful as a
cross-check against Unicorn when a result looks suspicious.

Notes on the icicle-emu Python bindings this wrapper targets:

* The bindings expose no per-instruction callback, so instruction tracing and
  address hooks are implemented by single-stepping (``step(1)``) and inspecting
  the program counter between steps.  Without tracing or hooks we fall back to
  the native ``run_until`` for speed.

* The JIT has a known correctness issue where a breakpoint added to a block
  that was already translated by a prior ``step`` is ignored.  We therefore
  construct the VM with ``jit=False``; it is still fast enough for the small
  snippets this tool runs, and correctness matters more than throughput here.

* There is no wall-clock stop on a running VM, so runaway code is bounded by an
  instruction budget (``icount_limit``) rather than a timer.
"""

import time
from typing import Any, Callable

from icicle import Icicle, MemoryProtection, RunStatus, ExceptionCode, MemoryException

from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_MIPS
from capstone import CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_THUMB
from capstone import CS_MODE_MIPS32, CS_MODE_BIG_ENDIAN, CS_MODE_LITTLE_ENDIAN
try:
    from capstone import CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCV64
    _HAS_CS_RISCV = True
except ImportError:  # older capstone
    _HAS_CS_RISCV = False
try:
    from capstone import CS_ARCH_PPC, CS_MODE_32 as _CS_PPC32, CS_MODE_64 as _CS_PPC64
    _HAS_CS_PPC = True
except ImportError:
    _HAS_CS_PPC = False

from .base import (
    BaseEngine, HookInfo, SnapshotInfo, TraceEntry,
    CODE_BASE, CODE_SIZE, STACK_BASE, STACK_SIZE, STACK_TOP,
    HEAP_BASE, HEAP_SIZE,
)


# Architecture string -> icicle architecture name.
# Keys mirror the Unicorn engine's naming so addresses/arch strings are portable.
ARCH_MAP: dict[str, str] = {
    "x86":       "i686",
    "x86_64":    "x86_64",
    "arm":       "armv7a",
    "arm_thumb": "thumbv7a",
    "arm64":     "aarch64",
    "mips":      "mips",
    "mips_le":   "mipsel",
    "riscv32":   "riscv32imc",
    "riscv64":   "riscv64gc",
    "ppc":       "powerpc",
    "ppc64":     "powerpc64",
    "msp430":    "msp430",
}

# Capstone arch/mode for disassembly during tracing.  None => no disassembler
# (the trace falls back to raw bytes), which is fine for architectures capstone
# cannot handle.
_CS_MAP: dict[str, tuple[int, int] | None] = {
    "x86":       (CS_ARCH_X86,   CS_MODE_32),
    "x86_64":    (CS_ARCH_X86,   CS_MODE_64),
    "arm":       (CS_ARCH_ARM,   CS_MODE_ARM),
    "arm_thumb": (CS_ARCH_ARM,   CS_MODE_THUMB),
    "arm64":     (CS_ARCH_ARM64, CS_MODE_ARM),
    "mips":      (CS_ARCH_MIPS,  CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN),
    "mips_le":   (CS_ARCH_MIPS,  CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN),
}
if _HAS_CS_RISCV:
    _CS_MAP["riscv32"] = (CS_ARCH_RISCV, CS_MODE_RISCV32)
    _CS_MAP["riscv64"] = (CS_ARCH_RISCV, CS_MODE_RISCV64)
if _HAS_CS_PPC:
    _CS_MAP["ppc"] = (CS_ARCH_PPC, _CS_PPC32 + CS_MODE_BIG_ENDIAN)
    _CS_MAP["ppc64"] = (CS_ARCH_PPC, _CS_PPC64 + CS_MODE_BIG_ENDIAN)

# Common registers per architecture for registers_read_all / snapshots.
COMMON_REGS: dict[str, list[str]] = {
    "x86":       ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags"],
    "x86_64":    ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
                  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eflags"],
    "arm":       ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9",
                  "r10", "r11", "r12", "sp", "lr", "pc", "cpsr"],
    "arm_thumb": ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9",
                  "r10", "r11", "r12", "sp", "lr", "pc", "cpsr"],
    "arm64":     [f"x{i}" for i in range(31)] + ["sp", "pc", "nzcv"],
    "mips":      ["zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
                  "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
                  "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
                  "t8", "t9", "gp", "sp", "s8", "ra", "pc"],
    "mips_le":   ["zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
                  "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
                  "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
                  "t8", "t9", "gp", "sp", "s8", "ra", "pc"],
    "riscv32":   ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0",
                  "s1"] + [f"a{i}" for i in range(8)] + ["pc"],
    "riscv64":   ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0",
                  "s1"] + [f"a{i}" for i in range(8)] + ["pc"],
    "ppc":       [f"r{i}" for i in range(32)] + ["pc", "lr", "ctr", "xer", "msr"],
    "ppc64":     [f"r{i}" for i in range(32)] + ["pc", "lr", "ctr", "xer", "msr"],
    "msp430":    [f"r{i}" for i in range(16)],
}

PAGE_SIZE = 0x1000
# How many instructions to let a traceless native run execute before giving up.
MAX_RUN_INSNS = 50_000_000

# Permission bitmask (rwx, 4=r/2=w/1=x) -> icicle MemoryProtection.
_PERM_MAP: dict[int, MemoryProtection] = {
    0: MemoryProtection.NoAccess,
    1: MemoryProtection.ExecuteOnly,
    4: MemoryProtection.ReadOnly,
    5: MemoryProtection.ExecuteRead,
    6: MemoryProtection.ReadWrite,
    7: MemoryProtection.ExecuteReadWrite,
}


def _to_protection(perms: int) -> MemoryProtection:
    """Map an rwx bitmask to the closest icicle MemoryProtection."""
    prot = _PERM_MAP.get(perms)
    if prot is not None:
        return prot
    # Fall back by feature: anything writable implies read, exec implies read.
    if perms & 2:
        return MemoryProtection.ExecuteReadWrite if perms & 1 else MemoryProtection.ReadWrite
    if perms & 1:
        return MemoryProtection.ExecuteRead
    if perms & 4:
        return MemoryProtection.ReadOnly
    return MemoryProtection.ExecuteReadWrite


class IcicleEngine(BaseEngine):
    """Icicle (SLEIGH) CPU emulator for code snippet and shellcode analysis."""

    CAPABILITIES = frozenset({
        "shellcode", "address_hooks", "instruction_trace", "snapshots",
    })
    SUPPORTED_ARCHS = tuple(ARCH_MAP)

    def __init__(self, arch: str, **kwargs: Any):
        if arch not in ARCH_MAP:
            raise ValueError(
                f"Unsupported architecture '{arch}'. Supported: {list(ARCH_MAP.keys())}"
            )
        super().__init__(arch, **kwargs)
        self.engine_type = "icicle"

        icicle_arch = ARCH_MAP[arch]
        try:
            # jit=False avoids a breakpoint-after-step miss in the JIT path.
            self.vm = Icicle(icicle_arch, jit=False)
        except Exception as e:
            raise RuntimeError(
                f"Failed to initialize Icicle for arch '{arch}' ({icicle_arch}): {e}"
            ) from e

        cs_spec = _CS_MAP.get(arch)
        self.cs: Cs | None = Cs(*cs_spec) if cs_spec else None

        # Track mapped regions ourselves: icicle exposes no map enumeration and
        # we need it for memory_search and snapshots.
        self._regions: dict[int, tuple[int, int]] = {}   # base -> (size, perms)

        # Default layout mirrors the Unicorn engine so addresses are portable.
        self.memory_map(CODE_BASE, CODE_SIZE, 7)
        self.memory_map(STACK_BASE, STACK_SIZE, 6)
        self.memory_map(HEAP_BASE, HEAP_SIZE, 7)

        self.vm.sp = STACK_TOP
        self.stack_overflow_detected = False

    # -- Internal helpers --

    def _disasm(self, address: int, code: bytes) -> str:
        if self.cs is not None:
            for _a, _sz, mnemonic, op_str in self.cs.disasm_lite(code, address):
                return f"{mnemonic} {op_str}".strip()
        return f"db {code.hex()}"

    def _trace_instruction(self, address: int) -> int:
        """Append a trace entry for the instruction at `address`. Returns its size."""
        # We do not know the instruction length up front; read a generous window
        # and let capstone report the real size.
        try:
            window = self.vm.mem_read(address, 16)
        except MemoryException:
            window = b""
        size = 1
        text = ""
        if self.cs is not None and window:
            for _a, sz, mnemonic, op_str in self.cs.disasm_lite(window, address):
                size = sz or 1
                text = f"{mnemonic} {op_str}".strip()
                break
        if not text:
            text = f"db {window[:4].hex()}" if window else "??"
        self._append_trace(TraceEntry(
            address=address, instruction=text, size=size, trace_type="instruction",
        ))
        return size

    def _dispatch_hook(self, address: int) -> None:
        info = self._addr_hooks.get(address)
        if info is None:
            return
        if info._handle is None:
            self._append_trace(TraceEntry(
                address=address, instruction=info.description,
                trace_type="hook", name=f"hook@0x{address:x}",
            ))
            return
        try:
            info._handle(self, address)
        except Exception as e:
            self._append_trace(TraceEntry(
                address=address, instruction=f"Hook exception: {e}",
                trace_type="error", name="hook_exception",
            ))

    # -- Execution --

    def start(self, begin: int, end: int, timeout_ms: int = 10000) -> dict[str, Any]:
        self._touch()
        self.stack_overflow_detected = False
        self.vm.pc = begin

        use_step_loop = self.tracing_enabled or bool(self._addr_hooks)
        start_time = time.time()
        error_msg = ""
        status_name = "ok"

        if use_step_loop:
            status_name, error_msg = self._run_stepwise(end, timeout_ms)
        else:
            status_name, error_msg = self._run_native(end)

        elapsed = time.time() - start_time
        result: dict[str, Any] = {
            "status": status_name,
            "elapsed_ms": round(elapsed * 1000, 2),
            "instructions_traced": len(self.trace),
            "instructions_executed": self.vm.icount,
            "pc": f"0x{self.vm.pc:x}",
        }
        if error_msg:
            result["error"] = error_msg
        return result

    def _run_native(self, end: int) -> tuple[str, str]:
        """Fast path used when there is nothing to observe per-instruction."""
        self.vm.icount_limit = self.vm.icount + MAX_RUN_INSNS
        st = self.vm.run_until(end)
        if st == RunStatus.Breakpoint:
            # The only breakpoint in play is run_until's own at `end`.
            return "ok", ""
        if st == RunStatus.InstructionLimit:
            return "timeout", f"Instruction budget ({MAX_RUN_INSNS}) exhausted before reaching 0x{end:x}"
        return self._status_from_runstatus(st)

    def _run_stepwise(self, end: int, timeout_ms: int) -> tuple[str, str]:
        """Single-step loop used when tracing is on or address hooks are set.

        Hooks are detected by comparing the program counter, so no breakpoints
        are installed (a breakpoint would stall ``step(1)``, which refuses to
        advance off an address that carries one).
        """
        deadline = time.time() + max(timeout_ms, 1) / 1000.0
        while True:
            pc = self.vm.pc
            if pc == end:
                return "ok", ""
            if time.time() > deadline:
                return "timeout", f"Wall-clock timeout ({timeout_ms} ms) before reaching 0x{end:x}"
            if self.tracing_enabled:
                self._trace_instruction(pc)
            self._dispatch_hook(pc)
            st = self.vm.step(1)
            if st == RunStatus.InstructionLimit:
                # step(1) completed one instruction normally.
                continue
            return self._status_from_runstatus(st)

    def _status_from_runstatus(self, st: RunStatus) -> tuple[str, str]:
        if st == RunStatus.Halt:
            return "ok", ""
        if st == RunStatus.UnhandledException:
            return self._exception_status()
        if st == RunStatus.OutOfMemory:
            return "error", "Out of memory"
        return "error", f"Execution stopped: {st}"

    def _exception_status(self) -> tuple[str, str]:
        code = self.vm.exception_code
        value = self.vm.exception_value
        if code == ExceptionCode.SelfModifyingCode:
            return ("self_modifying_code",
                    f"Self-modifying code at 0x{value:x} (pc=0x{self.vm.pc:x}); "
                    f"Icicle does not transparently re-translate modified code.")
        return "error", f"{code} at/for address 0x{value:x} (pc=0x{self.vm.pc:x})"

    def step(self, count: int = 1) -> list[TraceEntry]:
        self._touch()
        was_tracing = self.tracing_enabled
        self.tracing_enabled = True
        trace_start = len(self.trace)
        for _ in range(max(count, 1)):
            pc = self.vm.pc
            self._trace_instruction(pc)
            self._dispatch_hook(pc)
            st = self.vm.step(1)
            if st != RunStatus.InstructionLimit:
                # Anything other than a clean one-instruction completion (a
                # crash, a halt, or self-modifying code) ends the stepping run.
                break
        self.tracing_enabled = was_tracing
        return list(self.trace)[trace_start:]

    def stop(self) -> None:
        # The icicle bindings expose no asynchronous stop; execution is bounded
        # by instruction budget and wall-clock checks in the run loops instead.
        self._touch()

    # -- Memory --

    def memory_read(self, address: int, size: int) -> bytes:
        try:
            return bytes(self.vm.mem_read(address, size))
        except MemoryException as e:
            raise RuntimeError(f"Memory read failed at 0x{address:x} (size={size}): {e}") from e

    def memory_write(self, address: int, data: bytes) -> None:
        try:
            self.vm.mem_write(address, bytes(data))
        except MemoryException as e:
            raise RuntimeError(f"Memory write failed at 0x{address:x}: {e}") from e

    def memory_map(self, address: int, size: int, perms: int = 7) -> None:
        try:
            self.vm.mem_map(address, size, _to_protection(perms))
        except MemoryException as e:
            raise RuntimeError(f"Memory map failed at 0x{address:x} (size=0x{size:x}): {e}") from e
        self._regions[address] = (size, perms)

    def memory_search(self, pattern: bytes) -> list[int]:
        results: list[int] = []
        for base, (size, _perms) in sorted(self._regions.items()):
            try:
                data = bytes(self.vm.mem_read(base, size))
            except MemoryException:
                continue
            offset = 0
            while True:
                idx = data.find(pattern, offset)
                if idx == -1:
                    break
                results.append(base + idx)
                offset = idx + 1
        return results

    # -- Registers --

    def register_read(self, name: str) -> int:
        try:
            return self.vm.reg_read(name.lower())
        except KeyError as e:
            raise ValueError(f"Unknown register '{name}' for arch '{self.arch}'") from e

    def register_write(self, name: str, value: int) -> None:
        try:
            self.vm.reg_write(name.lower(), value & 0xFFFFFFFFFFFFFFFF)
        except KeyError as e:
            raise ValueError(f"Unknown register '{name}' for arch '{self.arch}'") from e

    def registers_read_all(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for name in COMMON_REGS.get(self.arch, []):
            try:
                result[name] = self.vm.reg_read(name)
            except KeyError:
                pass
        return result

    # -- Hooks --

    def hook_address(self, address: int, callback: Callable | None = None) -> str:
        self._touch()
        hook_id = self._gen_id("hook-")
        info = HookInfo(
            hook_id=hook_id,
            hook_type="address",
            target=f"0x{address:x}",
            description=f"Address hook at 0x{address:x}",
            _handle=callback,
        )
        self.hooks[hook_id] = info
        self._addr_hooks[address] = info
        # No breakpoint is installed: the presence of an address hook forces the
        # single-step run loop, which detects the hook by program counter.  (A
        # breakpoint would stall step(1), which refuses to advance off it.)
        return hook_id

    def hook_remove(self, hook_id: str) -> bool:
        self._touch()
        info = self.hooks.get(hook_id)
        if info is None:
            return False
        if info.hook_type == "address":
            addr = int(info.target, 16)
            self._addr_hooks.pop(addr, None)
        del self.hooks[hook_id]
        return True

    # -- Snapshots --

    def snapshot_save(self, label: str = "") -> str:
        self._touch()
        regs = {}
        for name in COMMON_REGS.get(self.arch, []):
            try:
                regs[name] = self.vm.reg_read(name)
            except KeyError:
                pass
        mem = []
        for base, (size, perms) in sorted(self._regions.items()):
            try:
                mem.append((base, size, perms, bytes(self.vm.mem_read(base, size))))
            except MemoryException:
                pass
        data = {
            "regs": regs,
            "mem": mem,
            "pc": self.vm.pc,
            "sp": self.vm.sp,
            "icount": self.vm.icount,
        }
        snap_id = self._gen_id("snap-")
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
            raise KeyError(f"Snapshot '{snapshot_id}' not found. Available: {list(self.snapshots.keys())}")
        data = snap._data
        # reset() clears memory and the (possibly stale) code cache; rebuilding
        # from the snapshot afterwards avoids self-modifying-code faults that a
        # plain overwrite of executed pages would raise.
        self.vm.reset()
        self._regions.clear()
        for base, size, perms, payload in data["mem"]:
            self.vm.mem_map(base, size, _to_protection(perms))
            self._regions[base] = (size, perms)
            self.vm.mem_write(base, payload)
        for name, value in data["regs"].items():
            try:
                self.vm.reg_write(name, value)
            except KeyError:
                pass
        self.vm.pc = data["pc"]
        self.vm.sp = data["sp"]
        self.vm.icount = data["icount"]

    # -- Lifecycle --

    def close(self) -> None:
        self._touch()
        self.hooks.clear()
        self.snapshots.clear()
        self.trace.clear()
        self._regions.clear()
        # The Rust VM is freed when self.vm is garbage-collected.
        self.vm = None
