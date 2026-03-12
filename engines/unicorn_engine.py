"""Unicorn CPU emulator engine wrapper."""

from typing import Any, Callable

from unicorn import (
    Uc, UcError,
    UC_ARCH_X86, UC_ARCH_ARM, UC_ARCH_ARM64, UC_ARCH_MIPS,
    UC_MODE_32, UC_MODE_64, UC_MODE_ARM, UC_MODE_THUMB,
    UC_MODE_MIPS32, UC_MODE_MIPS64, UC_MODE_BIG_ENDIAN, UC_MODE_LITTLE_ENDIAN,
    UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
    UC_ERR_READ_UNMAPPED, UC_ERR_WRITE_UNMAPPED, UC_ERR_FETCH_UNMAPPED,
    UC_ERR_INSN_INVALID, UC_ERR_MAP, UC_ERR_NOMEM,
    UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
)
from unicorn import x86_const as ux86
from unicorn import arm_const as uarm
from unicorn import arm64_const as uarm64
from unicorn import mips_const as umips
from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_MIPS
from capstone import CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_THUMB
from capstone import CS_MODE_MIPS32, CS_MODE_MIPS64, CS_MODE_BIG_ENDIAN, CS_MODE_LITTLE_ENDIAN

from .base import BaseEngine, HookInfo, SnapshotInfo, TraceEntry

import time

# Architecture mapping: name -> (uc_arch, uc_mode)
ARCH_MAP: dict[str, tuple[int, int]] = {
    "x86":      (UC_ARCH_X86,   UC_MODE_32),
    "x86_64":   (UC_ARCH_X86,   UC_MODE_64),
    "arm":      (UC_ARCH_ARM,   UC_MODE_ARM),
    "arm_thumb": (UC_ARCH_ARM,  UC_MODE_THUMB),
    "arm64":    (UC_ARCH_ARM64, UC_MODE_ARM),
    "mips":     (UC_ARCH_MIPS,  UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN),
    "mips_le":  (UC_ARCH_MIPS,  UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN),
    "mips64":   (UC_ARCH_MIPS,  UC_MODE_MIPS64 + UC_MODE_BIG_ENDIAN),
}

# Capstone arch/mode mapping (parallel to ARCH_MAP)
CS_ARCH_MAP: dict[str, tuple[int, int]] = {
    "x86":      (CS_ARCH_X86,   CS_MODE_32),
    "x86_64":   (CS_ARCH_X86,   CS_MODE_64),
    "arm":      (CS_ARCH_ARM,   CS_MODE_ARM),
    "arm_thumb": (CS_ARCH_ARM,  CS_MODE_THUMB),
    "arm64":    (CS_ARCH_ARM64, CS_MODE_ARM),
    "mips":     (CS_ARCH_MIPS,  CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN),
    "mips_le":  (CS_ARCH_MIPS,  CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN),
    "mips64":   (CS_ARCH_MIPS,  CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN),
}

# Register maps per architecture: name -> unicorn constant
_X86_REGS: dict[str, int] = {
    "eax": ux86.UC_X86_REG_EAX, "ebx": ux86.UC_X86_REG_EBX, "ecx": ux86.UC_X86_REG_ECX,
    "edx": ux86.UC_X86_REG_EDX, "esi": ux86.UC_X86_REG_ESI, "edi": ux86.UC_X86_REG_EDI,
    "ebp": ux86.UC_X86_REG_EBP, "esp": ux86.UC_X86_REG_ESP, "eip": ux86.UC_X86_REG_EIP,
    "eflags": ux86.UC_X86_REG_EFLAGS,
}

_X86_64_REGS: dict[str, int] = {
    "rax": ux86.UC_X86_REG_RAX, "rbx": ux86.UC_X86_REG_RBX, "rcx": ux86.UC_X86_REG_RCX,
    "rdx": ux86.UC_X86_REG_RDX, "rsi": ux86.UC_X86_REG_RSI, "rdi": ux86.UC_X86_REG_RDI,
    "rbp": ux86.UC_X86_REG_RBP, "rsp": ux86.UC_X86_REG_RSP, "rip": ux86.UC_X86_REG_RIP,
    "r8": ux86.UC_X86_REG_R8, "r9": ux86.UC_X86_REG_R9, "r10": ux86.UC_X86_REG_R10,
    "r11": ux86.UC_X86_REG_R11, "r12": ux86.UC_X86_REG_R12, "r13": ux86.UC_X86_REG_R13,
    "r14": ux86.UC_X86_REG_R14, "r15": ux86.UC_X86_REG_R15, "rflags": ux86.UC_X86_REG_EFLAGS,
}

_ARM_REGS: dict[str, int] = {
    "r0": uarm.UC_ARM_REG_R0, "r1": uarm.UC_ARM_REG_R1, "r2": uarm.UC_ARM_REG_R2,
    "r3": uarm.UC_ARM_REG_R3, "r4": uarm.UC_ARM_REG_R4, "r5": uarm.UC_ARM_REG_R5,
    "r6": uarm.UC_ARM_REG_R6, "r7": uarm.UC_ARM_REG_R7, "r8": uarm.UC_ARM_REG_R8,
    "r9": uarm.UC_ARM_REG_R9, "r10": uarm.UC_ARM_REG_R10, "r11": uarm.UC_ARM_REG_R11,
    "r12": uarm.UC_ARM_REG_R12, "sp": uarm.UC_ARM_REG_SP, "lr": uarm.UC_ARM_REG_LR,
    "pc": uarm.UC_ARM_REG_PC, "cpsr": uarm.UC_ARM_REG_CPSR,
}

_ARM64_REGS: dict[str, int] = {
    **{f"x{i}": getattr(uarm64, f"UC_ARM64_REG_X{i}") for i in range(31)},
    "sp": uarm64.UC_ARM64_REG_SP, "pc": uarm64.UC_ARM64_REG_PC, "lr": uarm64.UC_ARM64_REG_LR,
}

_MIPS_REGS: dict[str, int] = {
    "zero": umips.UC_MIPS_REG_ZERO, "at": umips.UC_MIPS_REG_AT,
    "v0": umips.UC_MIPS_REG_V0, "v1": umips.UC_MIPS_REG_V1,
    "a0": umips.UC_MIPS_REG_A0, "a1": umips.UC_MIPS_REG_A1, "a2": umips.UC_MIPS_REG_A2, "a3": umips.UC_MIPS_REG_A3,
    "t0": umips.UC_MIPS_REG_T0, "t1": umips.UC_MIPS_REG_T1, "t2": umips.UC_MIPS_REG_T2, "t3": umips.UC_MIPS_REG_T3,
    "t4": umips.UC_MIPS_REG_T4, "t5": umips.UC_MIPS_REG_T5, "t6": umips.UC_MIPS_REG_T6, "t7": umips.UC_MIPS_REG_T7,
    "s0": umips.UC_MIPS_REG_S0, "s1": umips.UC_MIPS_REG_S1, "s2": umips.UC_MIPS_REG_S2, "s3": umips.UC_MIPS_REG_S3,
    "s4": umips.UC_MIPS_REG_S4, "s5": umips.UC_MIPS_REG_S5, "s6": umips.UC_MIPS_REG_S6, "s7": umips.UC_MIPS_REG_S7,
    "t8": umips.UC_MIPS_REG_T8, "t9": umips.UC_MIPS_REG_T9,
    "gp": umips.UC_MIPS_REG_GP, "sp": umips.UC_MIPS_REG_SP,
    "fp": umips.UC_MIPS_REG_FP, "ra": umips.UC_MIPS_REG_RA,
    "pc": umips.UC_MIPS_REG_PC,
}

REG_MAPS: dict[str, dict[str, int]] = {
    "x86": _X86_REGS,
    "x86_64": _X86_64_REGS,
    "arm": _ARM_REGS,
    "arm_thumb": _ARM_REGS,
    "arm64": _ARM64_REGS,
    "mips": _MIPS_REGS,
    "mips_le": _MIPS_REGS,
    "mips64": _MIPS_REGS,
}

# Default memory layout
CODE_BASE = 0x1000000
CODE_SIZE = 4 * 1024 * 1024      # 4 MB
STACK_BASE = 0x7000000
STACK_SIZE = 1 * 1024 * 1024     # 1 MB
STACK_TOP = STACK_BASE + STACK_SIZE  # 0x7100000
HEAP_BASE = 0x8000000
HEAP_SIZE = 2 * 1024 * 1024      # 2 MB
DATA_BASE = 0x2000000
DATA_SIZE = 2 * 1024 * 1024      # 2 MB - for user data (strings, buffers)

# Stack pointer register per architecture
SP_REG: dict[str, str] = {
    "x86": "esp",
    "x86_64": "rsp",
    "arm": "sp",
    "arm_thumb": "sp",
    "arm64": "sp",
    "mips": "sp",
    "mips_le": "sp",
    "mips64": "sp",
}

# Program counter register per architecture
_PC_REG: dict[str, str] = {
    "x86": "eip",
    "x86_64": "rip",
    "arm": "pc",
    "arm_thumb": "pc",
    "arm64": "pc",
    "mips": "pc",
    "mips_le": "pc",
    "mips64": "pc",
}

# Unicorn error code descriptions
UC_ERR_MESSAGES: dict[int, str] = {
    UC_ERR_READ_UNMAPPED: "Read from unmapped memory",
    UC_ERR_WRITE_UNMAPPED: "Write to unmapped memory",
    UC_ERR_FETCH_UNMAPPED: "Fetch from unmapped memory (code at unmapped address)",
    UC_ERR_INSN_INVALID: "Invalid instruction encountered",
    UC_ERR_MAP: "Memory mapping error (overlapping or invalid region)",
    UC_ERR_NOMEM: "Out of memory",
}


def _translate_uc_error(err: UcError) -> str:
    """Convert UcError to a human-readable message."""
    errno = err.errno
    desc = UC_ERR_MESSAGES.get(errno, "")
    if desc:
        return f"Unicorn error {errno}: {desc}"
    return f"Unicorn error {errno}: {err}"


class UnicornEngine(BaseEngine):
    """Unicorn CPU emulator engine for code snippet and shellcode analysis."""

    def __init__(self, arch: str, **kwargs: Any):
        if arch not in ARCH_MAP:
            raise ValueError(f"Unsupported architecture '{arch}'. Supported: {list(ARCH_MAP.keys())}")

        super().__init__(arch, **kwargs)
        self.engine_type = "unicorn"

        uc_arch, uc_mode = ARCH_MAP[arch]
        self.uc = Uc(uc_arch, uc_mode)

        cs_arch, cs_mode = CS_ARCH_MAP[arch]
        self.cs = Cs(cs_arch, cs_mode)

        self._reg_map: dict[str, int] = REG_MAPS[arch]
        self._code_hook_handle: int | None = None
        self._mem_hook_handle: int | None = None

        # Set up default memory layout
        self.uc.mem_map(CODE_BASE, CODE_SIZE, UC_PROT_ALL)
        self.uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.uc.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)

        # Stack overflow detection
        self.stack_overflow_detected: bool = False
        self._insn_counter: int = 0
        self._sp_check_interval: int = 100  # check SP every N instructions

        # Cache SP register name to avoid repeated dict lookup in hot path
        self._sp_reg_name: str = SP_REG[arch]

        # Set stack pointer to top of stack
        self.register_write(self._sp_reg_name, STACK_TOP)

    # -- Internal hooks --

    def _hook_code_cb(self, uc: Uc, address: int, size: int, user_data: Any) -> None:
        """Code hook callback - traces instructions and dispatches address hooks."""
        # Instruction tracing
        if self.tracing_enabled:
            # mem_read() returns a bytearray; pass it directly — no bytes() copy needed.
            # disasm_lite() yields (addr, size, mnemonic, op_str) tuples with far less
            # allocation overhead than full CsInsn objects from disasm().
            code_bytes = uc.mem_read(address, size)
            disasm = ""
            for _addr, _sz, mnemonic, op_str in self.cs.disasm_lite(code_bytes, address):
                disasm = f"{mnemonic} {op_str}".strip()
                break
            if not disasm:
                disasm = f"db {code_bytes.hex()}"
            self._append_trace(TraceEntry(
                address=address,
                instruction=disasm,
                size=size,
                trace_type="instruction",
            ))

        # Stack bounds check (every N instructions to limit overhead)
        self._insn_counter += 1
        if self._insn_counter % self._sp_check_interval == 0:
            sp = self.register_read(self._sp_reg_name)
            if sp < STACK_BASE or sp > STACK_TOP:
                self.stack_overflow_detected = True
                self._append_trace(TraceEntry(
                    address=address,
                    instruction=f"STACK OVERFLOW: SP=0x{sp:x} outside [{STACK_BASE:#x}-{STACK_TOP:#x}]",
                    trace_type="error",
                    name="stack_overflow",
                ))
                uc.emu_stop()
                return

        # O(1) address hook dispatch via pre-computed dict.
        # _handle is always callable when set (guaranteed by hook_address()), so
        # a simple None-check is sufficient — no callable() overhead needed.
        hook_info = self._addr_hooks.get(address)
        if hook_info is not None and hook_info._handle is not None:
            try:
                hook_info._handle(self, address)
            except Exception as e:
                self._append_trace(TraceEntry(
                    address=address,
                    instruction=f"Hook exception: {e}",
                    trace_type="error",
                    name="hook_exception",
                ))

    def _hook_mem_cb(self, uc: Uc, access: int, address: int, size: int, value: int, user_data: Any) -> None:
        """Memory access hook callback."""
        if not self.tracing_enabled:
            return
        mem_type = "read" if access == 16 else "write"  # UC_MEM_READ=16, UC_MEM_WRITE=17
        self._append_trace(TraceEntry(
            address=address,
            instruction=f"mem_{mem_type} {size} bytes" + (f" value=0x{value:x}" if mem_type == "write" else ""),
            size=size,
            trace_type="memory",
            name=mem_type,
        ))

    def _ensure_hooks_installed(self) -> None:
        """Install the global code and memory hooks if not already installed."""
        if self._code_hook_handle is None:
            self._code_hook_handle = self.uc.hook_add(UC_HOOK_CODE, self._hook_code_cb)
        if self._mem_hook_handle is None:
            self._mem_hook_handle = self.uc.hook_add(
                UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                self._hook_mem_cb,
            )

    # -- Execution --

    def start(self, begin: int, end: int, timeout_ms: int = 10000) -> dict[str, Any]:
        self._touch()
        self._ensure_hooks_installed()
        self._step_limit = 0

        self.stack_overflow_detected = False
        self._insn_counter = 0

        start_time = time.time()
        error_msg = ""
        try:
            # Unicorn timeout is in microseconds
            self.uc.emu_start(begin, end, timeout=timeout_ms * 1000)
        except UcError as e:
            error_msg = _translate_uc_error(e)

        elapsed = time.time() - start_time
        status = "error" if error_msg else ("stack_overflow" if self.stack_overflow_detected else "ok")
        result: dict[str, Any] = {
            "status": status,
            "elapsed_ms": round(elapsed * 1000, 2),
            "instructions_traced": len(self.trace),
        }
        if error_msg:
            result["error"] = error_msg
        if self.stack_overflow_detected:
            sp = self.register_read(self._sp_reg_name)
            result["error"] = f"Stack overflow detected: SP=0x{sp:x} outside stack region [{STACK_BASE:#x}-{STACK_TOP:#x}]"
            result["stack_overflow"] = True
        return result

    def step(self, count: int = 1) -> list[TraceEntry]:
        self._touch()
        self._ensure_hooks_installed()

        was_tracing = self.tracing_enabled
        self.tracing_enabled = True
        trace_start = len(self.trace)

        # Read current PC
        pc_name = _PC_REG[self.arch]
        pc = self.register_read(pc_name)

        try:
            # Use Unicorn's native count parameter for accurate stepping
            self.uc.emu_start(pc, CODE_BASE + CODE_SIZE, timeout=5_000_000, count=count)
        except UcError:
            pass

        self.tracing_enabled = was_tracing
        return list(self.trace)[trace_start:]

    def stop(self) -> None:
        self._touch()
        try:
            self.uc.emu_stop()
        except UcError:
            pass

    # -- Memory --

    def memory_read(self, address: int, size: int) -> bytes:
        try:
            return bytes(self.uc.mem_read(address, size))
        except UcError as e:
            raise RuntimeError(_translate_uc_error(e)) from e

    def memory_write(self, address: int, data: bytes) -> None:
        try:
            self.uc.mem_write(address, data)
        except UcError as e:
            raise RuntimeError(_translate_uc_error(e)) from e

    def memory_map(self, address: int, size: int, perms: int = 7) -> None:
        # Convert rwx bitmask (7=rwx) to Unicorn protection flags
        uc_perms = 0
        if perms & 4:
            uc_perms |= UC_PROT_READ
        if perms & 2:
            uc_perms |= UC_PROT_WRITE
        if perms & 1:
            uc_perms |= UC_PROT_EXEC
        if uc_perms == 0:
            uc_perms = UC_PROT_ALL
        try:
            self.uc.mem_map(address, size, uc_perms)
        except UcError as e:
            raise RuntimeError(_translate_uc_error(e)) from e

    def memory_search(self, pattern: bytes) -> list[int]:
        results: list[int] = []
        for begin, end, _perms in self.uc.mem_regions():
            size = end - begin + 1
            try:
                data = bytes(self.uc.mem_read(begin, size))
            except UcError:
                continue
            offset = 0
            while True:
                idx = data.find(pattern, offset)
                if idx == -1:
                    break
                results.append(begin + idx)
                offset = idx + 1
        return results

    # -- Registers --

    def register_read(self, name: str) -> int:
        name_lower = name.lower()
        uc_const = self._reg_map.get(name_lower)
        if uc_const is None:
            raise ValueError(f"Unknown register '{name}' for arch '{self.arch}'. Available: {list(self._reg_map.keys())}")
        try:
            return self.uc.reg_read(uc_const)
        except UcError as e:
            raise RuntimeError(_translate_uc_error(e)) from e

    def register_write(self, name: str, value: int) -> None:
        name_lower = name.lower()
        uc_const = self._reg_map.get(name_lower)
        if uc_const is None:
            raise ValueError(f"Unknown register '{name}' for arch '{self.arch}'. Available: {list(self._reg_map.keys())}")
        try:
            self.uc.reg_write(uc_const, value)
        except UcError as e:
            raise RuntimeError(_translate_uc_error(e)) from e

    def registers_read_all(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for name, uc_const in self._reg_map.items():
            try:
                result[name] = self.uc.reg_read(uc_const)
            except UcError:
                pass
        return result

    # -- Hooks --

    def hook_address(self, address: int, callback: Callable | None = None) -> str:
        self._touch()
        self._ensure_hooks_installed()
        hook_id = self._gen_id("hook-")
        info = HookInfo(
            hook_id=hook_id,
            hook_type="address",
            target=f"0x{address:x}",
            description=f"Address hook at 0x{address:x}",
            _handle=callback,
        )
        self.hooks[hook_id] = info
        # Update O(1) lookup dict
        self._addr_hooks[address] = info
        return hook_id

    def hook_remove(self, hook_id: str) -> bool:
        self._touch()
        info = self.hooks.get(hook_id)
        if info is None:
            return False
        # Remove from O(1) lookup if it's an address hook
        if info.hook_type == "address":
            addr = int(info.target, 16)
            self._addr_hooks.pop(addr, None)
        del self.hooks[hook_id]
        return True

    # -- Snapshots --

    def snapshot_save(self, label: str = "") -> str:
        self._touch()
        ctx = self.uc.context_save()
        snap_id = self._gen_id("snap-")
        self.snapshots[snap_id] = SnapshotInfo(
            snapshot_id=snap_id,
            label=label or f"Snapshot {len(self.snapshots) + 1}",
            created_at=time.time(),
            _data=ctx,
        )
        return snap_id

    def snapshot_restore(self, snapshot_id: str) -> None:
        self._touch()
        snap = self.snapshots.get(snapshot_id)
        if snap is None:
            raise KeyError(f"Snapshot '{snapshot_id}' not found. Available: {list(self.snapshots.keys())}")
        self.uc.context_restore(snap._data)

    # -- Lifecycle --

    def close(self) -> None:
        """Clean up Unicorn resources."""
        self._touch()
        # Remove hooks
        if self._code_hook_handle is not None:
            try:
                self.uc.hook_del(self._code_hook_handle)
            except UcError:
                pass
            self._code_hook_handle = None
        if self._mem_hook_handle is not None:
            try:
                self.uc.hook_del(self._mem_hook_handle)
            except UcError:
                pass
            self._mem_hook_handle = None
        self.hooks.clear()
        self.snapshots.clear()
        self.trace.clear()
