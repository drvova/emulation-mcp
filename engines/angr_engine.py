"""angr emulation engine wrapper.

angr (https://angr.io) is a symbolic execution framework.  Where Unicorn,
Icicle and Qiling run one concrete path, angr can run a register or memory
region as a *symbolic* value and explore every path, then solve for the inputs
that drive execution to a chosen address.  That is the headline capability this
engine adds to the server; it also supports the ordinary concrete workflow
(load code, step, read registers/memory) so it slots into the shared interface.

The wrapper keeps a single "current" angr `SimState` (``self.state``) that the
concrete BaseEngine methods operate on, plus bookkeeping for symbolic variables
so the symbolic tools can solve for them after an exploration.
"""

import logging
import time
from typing import Any, Callable

import angr
from angr import claripy

from .base import (
    BaseEngine, HookInfo, SnapshotInfo, TraceEntry,
    CODE_BASE, CODE_SIZE, STACK_BASE, STACK_SIZE, STACK_TOP,
    HEAP_BASE, HEAP_SIZE, DATA_BASE, DATA_SIZE,
)

# angr is very chatty at INFO/WARNING; keep it quiet unless debugging.
for _name in ("angr", "cle", "pyvex", "claripy"):
    logging.getLogger(_name).setLevel(logging.ERROR)


# Architecture string -> angr/archinfo architecture id.  Keys mirror the other
# engines; the bool is whether the arch runs in Thumb mode.
ARCH_MAP: dict[str, tuple[str, bool]] = {
    "x86":       ("x86", False),
    "x86_64":    ("amd64", False),
    "arm":       ("armel", False),
    "arm_thumb": ("armel", True),
    "arm64":     ("aarch64", False),
    "mips":      ("mips32", False),
    "mips_le":   ("mipsel", False),
    "mips64":    ("mips64", False),
    "ppc":       ("ppc32", False),
    "ppc64":     ("ppc64", False),
    "riscv64":   ("riscv64", False),
}

# Common registers per architecture for registers_read_all.
COMMON_REGS: dict[str, list[str]] = {
    "x86":       ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"],
    "x86_64":    ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
                  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"],
    "arm":       [f"r{i}" for i in range(13)] + ["sp", "lr", "pc"],
    "arm_thumb": [f"r{i}" for i in range(13)] + ["sp", "lr", "pc"],
    "arm64":     [f"x{i}" for i in range(31)] + ["sp", "pc"],
    "mips":      ["v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3",
                  "s0", "s1", "s2", "s3", "gp", "sp", "fp", "ra", "pc"],
    "mips_le":   ["v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3",
                  "s0", "s1", "s2", "s3", "gp", "sp", "fp", "ra", "pc"],
    "mips64":    ["v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3",
                  "s0", "s1", "s2", "s3", "gp", "sp", "fp", "ra", "pc"],
    "ppc":       [f"r{i}" for i in range(32)] + ["pc", "lr", "ctr"],
    "ppc64":     [f"r{i}" for i in range(32)] + ["pc", "lr", "ctr"],
    "riscv64":   ["ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1"]
                 + [f"a{i}" for i in range(8)] + ["pc"],
}

# Bound exploration so a symbolic run can never hang the server.
MAX_EXPLORE_STATES = 2000
PAGE_SIZE = 0x1000


class _ReturnValueProcedure(angr.SimProcedure):
    """A SimProcedure that returns immediately with a fixed concrete value.

    The value is carried on a ``RET_VALUE`` class attribute so one subclass is
    minted per hooked function (see AngrEngine.hook_function).
    """
    RET_VALUE = 0

    def run(self):  # noqa: D401 - angr calls this with the guest's args
        return claripy.BVV(self.RET_VALUE, self.state.arch.bits)


class AngrEngine(BaseEngine):
    """angr symbolic/concrete execution engine."""

    CAPABILITIES = frozenset({
        "shellcode", "binary_loading", "address_hooks",
        "instruction_trace", "snapshots", "symbolic",
        "cfg", "function_call", "decompiler", "constraints",
        "inspection", "sim_procedures",
    })

    # state.inspect events we accept for add_inspect_hook.
    INSPECT_EVENTS = frozenset({
        "mem_read", "mem_write", "reg_read", "reg_write", "address_concretization",
        "instruction", "statement", "expr", "call", "return", "fork",
        "symbolic_variable", "constraints", "exit", "syscall", "irsb", "dirty",
    })
    SUPPORTED_ARCHS = tuple(ARCH_MAP)

    def __init__(
        self,
        arch: str = "",
        binary_path: str = "",
        load_address: int = CODE_BASE,
        **kwargs: Any,
    ):
        self.binary_path = binary_path
        self._load_address = load_address
        self._thumb = False
        self._regions: list[tuple[int, int]] = []
        self._symvars: dict[str, Any] = {}
        # In shellcode mode, [_code_lo, _code_hi) is backed in the loader image;
        # writes here are mirrored there so angr's block lifter sees the code.
        self._code_lo = 0
        self._code_hi = 0
        # Stash of states from the most recent explore(), for solving.
        self._found_states: list[Any] = []

        if binary_path:
            arch = self._init_binary(binary_path, arch)
        else:
            if arch not in ARCH_MAP:
                raise ValueError(
                    f"Unsupported architecture '{arch}'. Supported: {list(ARCH_MAP.keys())}"
                )
            arch = self._init_shellcode(arch)

        super().__init__(arch, **kwargs)
        self.engine_type = "angr"

    # -- Construction helpers --

    @property
    def _base_options(self) -> set:
        return {
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }

    def _init_shellcode(self, arch: str) -> str:
        arch_id, thumb = ARCH_MAP[arch]
        self._thumb = thumb
        self._code_lo = self._load_address
        self._code_hi = self._load_address + CODE_SIZE
        try:
            # Back the whole CODE window in the loader image.  angr's block
            # lifter reads instruction bytes from the loader, not from state
            # memory, so code written via memory_write is mirrored into this
            # backer (see memory_write) to be executable.
            self.proj = angr.load_shellcode(
                bytes(CODE_SIZE), arch=arch_id, load_address=self._load_address, thumb=thumb,
            )
        except Exception as e:
            raise RuntimeError(f"Failed to create angr project for arch '{arch}': {e}") from e
        self.state = self.proj.factory.blank_state(
            addr=self._pc_value(self._load_address), add_options=self._base_options,
        )
        # Map a working layout mirroring the other engines.
        for base, size in ((STACK_BASE, STACK_SIZE), (HEAP_BASE, HEAP_SIZE), (DATA_BASE, DATA_SIZE)):
            self.state.memory.map_region(base, size, 7, init_zero=True)
            self._regions.append((base, size))
        self._regions.append((self._load_address, CODE_SIZE))
        self.state.regs.sp = STACK_TOP
        return arch

    def _init_binary(self, binary_path: str, arch: str) -> str:
        try:
            self.proj = angr.Project(binary_path, auto_load_libs=False)
        except Exception as e:
            raise RuntimeError(f"Failed to load binary '{binary_path}' with angr: {e}") from e
        self.state = self.proj.factory.entry_state(add_options=self._base_options)
        for obj in self.proj.loader.all_objects:
            self._regions.append((obj.min_addr, obj.max_addr - obj.min_addr + 1))
        # Derive our arch string from the project if the caller did not pass one.
        if arch and arch in ARCH_MAP:
            self._thumb = ARCH_MAP[arch][1]
            return arch
        name = self.proj.arch.name.lower()
        reverse = {
            "amd64": "x86_64", "x86": "x86", "armel": "arm", "armhf": "arm",
            "aarch64": "arm64", "mips32": "mips", "mipsel": "mips_le",
            "mips64": "mips64", "ppc32": "ppc", "ppc64": "ppc64", "riscv64": "riscv64",
        }
        return reverse.get(name, name)

    def _pc_value(self, addr: int) -> int:
        """Apply the Thumb bit to an address when running in Thumb mode."""
        return (addr | 1) if self._thumb else addr

    def _clean_addr(self, addr: int) -> int:
        return addr & ~1 if self._thumb else addr

    # -- Execution --

    def start(self, begin: int = 0, end: int = 0, timeout_ms: int = 10000) -> dict[str, Any]:
        self._touch()
        if begin:
            self.state.regs.pc = self._pc_value(begin)
        start_pc = self.state.solver.eval(self.state.regs.pc)

        simgr = self.proj.factory.simulation_manager(self.state)
        deadline = time.time() + max(timeout_ms, 1) / 1000.0
        target = self._clean_addr(end) if end else None
        # angr executes a basic block at a time; to stop on the exact `end`
        # address we break blocks there with an extra stop point.
        stop_points = {target} if target is not None else None
        start_time = time.time()
        reached = False
        status = "stopped"
        error = ""

        try:
            while simgr.active:
                if time.time() > deadline:
                    status = "timeout"
                    error = f"Wall-clock timeout ({timeout_ms} ms)"
                    break
                if target is not None and any(self._clean_addr(s.addr) == target for s in simgr.active):
                    reached = True
                    break
                if len(simgr.active) + len(simgr.stashes.get("deferred", [])) > MAX_EXPLORE_STATES:
                    status = "state_explosion"
                    error = f"Exceeded {MAX_EXPLORE_STATES} states"
                    break
                if self.tracing_enabled:
                    for s in simgr.active:
                        self._trace_state(s, limit_addr=target)
                simgr.step(extra_stop_points=stop_points)
            else:
                status = "no_active_states"
        except Exception as e:
            status = "error"
            error = f"{type(e).__name__}: {e}"

        # Pick the state to carry forward: one that reached the target if asked,
        # else the first active/deadended state available.
        chosen = None
        if target is not None:
            for s in simgr.active:
                if self._clean_addr(s.addr) == target:
                    chosen = s
                    break
        if chosen is None and simgr.active:
            chosen = simgr.active[0]
        if chosen is None:
            for stash in ("deadended", "found", "deferred"):
                if simgr.stashes.get(stash):
                    chosen = simgr.stashes[stash][0]
                    break
        if chosen is not None:
            self.state = chosen

        if reached:
            status = "ok"
        elapsed = time.time() - start_time
        result: dict[str, Any] = {
            "status": status,
            "elapsed_ms": round(elapsed * 1000, 2),
            "start": f"0x{start_pc:x}",
            "pc": f"0x{self.state.solver.eval(self.state.regs.pc):x}",
            "active_states": len(simgr.active),
            "deadended_states": len(simgr.stashes.get("deadended", [])),
            "instructions_traced": len(self.trace),
        }
        if error:
            result["error"] = error
        return result

    def _trace_state(self, state: Any, limit_addr: int | None = None) -> None:
        try:
            block = self.proj.factory.block(self._clean_addr(state.addr))
        except Exception:
            return
        for insn in block.capstone.insns:
            if limit_addr is not None and insn.address >= limit_addr:
                break
            self._append_trace(TraceEntry(
                address=insn.address,
                instruction=f"{insn.mnemonic} {insn.op_str}".strip(),
                size=insn.size,
                trace_type="instruction",
            ))

    def step(self, count: int = 1) -> list[TraceEntry]:
        self._touch()
        # Force tracing on for the duration so the stepped instructions are
        # always returned, matching the other engines' step() behaviour.
        was_tracing = self.tracing_enabled
        self.tracing_enabled = True
        trace_start = len(self.trace)
        try:
            for _ in range(max(count, 1)):
                self._trace_single_instruction(self.state)
                self._dispatch_hooks(self.state.addr)
                try:
                    succ = self.proj.factory.successors(self.state, num_inst=1)
                except Exception:
                    break
                flat = succ.flat_successors or succ.unsat_successors
                if not flat:
                    break
                self.state = flat[0]
        finally:
            self.tracing_enabled = was_tracing
        return list(self.trace)[trace_start:]

    def _trace_single_instruction(self, state: Any) -> None:
        try:
            block = self.proj.factory.block(self._clean_addr(state.addr), num_inst=1)
            for insn in block.capstone.insns:
                self._append_trace(TraceEntry(
                    address=insn.address,
                    instruction=f"{insn.mnemonic} {insn.op_str}".strip(),
                    size=insn.size,
                    trace_type="instruction",
                ))
                return
        except Exception:
            pass

    def _dispatch_hooks(self, address: int) -> None:
        info = self._addr_hooks.get(self._clean_addr(address))
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

    def stop(self) -> None:
        # Execution in start()/explore() is bounded by wall-clock and state caps.
        self._touch()

    # -- Memory --

    def memory_read(self, address: int, size: int) -> bytes:
        try:
            val = self.state.memory.load(address, size)
            return self.state.solver.eval(val, cast_to=bytes)
        except Exception as e:
            raise RuntimeError(f"Memory read failed at 0x{address:x} (size={size}): {e}") from e

    def memory_write(self, address: int, data: bytes) -> None:
        data = bytes(data)
        try:
            self.state.memory.store(address, data)
        except Exception as e:
            raise RuntimeError(f"Memory write failed at 0x{address:x}: {e}") from e
        # Mirror writes that land in the loader-backed code window so angr's
        # block lifter executes the freshly written code.
        lo = max(address, self._code_lo)
        hi = min(address + len(data), self._code_hi)
        if lo < hi:
            try:
                self.proj.loader.memory.store(lo, data[lo - address:hi - address])
            except Exception:
                pass

    def memory_map(self, address: int, size: int, perms: int = 7) -> None:
        try:
            self.state.memory.map_region(address, size, perms, init_zero=True)
        except Exception as e:
            raise RuntimeError(f"Memory map failed at 0x{address:x} (size=0x{size:x}): {e}") from e
        self._regions.append((address, size))

    def memory_search(self, pattern: bytes) -> list[int]:
        results: list[int] = []
        for base, size in self._regions:
            off = base
            region_end = base + size
            while off < region_end:
                chunk_size = min(PAGE_SIZE, region_end - off)
                try:
                    mv = self.state.memory.concrete_load(off, chunk_size)
                except Exception:
                    off += chunk_size
                    continue
                data = bytes(mv)
                idx = 0
                while True:
                    found = data.find(pattern, idx)
                    if found == -1:
                        break
                    results.append(off + found)
                    idx = found + 1
                off += chunk_size
        return results

    # -- Registers --

    def register_read(self, name: str) -> int:
        try:
            reg = getattr(self.state.regs, name.lower())
        except AttributeError as e:
            raise ValueError(f"Unknown register '{name}' for arch '{self.arch}'") from e
        return self.state.solver.eval(reg)

    def register_write(self, name: str, value: int) -> None:
        try:
            setattr(self.state.regs, name.lower(), value)
        except AttributeError as e:
            raise ValueError(f"Unknown register '{name}' for arch '{self.arch}'") from e

    def registers_read_all(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for name in COMMON_REGS.get(self.arch, []):
            try:
                result[name] = self.state.solver.eval(getattr(self.state.regs, name))
            except Exception:
                pass
        return result

    def register_is_symbolic(self, name: str) -> bool:
        try:
            return bool(getattr(self.state.regs, name.lower()).symbolic)
        except AttributeError:
            return False

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
        self._addr_hooks[self._clean_addr(address)] = info

        # Also register a project hook so address hooks fire during a full
        # start()/explore() run, not only while single-stepping.
        engine = self

        def _proj_hook(state: Any) -> None:
            engine._dispatch_hooks(state.addr)

        try:
            self.proj.hook(self._clean_addr(address), _proj_hook, length=0)
            info._handle_proj = True  # type: ignore[attr-defined]
        except Exception:
            pass
        return hook_id

    def add_inspect_hook(self, event: str, callback: Callable, when: str = "before") -> str:
        """Register a callback on a fine-grained angr event (state.inspect).

        event: one of INSPECT_EVENTS — "mem_read", "mem_write", "reg_read",
          "reg_write", "instruction", "call", "return", "symbolic_variable", ...
        when: "before" or "after" the event.
        The callback receives the angr `SimState`; read the event details from
        `state.inspect.attrs` (e.g. `.mem_write_address`, `.mem_write_expr`).
        It is observe-only and must not re-enter this engine. Breakpoints are
        copied into child states, so they fire throughout start()/explore().
        Install before running; remove with hook_remove().
        """
        self._touch()
        if event not in self.INSPECT_EVENTS:
            raise ValueError(
                f"Unknown inspect event '{event}'. Known: {sorted(self.INSPECT_EVENTS)}"
            )
        when_const = angr.BP_AFTER if str(when).lower() == "after" else angr.BP_BEFORE
        bp = self.state.inspect.b(event, when=when_const, action=callback)
        hook_id = self._gen_id("insp-")
        info = HookInfo(
            hook_id=hook_id,
            hook_type="inspect",
            target=f"{event}:{when}",
            description=f"Inspect {event} ({when})",
            _handle=(event, bp),
        )
        self.hooks[hook_id] = info
        return hook_id

    def hook_function(self, address: int, return_value: int | None = None) -> str:
        """Replace the function at `address` with a stub that returns at once.

        return_value: force this concrete return value; None returns an
        unconstrained symbolic value (ReturnUnconstrained). Useful to stub out
        library/checksum functions during symbolic exploration. Remove with
        hook_remove().
        """
        self._touch()
        clean = self._clean_addr(address)
        if return_value is None:
            proc = angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]()
            desc = f"hook_function 0x{address:x} -> unconstrained"
        else:
            proc_cls = type("ReturnValue", (_ReturnValueProcedure,),
                            {"RET_VALUE": int(return_value)})
            proc = proc_cls()
            desc = f"hook_function 0x{address:x} -> {return_value:#x}"
        try:
            self.proj.hook(clean, proc, replace=True)
        except Exception as e:
            raise RuntimeError(f"Failed to hook 0x{address:x}: {e}") from e
        hook_id = self._gen_id("simproc-")
        self.hooks[hook_id] = HookInfo(
            hook_id=hook_id, hook_type="sim_procedure",
            target=f"0x{address:x}", description=desc, _handle=clean,
        )
        return hook_id

    def hook_skip(self, address: int, length: int = 0) -> str:
        """No-op `length` bytes at `address` (skip an instruction/sequence).

        angr jumps over the hooked bytes without executing them. length=0 lets
        the stub run in place of the block. Remove with hook_remove().
        """
        self._touch()
        clean = self._clean_addr(address)
        try:
            self.proj.hook(clean, angr.SIM_PROCEDURES["stubs"]["Nop"](),
                           length=max(length, 0), replace=True)
        except Exception as e:
            raise RuntimeError(f"Failed to hook-skip 0x{address:x}: {e}") from e
        hook_id = self._gen_id("skip-")
        self.hooks[hook_id] = HookInfo(
            hook_id=hook_id, hook_type="skip",
            target=f"0x{address:x}", description=f"skip 0x{address:x} (+{length})",
            _handle=clean,
        )
        return hook_id

    def hook_remove(self, hook_id: str) -> bool:
        self._touch()
        info = self.hooks.get(hook_id)
        if info is None:
            return False
        if info.hook_type == "address":
            addr = int(info.target, 16)
            self._addr_hooks.pop(self._clean_addr(addr), None)
            try:
                if self.proj.is_hooked(self._clean_addr(addr)):
                    self.proj.unhook(self._clean_addr(addr))
            except Exception:
                pass
        elif info.hook_type == "inspect" and info._handle:
            event, bp = info._handle
            try:
                self.state.inspect.remove_breakpoint(event, bp)
            except Exception:
                pass
        elif info.hook_type in ("sim_procedure", "skip") and info._handle is not None:
            try:
                if self.proj.is_hooked(info._handle):
                    self.proj.unhook(info._handle)
            except Exception:
                pass
        del self.hooks[hook_id]
        return True

    # -- Snapshots --

    def snapshot_save(self, label: str = "") -> str:
        self._touch()
        snap_id = self._gen_id("snap-")
        self.snapshots[snap_id] = SnapshotInfo(
            snapshot_id=snap_id,
            label=label or f"snapshot_{len(self.snapshots)}",
            created_at=time.time(),
            _data=self.state.copy(),
        )
        return snap_id

    def snapshot_restore(self, snapshot_id: str) -> None:
        self._touch()
        snap = self.snapshots.get(snapshot_id)
        if snap is None:
            raise KeyError(f"Snapshot '{snapshot_id}' not found. Available: {list(self.snapshots.keys())}")
        self.state = snap._data.copy()

    # -- Symbolic execution (angr-specific) --

    def set_symbolic_register(self, name: str, bits: int = 0) -> str:
        """Make a register symbolic.  Returns the symbolic variable name."""
        self._touch()
        try:
            cur = getattr(self.state.regs, name.lower())
        except AttributeError as e:
            raise ValueError(f"Unknown register '{name}' for arch '{self.arch}'") from e
        width = bits or cur.size()
        var_name = f"{name.lower()}_{self._gen_id()}"
        sym = claripy.BVS(var_name, width)
        setattr(self.state.regs, name.lower(), sym)
        self._symvars[var_name] = sym
        return var_name

    def set_symbolic_memory(self, address: int, size: int, label: str = "") -> str:
        """Make `size` bytes of memory symbolic.  Returns the variable name."""
        self._touch()
        var_name = f"{label or 'mem'}_{self._gen_id()}"
        sym = claripy.BVS(var_name, size * 8)
        try:
            self.state.memory.store(address, sym)
        except Exception as e:
            raise RuntimeError(f"Failed to store symbolic memory at 0x{address:x}: {e}") from e
        self._symvars[var_name] = sym
        return var_name

    def _apply_techniques(self, simgr, techniques: list[str] | None) -> None:
        """Attach angr exploration techniques by name, e.g. 'dfs',
        'loopseer:128', 'lengthlimiter:1000'."""
        import angr as _angr
        for spec in (techniques or []):
            name, _, arg = spec.partition(":")
            name = name.strip().lower()
            try:
                if name == "dfs":
                    simgr.use_technique(_angr.exploration_techniques.DFS())
                elif name == "loopseer":
                    simgr.use_technique(_angr.exploration_techniques.LoopSeer(
                        bound=int(arg) if arg else 128))
                elif name == "lengthlimiter":
                    simgr.use_technique(_angr.exploration_techniques.LengthLimiter(
                        max_length=int(arg) if arg else 1000))
                elif name == "oppologist":
                    simgr.use_technique(_angr.exploration_techniques.Oppologist())
            except Exception:
                pass

    def explore(
        self,
        find: list[int],
        avoid: list[int] | None = None,
        timeout_ms: int = 30000,
        num_find: int = 1,
        techniques: list[str] | None = None,
        veritesting: bool = False,
    ) -> dict[str, Any]:
        """Explore paths from the current state to any `find` address.

        techniques: optional exploration techniques ('dfs', 'loopseer[:bound]',
          'lengthlimiter[:max]', 'oppologist'). veritesting enables Veritesting.

        Returns a summary including solved values for every symbolic variable,
        for each state that reached a target.
        """
        self._touch()
        avoid = avoid or []
        find_clean = [self._clean_addr(a) for a in find]
        avoid_clean = [self._clean_addr(a) for a in avoid]
        simgr = self.proj.factory.simulation_manager(self.state, veritesting=veritesting)
        self._apply_techniques(simgr, techniques)

        deadline = time.time() + max(timeout_ms, 1) / 1000.0
        aborted = ""

        def _step_func(lsm: Any) -> Any:
            if time.time() > deadline:
                nonlocal aborted
                aborted = "timeout"
                lsm.move(from_stash="active", to_stash="deferred")
            total = sum(len(v) for v in lsm.stashes.values())
            if total > MAX_EXPLORE_STATES:
                aborted = "state_explosion"
                lsm.move(from_stash="active", to_stash="deferred")
            return lsm

        start_time = time.time()
        try:
            simgr.explore(
                find=tuple(find_clean),
                avoid=tuple(avoid_clean) if avoid_clean else None,
                num_find=num_find,
                step_func=_step_func,
            )
        except Exception as e:
            return {"status": "error", "error": f"{type(e).__name__}: {e}"}

        self._found_states = list(simgr.found)
        solutions = [self._solve_state(s) for s in simgr.found]
        if simgr.found:
            # Adopt the first solution path as the current state.
            self.state = simgr.found[0]

        return {
            "status": "found" if simgr.found else (aborted or "not_found"),
            "elapsed_ms": round((time.time() - start_time) * 1000, 2),
            "found": len(simgr.found),
            "avoided": len(simgr.stashes.get("avoid", [])),
            "deadended": len(simgr.stashes.get("deadended", [])),
            "active_remaining": len(simgr.active),
            "solutions": solutions,
        }

    def _solve_state(self, state: Any) -> dict[str, Any]:
        """Concretize all tracked symbolic variables for one state."""
        sol: dict[str, Any] = {"address": f"0x{state.addr:x}", "values": {}}
        for var_name, sym in self._symvars.items():
            try:
                val = state.solver.eval(sym)
                nbytes = (sym.size() + 7) // 8
                sol["values"][var_name] = {
                    "hex": f"0x{val:x}",
                    "int": val,
                    "bytes": val.to_bytes(nbytes, "big").hex(),
                }
            except Exception:
                sol["values"][var_name] = None
        return sol

    def solve(self, var_name: str, count: int = 1) -> list[int]:
        """Return up to `count` concrete solutions for a symbolic variable."""
        sym = self._symvars.get(var_name)
        if sym is None:
            raise KeyError(f"Unknown symbolic variable '{var_name}'. Known: {list(self._symvars.keys())}")
        state = self._found_states[0] if self._found_states else self.state
        return list(state.solver.eval_upto(sym, count))

    def list_symbolic(self) -> list[dict[str, Any]]:
        return [{"name": n, "bits": s.size()} for n, s in self._symvars.items()]

    # -- Constraints & solver introspection (angr-specific) --

    _OPS = {
        "==": lambda a, b: a == b, "eq": lambda a, b: a == b,
        "!=": lambda a, b: a != b, "ne": lambda a, b: a != b,
        "<":  lambda a, b: a < b,  "lt": lambda a, b: a < b,
        "<=": lambda a, b: a <= b, "le": lambda a, b: a <= b,
        ">":  lambda a, b: a > b,  "gt": lambda a, b: a > b,
        ">=": lambda a, b: a >= b, "ge": lambda a, b: a >= b,
    }

    def _solver_state(self) -> Any:
        """The state carrying the live constraints (a found path, else current)."""
        return self._found_states[0] if self._found_states else self.state

    def add_constraint(self, var_name: str, op: str, value: int) -> dict[str, Any]:
        """Add a constraint `<var> <op> <value>` to the current state.

        op is one of ==,!=,<,<=,>,>= (or eq/ne/lt/le/gt/ge). Comparisons are
        unsigned. Returns the running satisfiability after adding it.
        """
        self._touch()
        sym = self._symvars.get(var_name)
        if sym is None:
            raise KeyError(f"Unknown symbolic variable '{var_name}'. Known: {list(self._symvars.keys())}")
        fn = self._OPS.get(str(op).strip().lower())
        if fn is None:
            raise ValueError(f"Unknown operator '{op}'. Use one of {sorted(self._OPS)}")
        self.state.solver.add(fn(sym, claripy.BVV(value, sym.size())))
        return {"variable": var_name, "op": op, "value": value,
                "satisfiable": bool(self.state.solver.satisfiable())}

    def value_range(self, var_name: str) -> dict[str, Any]:
        """Return the min and max concrete value a symbolic variable can take."""
        self._touch()
        sym = self._symvars.get(var_name)
        if sym is None:
            raise KeyError(f"Unknown symbolic variable '{var_name}'. Known: {list(self._symvars.keys())}")
        state = self._solver_state()
        try:
            lo = state.solver.min(sym)
            hi = state.solver.max(sym)
        except Exception as e:
            return {"variable": var_name, "error": f"{type(e).__name__}: {e}"}
        unique = lo == hi
        return {"variable": var_name, "bits": sym.size(),
                "min": lo, "max": hi, "unique": unique}

    def is_satisfiable(self) -> bool:
        """Whether the current state's accumulated constraints are satisfiable."""
        self._touch()
        return bool(self.state.solver.satisfiable())

    # -- Static analysis (angr-specific) --

    def recover_cfg(self, fast: bool = True) -> dict[str, Any]:
        """Recover a control-flow graph and the functions in it."""
        self._touch()
        try:
            if fast:
                cfg = self.proj.analyses.CFGFast(normalize=True)
            else:
                cfg = self.proj.analyses.CFGEmulated(normalize=True)
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}
        self._cfg = cfg
        funcs = []
        for fn in self.proj.kb.functions.values():
            funcs.append({
                "address": f"0x{fn.addr:x}",
                "name": fn.name,
                "size": getattr(fn, "size", 0),
                "is_plt": bool(getattr(fn, "is_plt", False)),
            })
        funcs.sort(key=lambda f: int(f["address"], 16))
        return {"nodes": cfg.graph.number_of_nodes(),
                "edges": cfg.graph.number_of_edges(),
                "functions": funcs}

    def list_functions(self) -> list[dict[str, Any]]:
        """List recovered functions (runs CFGFast first if needed)."""
        if getattr(self, "_cfg", None) is None:
            self.recover_cfg(fast=True)
        out = []
        for fn in self.proj.kb.functions.values():
            out.append({"address": f"0x{fn.addr:x}", "name": fn.name,
                        "size": getattr(fn, "size", 0)})
        out.sort(key=lambda f: int(f["address"], 16))
        return out

    def call_function(self, address: int, args: list[int] | None = None) -> dict[str, Any]:
        """Execute a function with concrete integer args and return its result,
        using angr's calling-convention-aware `callable`."""
        self._touch()
        args = args or []
        try:
            caller = self.proj.factory.callable(
                self._clean_addr(address), concrete_only=True,
                add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                             angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS},
            )
            ret = caller(*args)
        except Exception:
            # Retry allowing path forks (symbolic / multi-path return).
            try:
                caller = self.proj.factory.callable(
                    self._clean_addr(address), concrete_only=False,
                    add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                 angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS},
                )
                ret = caller(*args)
            except Exception as e:
                return {"error": f"{type(e).__name__}: {e}"}
        if ret is None:
            return {"address": f"0x{address:x}", "args": args, "return_value": None}
        try:
            val = caller.result_state.solver.eval(ret)
        except Exception:
            val = None
        return {
            "address": f"0x{address:x}",
            "args": args,
            "return_value": {"hex": f"0x{val:x}", "int": val} if val is not None else None,
        }

    def _ensure_cfg(self):
        if getattr(self, "_cfg", None) is None:
            self.recover_cfg(fast=True)
        return self._cfg

    def _lookup_function(self, address: int):
        clean = self._clean_addr(address)
        funcs = self.proj.kb.functions
        try:
            return funcs.get_by_addr(clean)
        except KeyError:
            return funcs.get(clean) if clean in funcs else None

    def decompile_function(self, address: int) -> dict[str, Any]:
        """Decompile the function at `address` to pseudo-C (runs CFG first)."""
        self._touch()
        try:
            cfg = self._ensure_cfg()
        except Exception as e:
            return {"error": f"CFG recovery failed: {type(e).__name__}: {e}"}
        fn = self._lookup_function(address)
        if fn is None:
            return {"error": f"No function recovered at 0x{address:x}. "
                             f"Run emu_cfg / check emu_function_info first."}
        try:
            dec = self.proj.analyses.Decompiler(fn, cfg=cfg.model)
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}
        code = getattr(getattr(dec, "codegen", None), "text", None)
        if not code:
            return {"error": "Decompiler produced no output (unsupported function)."}
        return {"address": f"0x{fn.addr:x}", "name": fn.name, "code": code}

    def function_info(self, address: int) -> dict[str, Any]:
        """Metadata about one recovered function: flags, blocks, callers, callees."""
        self._touch()
        try:
            cfg = self._ensure_cfg()
        except Exception as e:
            return {"error": f"CFG recovery failed: {type(e).__name__}: {e}"}
        fn = self._lookup_function(address)
        if fn is None:
            return {"error": f"No function recovered at 0x{address:x}."}
        callgraph = cfg.functions.callgraph
        funcs = self.proj.kb.functions

        def _names(addrs):
            out = []
            for a in addrs:
                try:
                    out.append(funcs.get_by_addr(a).name)
                except Exception:
                    out.append(f"0x{a:x}")
            return out

        callers = _names(callgraph.predecessors(fn.addr)) if fn.addr in callgraph else []
        callees = _names(callgraph.successors(fn.addr)) if fn.addr in callgraph else []
        try:
            nblocks = len(list(fn.blocks))
        except Exception:
            nblocks = 0
        info: dict[str, Any] = {
            "address": f"0x{fn.addr:x}",
            "name": fn.name,
            "size": getattr(fn, "size", 0),
            "blocks": nblocks,
            "returning": bool(getattr(fn, "returning", False)),
            "is_plt": bool(getattr(fn, "is_plt", False)),
            "is_syscall": bool(getattr(fn, "is_syscall", False)),
            "callers": sorted(set(callers)),
            "callees": sorted(set(callees)),
        }
        # Calling convention / prototype are best-effort (may be None).
        cc = getattr(fn, "calling_convention", None)
        if cc is not None:
            info["calling_convention"] = str(cc)
        proto = getattr(fn, "prototype", None)
        if proto is not None:
            info["prototype"] = str(proto)
        return info

    # -- Lifecycle --

    def close(self) -> None:
        self._touch()
        self.hooks.clear()
        self.snapshots.clear()
        self.trace.clear()
        self._symvars.clear()
        self._found_states = []
        self.state = None
        self.proj = None
