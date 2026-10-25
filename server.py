"""Emulation MCP Server - CPU and binary emulation for reverse engineering.

Supports:
- Unicorn Engine: shellcode and code snippet emulation (x86, ARM, MIPS, ...)
- Qiling Framework: full binary emulation with OS-level syscall support

Usage:
    python server.py
"""

import sys
import os
import re
import inspect
import subprocess
import json
import threading
from collections import defaultdict

# Add project root to path so engines can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastmcp import FastMCP
from session_manager import SessionManager
from engines import (
    ENGINE_NAMES, get_engine_class, is_installed, describe_engines,
)
from engines.base import CODE_BASE, CODE_SIZE, DATA_BASE, DATA_SIZE, STACK_TOP
import fuzzing

mcp = FastMCP(
    "emulation",
    instructions=(
        "CPU and binary emulation for reverse engineering workflows.\n"
        "Engines (call emu_list_engines to see which are installed):\n"
        "- 'unicorn': Fast CPU emulator for shellcode and code snippets. No OS, no syscalls.\n"
        "- 'qiling':  Full binary emulation with OS support (Linux/Windows/...). Needs a rootfs.\n"
        "- 'icicle':  CPU emulator on Ghidra SLEIGH semantics. Adds RISC-V/PowerPC/MSP430 and\n"
        "             serves as an independent cross-check of Unicorn (see emu_compare_engines).\n"
        "- 'angr':    Symbolic execution. Make registers/memory symbolic and solve for the\n"
        "             inputs that drive execution to a target address (emu_explore/emu_solve).\n\n"
        "Typical workflow:\n"
        "1. Create a session with emu_create_session (pick an engine + arch)\n"
        "2. For CPU engines: map memory, write code, run\n"
        "3. For Qiling: point at binary + rootfs, hook syscalls/APIs, run\n"
        "4. For angr: write code, make inputs symbolic, explore to a target, solve\n"
        "5. Inspect registers, memory, trace; use snapshots to save/restore state\n\n"
        "Tool surface: a small generic CORE is advertised (session lifecycle, run/step,\n"
        "memory/register access) together with the introspection trio -- emu_describe\n"
        "lists a session's live capabilities and each method's signature, and emu_call\n"
        "invokes any of them. This reaches the FULL engine API (hooks, snapshots,\n"
        "symbolization, CFG, fuzzing, ...) without a dedicated tool per capability, which\n"
        "matters because engines/archs support different subsets. Discover with\n"
        "emu_describe, then drive with emu_call. Set EMU_EXPOSE_TYPED_TOOLS=1 to also\n"
        "advertise the full catalog of explicit emu_* verbs."
    ),
)

sessions = SessionManager()

# ---------------------------------------------------------------------------
# Tool surface: a lean generic core, advertised by default; the full typed
# catalog is opt-in.
# ---------------------------------------------------------------------------
# A large fixed catalog of typed tools is the wrong primary interface: every
# engine/arch/install supports a different subset, and hand-wiring one verb per
# capability neither scales nor lets a capable model build its own tooling. So
# by default the server advertises only a small, engine-agnostic CORE and the
# generic introspection trio (emu_describe / emu_call / emu_eval). A model
# inspects a session with emu_describe -- which now reports the engine's live
# capabilities and each method's signature -- and drives the full engine API
# through emu_call, so the advertised list need not enumerate capabilities that
# vary per engine.
#
# Set EMU_EXPOSE_TYPED_TOOLS=1 to additionally advertise the whole typed catalog
# (emu_hook_*, emu_snapshot_*, emu_symbolize, emu_cfg, emu_fuzz, ...) for clients
# or models that prefer explicit, discoverable verbs. Either way every emu_*
# function stays defined on this module, so nothing is lost: the un-advertised
# ones remain reachable via emu_call and importable by tests.
_EXPOSE_TYPED = os.getenv("EMU_EXPOSE_TYPED_TOOLS", "0").strip().lower() not in (
    "", "0", "false", "no", "off",
)

CORE_TOOLS: frozenset[str] = frozenset({
    # session lifecycle + discovery
    "emu_create_session", "emu_list_sessions", "emu_close_session", "emu_list_engines",
    # execution
    "emu_run", "emu_step",
    # raw memory + registers
    "emu_memory_read", "emu_memory_write", "emu_memory_map",
    "emu_registers_read", "emu_register_write",
    # generic introspection + invocation (the composable core)
    "emu_describe", "emu_call", "emu_eval",
})

_mcp_tool = mcp.tool  # the real FastMCP decorator factory


def _gated_tool(*dargs, **dkwargs):
    """Intercept ``@mcp.tool()`` so registration is core/flag gated.

    A tool is advertised over MCP when its function name is in CORE_TOOLS or
    when EMU_EXPOSE_TYPED_TOOLS is set; otherwise the function is defined on the
    module but not registered. This keeps the default tool surface small without
    editing (or losing) any of the typed tools.
    """
    def deco(fn):
        if getattr(fn, "__name__", "") in CORE_TOOLS or _EXPOSE_TYPED:
            return _mcp_tool(*dargs, **dkwargs)(fn)
        return fn
    return deco


mcp.tool = _gated_tool  # every @mcp.tool() below routes through the gate

# ---------------------------------------------------------------------------
# Security & resource limits
# ---------------------------------------------------------------------------

# EM-1: Comma-separated list of allowed directories for binary paths.
# If not set, all paths are allowed (backwards compatible).
_ALLOWED_DIRS_RAW = os.getenv("EMULATION_ALLOWED_DIRS", "")
ALLOWED_DIRS: list[str] = [
    os.path.realpath(d.strip()) for d in _ALLOWED_DIRS_RAW.split(",") if d.strip()
]

# EM-2: Maximum number of concurrent sessions
MAX_SESSIONS = int(os.getenv("EMU_MAX_SESSIONS", "10"))

# EM-3: Maximum memory map size (256 MB)
MAX_MEMORY_MAP_SIZE = 256 * 1024 * 1024

# EM-5: Maximum step count to prevent server hangs
MAX_STEPS = 1_000_000

# EM-6: Default timeout for Qiling execution (seconds)
QILING_TIMEOUT_S = int(os.getenv("EMU_QILING_TIMEOUT", "60"))


def _validate_binary_path(path: str) -> str:
    """Validate that a binary path is within ALLOWED_DIRS.

    Returns the resolved real path if valid.
    Raises ValueError if the path is outside allowed directories.
    """
    real = os.path.realpath(path)
    if not ALLOWED_DIRS:
        return real  # no restriction configured
    for allowed in ALLOWED_DIRS:
        if real.startswith(allowed + os.sep) or real == allowed:
            return real
    raise ValueError(
        f"Path '{path}' is outside allowed directories. "
        f"Allowed: {', '.join(ALLOWED_DIRS)}"
    )


# ---------------------------------------------------------------------------
# Reflective access helpers (emu_call / emu_describe / emu_eval)
# ---------------------------------------------------------------------------

# EM-8: Opt-in gate for the arbitrary-code eval tool (off by default).
ENABLE_EVAL = os.getenv("EMU_ENABLE_EVAL", "").lower() in ("1", "true", "yes", "on")

# Background GDB subprocesses, keyed by session_id: (Popen, dump_file_path).
_GDB_PROCS = {}
_GDB_RUNNER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "icicle_ext", "gdb_server_runner.py")


_GDB_DUMP_BYTE_CAP = 64 * 1024 * 1024  # don't dump bytes for ranges larger than this


def _dump_icicle_state(engine) -> dict:
    """Serialize an Icicle session's state for a fresh VM to restore.

    Captures the icicle arch string, the real mapped memory ranges (via the
    MMU, so OS-loaded images are included), zero/oversized ranges without bytes,
    all <=64-bit registers, and pc/sp.
    """
    vm = engine.vm
    # Prefer true MMU enumeration (covers Linux/loader mappings); fall back to
    # the wrapper's tracked regions on an older binding.
    ranges: list[tuple[int, int, int]] = []
    if hasattr(vm, "mem_map_ranges"):
        try:
            ranges = [(base, size, 7) for base, size in vm.mem_map_ranges()]
        except Exception:
            ranges = []
    if not ranges:
        ranges = [(base, size, perms) for base, (size, perms) in sorted(engine._regions.items())]

    regions = []
    for base, size, perms in ranges:
        if size <= 0:
            continue
        hexbytes = ""
        if size <= _GDB_DUMP_BYTE_CAP:
            try:
                data = bytes(vm.mem_read(base, size))
                if data.strip(b"\x00"):   # skip all-zero ranges (mapped zeroed anyway)
                    hexbytes = data.hex()
            except Exception:
                pass
        regions.append([base, size, perms, hexbytes])
    regs = {}
    try:
        for name, (_off, rsize) in vm.reg_list().items():
            if rsize <= 8:
                try:
                    regs[name] = vm.reg_read(name)
                except Exception:
                    pass
    except Exception:
        pass
    return {
        "arch": vm.architecture,
        "regions": regions,
        "regs": regs,
        "pc": vm.pc,
        "sp": vm.sp,
    }

# The underlying native object for each engine, reachable via target="native".
_NATIVE_ATTR = {"unicorn": "uc", "qiling": "ql", "icicle": "vm", "angr": "state"}


def _native_object(engine):
    """Return the engine's underlying native object (uc/ql/vm/state), or None."""
    return getattr(engine, _NATIVE_ATTR.get(engine.engine_type, ""), None)


def _resolve_target(engine, target: str):
    """Resolve a reflective target name to an object."""
    if target == "engine":
        return engine
    if target == "native":
        obj = _native_object(engine)
        if obj is None:
            raise ValueError(f"Engine '{engine.engine_type}' exposes no native object.")
        return obj
    raise ValueError(f"Unknown target '{target}'. Use 'engine' or 'native'.")


def _coerce_arg(v):
    """Coerce JSON argument values into Python call arguments.

    - "0x1234" (hex string) -> int
    - {"hex": "deadbeef"}   -> bytes
    - {"bytes": [1,2,3]}    -> bytes
    - lists are coerced element-wise
    """
    if isinstance(v, str) and re.fullmatch(r"0[xX][0-9a-fA-F]+", v):
        return int(v, 16)
    if isinstance(v, dict):
        if set(v) == {"hex"} and isinstance(v["hex"], str):
            return bytes.fromhex(v["hex"].replace(" ", ""))
        if set(v) == {"bytes"} and isinstance(v["bytes"], list):
            return bytes(v["bytes"])
        return v
    if isinstance(v, list):
        return [_coerce_arg(x) for x in v]
    return v


def _format_value(r) -> str:
    """Render an arbitrary return value as a readable string."""
    if r is None:
        return "None"
    if isinstance(r, bool):
        return str(r)
    if isinstance(r, int):
        return f"{r} (0x{r:x})" if r >= 0 else str(r)
    if isinstance(r, (bytes, bytearray)):
        b = bytes(r)
        return f"bytes[{len(b)}]: {b.hex()}"
    if isinstance(r, (list, tuple)):
        inner = ", ".join(_format_value(x) for x in list(r)[:64])
        more = "" if len(r) <= 64 else f", … (+{len(r) - 64} more)"
        return f"[{inner}{more}]"
    if isinstance(r, dict):
        items = ", ".join(f"{k}={_format_value(v)}" for k, v in list(r.items())[:64])
        return f"{{{items}}}"
    return repr(r)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_addr(addr: str | int) -> int:
    """Parse hex string or int to integer address."""
    if isinstance(addr, int):
        if addr < 0:
            raise ValueError(f"Negative address not allowed: {addr}")
        return addr
    addr = addr.strip()
    if addr.startswith("0x") or addr.startswith("0X"):
        val = int(addr, 16)
    else:
        # Try hex first, fall back to decimal
        try:
            val = int(addr, 16)
        except ValueError:
            val = int(addr)
    if val < 0:
        raise ValueError(f"Negative address not allowed: {val}")
    return val


def _parse_int(value: str | int) -> int:
    """Parse an integer VALUE (not an address): decimal by default, 0x => hex.

    Unlike _parse_addr, a bare "10" means ten, not sixteen — the right default
    for constraint bounds and forced return values. Negative values are allowed.
    """
    if isinstance(value, int):
        return value
    value = value.strip()
    if value.lower().startswith(("0x", "-0x", "+0x")):
        return int(value, 16)
    return int(value, 10)


def _hex_dump(data: bytes, base_addr: int = 0, width: int = 16) -> str:
    """Format bytes as a hex dump string."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"0x{base_addr + i:08x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Report format helpers
# ---------------------------------------------------------------------------

# Known register roles for report annotations
_REG_ROLES = {
    # Return value registers
    "rax": "Return value", "eax": "Return value", "v0": "Return value",
    "r0": "Return value (ARM)", "x0": "Return value (ARM64)",
    # Argument registers (x86_64)
    "rdi": "Arg 1", "rsi": "Arg 2", "rdx": "Arg 3",
    "rcx": "Arg 4", "r8": "Arg 5", "r9": "Arg 6",
    # Argument registers (MIPS)
    "a0": "Arg 1", "a1": "Arg 2", "a2": "Arg 3", "a3": "Arg 4",
    # Argument registers (ARM)
    "r1": "Arg 2 (ARM)", "r2": "Arg 3 (ARM)", "r3": "Arg 4 (ARM)",
    "x1": "Arg 2 (ARM64)", "x2": "Arg 3 (ARM64)", "x3": "Arg 4 (ARM64)",
    # Stack / frame / link
    "rsp": "Stack pointer", "esp": "Stack pointer", "sp": "Stack pointer",
    "rbp": "Frame pointer", "ebp": "Frame pointer", "fp": "Frame pointer",
    "rip": "Instruction pointer", "eip": "Instruction pointer", "pc": "Program counter",
    "ra": "Return address", "lr": "Link register",
}

# Shell metacharacters worth noting in memory report
_SHELL_META = set("|;&$`(){}[]!<>")


def _reg_note(name: str, value: int) -> str:
    """Return an interpretive note for a register value."""
    return _REG_ROLES.get(name.lower(), "")


def _report_run(result: dict, regs: dict, trace_count: int) -> str:
    """Format emu_run output as markdown report."""
    status = result.get("status", "unknown")
    status_text = "Completed successfully" if status == "ok" else f"Error: {status}"
    elapsed = result.get("elapsed_ms", 0)
    instr = result.get("instructions_traced", trace_count)

    lines = [
        "### Emulation Result\n",
        "| Property | Value |",
        "|----------|-------|",
        f"| Status | {status_text} |",
        f"| Instructions | {instr} |",
        f"| Duration | {elapsed} ms |",
        "",
        "**Key Registers:**",
        "| Register | Value | Interpretation |",
        "|----------|-------|----------------|",
    ]
    for k, v in regs.items():
        if v == 0:
            continue
        note = _reg_note(k, v)
        lines.append(f"| {k} | 0x{v:x} | {note} |")

    zero_count = sum(1 for v in regs.values() if v == 0)
    if zero_count:
        lines.append(f"\n*{zero_count} register(s) at zero omitted.*")
    return "\n".join(lines)


def _report_registers(regs: dict) -> str:
    """Format register state as markdown report."""
    lines = [
        "### Register State\n",
        "| Register | Hex | Decimal | Notes |",
        "|----------|-----|---------|-------|",
    ]
    zero_count = 0
    for k, v in regs.items():
        if v == 0:
            zero_count += 1
            continue
        note = _reg_note(k, v)
        lines.append(f"| {k} | 0x{v:x} | {v} | {note} |")

    if zero_count:
        lines.append(f"\n*Non-zero registers shown. {zero_count} register(s) at zero omitted.*")
    return "\n".join(lines)


def _report_memory(data: bytes, base_addr: int) -> str:
    """Format memory read as markdown report."""
    hex_lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_lines.append(" ".join(f"{b:02x}" for b in chunk))
    hex_block = "\n".join(hex_lines)

    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    ascii_display = ascii_str.rstrip(".")

    lines = [
        f"### Memory at 0x{base_addr:x} ({len(data)} bytes)\n",
        "**Hex:**",
        "```",
        hex_block,
        "```",
        "",
        f"**ASCII:** `{ascii_display}`" if ascii_display else "**ASCII:** *(no printable content)*",
    ]

    notable = []
    for i, b in enumerate(data):
        ch = chr(b) if 32 <= b < 127 else None
        if ch and ch in _SHELL_META:
            notable.append(f"- Offset 0x{i:x}: `{b:02x}` = `{ch}` (shell metacharacter)")
        elif b == 0 and i > 0 and any(32 <= data[j] < 127 for j in range(max(0, i - 1), i)):
            notable.append(f"- Null terminator at offset 0x{i:x}")

    if notable:
        lines.append("")
        lines.append("**Notable bytes:**")
        lines.extend(notable[:20])

    return "\n".join(lines)


def _report_shellcode(arch: str, code_len: int, base_address: str,
                      result: dict, trace: list, regs: dict) -> str:
    """Format shellcode emulation result as markdown report."""
    status = result.get("status", "unknown")
    status_text = "Completed successfully" if status == "ok" else f"Error: {status}"
    elapsed = result.get("elapsed_ms", 0)

    lines = [
        f"### Shellcode Emulation ({arch}, {code_len} bytes at {base_address})\n",
        "| Property | Value |",
        "|----------|-------|",
        f"| Status | {status_text} |",
        f"| Instructions | {len(trace)} |",
        f"| Duration | {elapsed} ms |",
        "",
    ]

    if trace:
        lines.append("**Execution Trace:**")
        lines.append("```")
        if len(trace) <= 20:
            for t in trace:
                lines.append(f"{t['address']}: {t['instruction']}")
        else:
            for t in trace[:10]:
                lines.append(f"{t['address']}: {t['instruction']}")
            lines.append(f"... ({len(trace) - 15} instructions omitted) ...")
            for t in trace[-5:]:
                lines.append(f"{t['address']}: {t['instruction']}")
        lines.append("```")
        lines.append("")

    lines.append("**Key Registers:**")
    lines.append("| Register | Value | Interpretation |")
    lines.append("|----------|-------|----------------|")
    for k, v in regs.items():
        if v == 0:
            continue
        note = _reg_note(k, v)
        lines.append(f"| {k} | 0x{v:x} | {note} |")

    zero_count = sum(1 for v in regs.values() if v == 0)
    if zero_count:
        lines.append(f"\n*{zero_count} register(s) at zero omitted.*")

    return "\n".join(lines)


def _report_hooks(hooks: list) -> str:
    """Format hooks list as markdown report."""
    lines = [
        f"### Active Hooks ({len(hooks)})\n",
        "| Hook ID | Type | Target | Description |",
        "|---------|------|--------|-------------|",
    ]
    for h in hooks:
        desc = h.get("description", "") or ""
        lines.append(f"| {h['hook_id']} | {h['type']} | {h['target']} | {desc} |")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Smart trace analysis helpers
# ---------------------------------------------------------------------------

_BRANCH_MNEMONICS = {
    "beq", "bne", "bgtz", "blez", "bgez", "bltz", "bnez", "beqz",  # MIPS
    "b", "bl", "bx", "blx", "beq", "bne", "bgt", "blt", "bge", "ble",  # ARM
    "je", "jne", "jg", "jl", "jge", "jle", "jz", "jnz", "ja", "jb",  # x86
    "jmp", "call",
}

_DANGEROUS_CALLS = {"system", "popen", "execve", "strcpy", "sprintf", "gets", "strcat"}


def _analyze_trace(trace_entries: list[dict], arch: str) -> dict:
    """Analyze trace for loops, branches, key events."""
    addr_counts: dict[str, int] = {}
    mem_reads: dict[str, int] = {}
    mem_writes: dict[str, int] = {}
    branches: list[dict] = []
    api_calls: list[dict] = []
    dangerous_ops: list[dict] = []

    for i, t in enumerate(trace_entries):
        typ = t.get("type", "instruction")
        addr = t.get("address", "0x0")

        if typ == "instruction":
            addr_counts[addr] = addr_counts.get(addr, 0) + 1
            instr = t.get("instruction", "")
            mnemonic = instr.split()[0] if instr else ""
            if mnemonic in _BRANCH_MNEMONICS:
                branches.append({"index": i, "address": addr, "instruction": instr})

        elif typ == "memory":
            name = t.get("name", "")
            page = addr[:len(addr)-3] + "xxx" if len(addr) > 3 else addr
            if "read" in name:
                mem_reads[page] = mem_reads.get(page, 0) + 1
            else:
                mem_writes[page] = mem_writes.get(page, 0) + 1

        elif typ in ("syscall", "api"):
            call_name = t.get("name", "")
            api_calls.append({"index": i, "name": call_name, "args": t.get("args", [])})
            if call_name.lower() in _DANGEROUS_CALLS:
                dangerous_ops.append({"index": i, "address": addr, "call": call_name})

    # Detect loops (addresses hit >3 times)
    loops = []
    for addr, count in sorted(addr_counts.items(), key=lambda x: -x[1]):
        if count > 3:
            loops.append({"address": addr, "iterations": count})
        if len(loops) >= 10:
            break

    return {
        "total": len(trace_entries),
        "entry": trace_entries[0].get("address", "?") if trace_entries else "?",
        "exit": trace_entries[-1].get("address", "?") if trace_entries else "?",
        "loops": loops,
        "branches": branches[:50],
        "api_calls": api_calls,
        "dangerous_ops": dangerous_ops,
        "mem_reads": mem_reads,
        "mem_writes": mem_writes,
        "unique_addrs": len(addr_counts),
    }


def _format_smart_trace(trace_entries: list[dict], arch: str) -> str:
    """Produce an analyzed trace summary."""
    a = _analyze_trace(trace_entries, arch)
    parts = [f"## Trace Summary ({a['total']} instructions)\n"]

    parts.append("### Execution Flow")
    parts.append(f"- Entry: {a['entry']}")
    parts.append(f"- Exit: {a['exit']}")
    parts.append(f"- Total instructions: {a['total']}")
    parts.append(f"- Unique addresses: {a['unique_addrs']}")
    parts.append("")

    if a["loops"]:
        parts.append("### Loops Detected")
        for lp in a["loops"]:
            parts.append(f"- **{lp['address']}**: {lp['iterations']} iterations")
        parts.append("")

    if a["api_calls"]:
        parts.append("### API/Syscall Calls")
        for call in a["api_calls"]:
            args_str = ", ".join(str(x) for x in call["args"][:4])
            parts.append(f"- [#{call['index']}] {call['name']}({args_str})")
        parts.append("")

    if a["dangerous_ops"]:
        parts.append("### ⚠ Dangerous Operations")
        for op in a["dangerous_ops"]:
            parts.append(f"- [#{op['index']}] {op['address']}: **{op['call']}()** called")
        parts.append("")

    if a["mem_reads"] or a["mem_writes"]:
        parts.append("### Memory Access")
        if a["mem_reads"]:
            parts.append("**Reads:**")
            for page, count in sorted(a["mem_reads"].items()):
                parts.append(f"- {page}: {count} accesses")
        if a["mem_writes"]:
            parts.append("**Writes:**")
            for page, count in sorted(a["mem_writes"].items()):
                parts.append(f"- {page}: {count} accesses")
        parts.append("")

    if a["branches"]:
        parts.append(f"### Branches ({len(a['branches'])} detected)")
        shown = a["branches"][:15]
        for br in shown:
            parts.append(f"- [#{br['index']}] {br['address']}: {br['instruction']}")
        if len(a["branches"]) > 15:
            parts.append(f"- ... and {len(a['branches']) - 15} more")
        parts.append("")

    return "\n".join(parts)


def _format_report_trace(trace_entries: list[dict], arch: str) -> str:
    """Produce clean markdown for bug bounty reports."""
    a = _analyze_trace(trace_entries, arch)
    parts = [f"### CPU Emulation Trace\n"]

    parts.append(f"**Architecture:** {arch}")
    parts.append(f"**Instructions executed:** {a['total']}")
    parts.append(f"**Entry point:** {a['entry']}")
    parts.append(f"**Exit point:** {a['exit']}")
    parts.append("")

    if a["loops"]:
        main_loop = a["loops"][0]
        parts.append(f"**Main loop:** {main_loop['address']} executed {main_loop['iterations']} times"
                      f" (character validation loop)")
        parts.append("")

    if a["dangerous_ops"]:
        parts.append("**Dangerous operations detected:**")
        for op in a["dangerous_ops"]:
            parts.append(f"- `{op['call']}()` called at {op['address']}")
        parts.append("")

    if a["api_calls"]:
        parts.append("**API calls observed:**")
        for call in a["api_calls"]:
            args_str = ", ".join(str(x) for x in call["args"][:4])
            parts.append(f"- `{call['name']}({args_str})`")
        parts.append("")

    # Show first 5 and last 5 instructions for context
    instrs = [t for t in trace_entries if t.get("type") == "instruction"]
    if len(instrs) > 10:
        parts.append("**Trace excerpt** (first 5 / last 5):")
        parts.append("```")
        for t in instrs[:5]:
            parts.append(f"  {t['address']}: {t['instruction']}")
        parts.append(f"  ... ({len(instrs) - 10} instructions omitted) ...")
        for t in instrs[-5:]:
            parts.append(f"  {t['address']}: {t['instruction']}")
        parts.append("```")
    elif instrs:
        parts.append("**Full trace:**")
        parts.append("```")
        for t in instrs:
            parts.append(f"  {t['address']}: {t['instruction']}")
        parts.append("```")

    return "\n".join(parts)


# ===========================================================================
# Session Management Tools
# ===========================================================================

@mcp.tool()
def emu_create_session(
    engine: str,
    arch: str = "",
    label: str = "",
    binary_path: str = "",
    rootfs: str = "",
    ostype: str = "linux",
    args: list[str] | None = None,
    enable_trace: bool = False,
    engine_options: dict | None = None,
) -> str:
    """Create a new emulation session.

    engine: one of "unicorn", "qiling", "icicle", "angr", "sogen" (see emu_list_engines).
      - unicorn / icicle: CPU emulators for shellcode & code snippets.
      - qiling: full binary emulation with OS services.
      - angr: symbolic execution (shellcode mode, or binary mode with binary_path).
      - sogen: Windows/Linux user-mode emulator loading real system libraries.
    arch: Architecture string - "x86", "x86_64", "arm", "arm_thumb", "arm64", "mips",
      "mips_le", and (icicle/angr) "riscv64", "ppc", "ppc64", etc. Optional for angr in
      binary mode (detected from the binary).
    label: Optional human-readable label for the session.

    For Qiling:
      binary_path: Path to the ELF/PE binary to emulate.
      rootfs: Path to the root filesystem (e.g., extracted firmware squashfs-root).
      ostype: "linux", "windows", or "freebsd".
      args: Command-line arguments for the binary.
    For angr binary mode:
      binary_path: Path to the ELF/PE binary (no rootfs needed).
    For Sogen:
      binary_path: PE/ELF to run (optional; omit for an empty emulator).
      rootfs: the emulation root -- a prepared tree of system DLLs + registry for
        Windows (e.g. https://sogen.dev/root.zip); Linux defaults to the host '/'.
      ostype: "windows" or "linux".
      engine_options: {"backend": "unicorn"|"icicle"} selects the CPU backend.

    engine_options: Optional dict of engine-specific constructor options. For
      Icicle these map onto the VM knobs, e.g. {"jit": true} (faster, but only
      safe without breakpoints/stepping), {"shadow_stack": true},
      {"track_uninitialized": true}, or {"mem_capacity": 100000}.

    Returns session_id to use with other emu_* tools.
    """
    try:
        # EM-2: Enforce session count limit
        if len(sessions.list_sessions()) >= MAX_SESSIONS:
            return f"Error: Maximum session limit ({MAX_SESSIONS}) reached. Close existing sessions first."

        if engine not in ENGINE_NAMES:
            return f"Error: Unknown engine '{engine}'. Available: {', '.join(ENGINE_NAMES)}."
        if not is_installed(engine):
            return (f"Error: Engine '{engine}' is not installed. "
                    f"See emu_list_engines for installation instructions.")
        engine_cls = get_engine_class(engine)
        opts = engine_options or {}

        if engine == "qiling":
            if not binary_path:
                return "Error: binary_path is required for Qiling engine."
            if not rootfs:
                return "Error: rootfs is required for Qiling engine (path to extracted filesystem)."
            _validate_binary_path(binary_path)  # EM-1
            eng = engine_cls(
                binary_path=binary_path, rootfs=rootfs, arch=arch,
                ostype=ostype, args=args or [], enable_trace=enable_trace,
                **opts,
            )
        elif engine == "angr" and binary_path:
            _validate_binary_path(binary_path)  # EM-1
            eng = engine_cls(arch=arch, binary_path=binary_path, **opts)
            if enable_trace:
                eng.enable_tracing()
        elif engine == "sogen":
            # Sogen: Windows/Linux user-mode. binary_path optional (empty ->
            # create_empty); rootfs maps to the emulation root. Backend and
            # other knobs come through engine_options.
            if binary_path:
                _validate_binary_path(binary_path)  # EM-1
            eng = engine_cls(
                arch=arch or "x86_64", binary_path=binary_path, rootfs=rootfs,
                ostype=ostype, args=args or [], enable_trace=enable_trace, **opts,
            )
        else:
            if not arch:
                return f"Error: arch is required for the '{engine}' engine."
            kw = dict(opts)
            # Icicle Linux userspace mode: load an ELF with syscall emulation.
            if engine == "icicle" and binary_path:
                _validate_binary_path(binary_path)  # EM-1
                kw["binary_path"] = binary_path
                if args:
                    kw["argv"] = args
                kw.setdefault("os", "linux")
            eng = engine_cls(arch=arch, **kw)
            if enable_trace:
                eng.enable_tracing()

        arch = eng.arch  # may have been detected (angr binary mode)
        session_id = sessions.create_session(eng, label=label or f"{engine}/{arch}")
        info = eng.get_info()
        return (
            f"Session created: {session_id}\n"
            f"Engine: {engine}\n"
            f"Architecture: {arch}\n"
            f"Label: {label or f'{engine}/{arch}'}\n"
            f"Info: {info}"
        )
    except Exception as e:
        return f"Error creating session: {e}"


@mcp.tool()
def emu_list_sessions() -> str:
    """List all active emulation sessions with their details."""
    sess_list = sessions.list_sessions()
    if not sess_list:
        return "No active sessions."
    parts = [f"Active sessions ({len(sess_list)}):\n"]
    for s in sess_list:
        parts.append(
            f"  {s['session_id']} | {s['engine_type']}/{s['arch']} | "
            f"label={s['label']} | hooks={s['hooks']} | "
            f"snapshots={s['snapshots']} | trace={s['trace_entries']}"
        )
    return "\n".join(parts)


@mcp.tool()
def emu_close_session(session_id: str) -> str:
    """Close an emulation session and free all resources.

    session_id: The session ID returned by emu_create_session.
    """
    _stop_gdb(session_id)  # tear down any background GDB server for this session
    if sessions.close(session_id):
        return f"Session {session_id} closed."
    return f"Session {session_id} not found."


# ===========================================================================
# Execution Tools
# ===========================================================================

@mcp.tool()
def emu_run(
    session_id: str,
    start_addr: str = "",
    end_addr: str = "",
    timeout_ms: int = 10000,
    format: str = "default",
) -> str:
    """Run emulation in a session.

    session_id: Active session ID.
    start_addr: Start address (hex, e.g. "0x1000000"). Required for Unicorn.
    end_addr: End address (hex). Emulation stops here. Required for Unicorn.
    timeout_ms: Maximum execution time in milliseconds (default: 10000).
    format: Output format - "default" for plain text, "report" for markdown tables.

    For Qiling sessions without start/end: runs from the binary's entry point.
    For Icicle with start_addr but no end_addr: runs freely until a halt,
    breakpoint, crash, or the instruction budget (status "breakpoint" stops at a
    breakpoint; resume by running again from the current pc).
    Returns execution summary with register state.
    """
    if format not in ("default", "report"):
        return f"Error: Unknown format '{format}'. Use 'default' or 'report'."
    try:
        engine = sessions.get(session_id)
        begin = _parse_addr(start_addr) if start_addr else 0
        end = _parse_addr(end_addr) if end_addr else 0

        # EM-6: Enforce wall-clock timeout for Qiling sessions via threading.Timer
        if engine.engine_type == "qiling":
            _timeout_fired = threading.Event()

            def _on_timeout():
                _timeout_fired.set()
                try:
                    engine.ql.stop()
                except Exception:
                    pass

            timer = threading.Timer(QILING_TIMEOUT_S, _on_timeout)
            timer.daemon = True
            timer.start()
            try:
                result = engine.start(begin, end, timeout_ms=timeout_ms)
            finally:
                timer.cancel()
            if _timeout_fired.is_set():
                result = {"status": "timeout", "error": f"Qiling execution exceeded {QILING_TIMEOUT_S}s wall-clock timeout"}
        else:
            result = engine.start(begin, end, timeout_ms=timeout_ms)

        regs = engine.registers_read_all()
        trace_count = len(engine.trace)

        if format == "report":
            return _report_run(result, regs, trace_count)

        reg_str = "  ".join(f"{k}=0x{v:x}" for k, v in regs.items())
        return (
            f"Execution completed.\n"
            f"Result: {result}\n"
            f"Registers: {reg_str}\n"
            f"Trace entries: {trace_count}"
        )
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Execution error: {e}"


@mcp.tool()
def emu_step(session_id: str, count: int = 1) -> str:
    """Step N instructions in the emulation session.

    session_id: Active session ID.
    count: Number of instructions to step (default: 1).

    Returns the traced instructions.
    """
    try:
        engine = sessions.get(session_id)
        # EM-5: Cap step count
        if count < 1:
            return "Error: Step count must be at least 1."
        count = min(count, MAX_STEPS)
        entries = engine.step(count)
        if not entries:
            return "No instructions stepped (execution may have ended)."
        parts = [f"Stepped {len(entries)} instruction(s):\n"]
        for e in entries:
            parts.append(f"  0x{e.address:08x}: {e.instruction}")
        return "\n".join(parts)
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Step error: {e}"


@mcp.tool()
def emu_emulate_shellcode(
    arch: str,
    code_hex: str,
    base_address: str = "0x1000000",
    timeout_ms: int = 5000,
    format: str = "default",
    engine: str = "unicorn",
) -> str:
    """One-shot shellcode emulation. Creates a temporary session, runs the code, returns results.

    arch: Architecture ("x86", "x86_64", "arm", "mips", etc.)
    code_hex: Hex-encoded shellcode bytes (e.g. "90909090" for NOP sled).
    base_address: Address to load shellcode at (default: 0x1000000).
    timeout_ms: Maximum execution time (default: 5000ms).
    format: Output format - "default" for plain text, "report" for markdown tables.
    engine: CPU engine to use - "unicorn" (default), "icicle", or "angr".

    Returns: disassembly trace, final register state, and any memory changes.
    """
    if format not in ("default", "report"):
        return f"Error: Unknown format '{format}'. Use 'default' or 'report'."
    if engine not in ("unicorn", "icicle", "angr"):
        return f"Error: engine must be 'unicorn', 'icicle' or 'angr' for shellcode emulation, not '{engine}'."
    if not is_installed(engine):
        return f"Error: Engine '{engine}' is not installed. See emu_list_engines."
    engine_obj = None
    try:
        clean_hex = code_hex.replace(" ", "")
        if clean_hex.lower().startswith("0x"):
            clean_hex = clean_hex[2:]
        code = bytes.fromhex(clean_hex)
        base = _parse_addr(base_address)

        engine_obj = get_engine_class(engine)(arch=arch)
        engine = engine_obj  # the rest of this function operates on the instance
        engine.enable_tracing()

        # Write code to default code segment
        engine.memory_write(base, code)

        # Run
        result = engine.start(base, base + len(code), timeout_ms=timeout_ms)

        # Collect results
        regs = engine.registers_read_all()
        trace = engine.get_trace(limit=100)

        reg_str = "\n".join(f"  {k:>6} = 0x{v:x}" for k, v in regs.items())
        trace_str = "\n".join(
            f"  {t['address']}: {t['instruction']}"
            for t in trace
        )

        if format == "report":
            return _report_shellcode(arch, len(code), base_address, result, trace, regs)

        return (
            f"Shellcode emulation ({arch}, {len(code)} bytes at {base_address}):\n\n"
            f"Execution: {result}\n\n"
            f"Trace ({len(trace)} instructions):\n{trace_str}\n\n"
            f"Final registers:\n{reg_str}"
        )
    except Exception as e:
        return f"Shellcode emulation error: {e}"
    finally:
        # EM-7: Ensure engine cleanup even on exception
        if engine_obj is not None:
            try:
                engine_obj.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Helpers for emu_load_function
# ---------------------------------------------------------------------------

def _r2_cmd(binary_path: str, cmds: list[str]) -> str:
    """Run radare2 commands on a binary and return stdout.

    Returns empty string on timeout or unexpected errors so callers
    can fall back gracefully instead of crashing.
    """
    cmd_str = ";".join(cmds)
    try:
        result = subprocess.run(
            ["r2", "-q", "-e", "bin.cache=true", "-c", cmd_str, binary_path],
            capture_output=True, text=True, timeout=30,
        )
        return result.stdout.strip()
    except FileNotFoundError:
        raise RuntimeError("radare2 (r2) not found in PATH. Install radare2 to use emu_load_function.")
    except subprocess.TimeoutExpired:
        # subprocess.run already kills the child on timeout (Python 3.3+)
        return ""
    except Exception:
        return ""


def _detect_arch(info: dict) -> str:
    """Map radare2 binary info to emulation arch string."""
    r2_arch = info.get("arch", "")
    bits = info.get("bits", 32)
    endian = info.get("endian", "little")
    if r2_arch == "x86" and bits == 64:
        return "x86_64"
    if r2_arch == "x86":
        return "x86"
    if r2_arch == "arm" and bits == 64:
        return "arm64"
    if r2_arch == "arm":
        return "arm"
    if r2_arch == "mips" and endian == "little":
        return "mips_le"
    if r2_arch == "mips":
        return "mips"
    return r2_arch


# Calling convention argument registers per architecture
_ARG_REGS: dict[str, list[str]] = {
    "x86": ["eax", "ecx", "edx"],
    "x86_64": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    "arm": ["r0", "r1", "r2", "r3"],
    "arm_thumb": ["r0", "r1", "r2", "r3"],
    "arm64": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
    "mips": ["a0", "a1", "a2", "a3"],
    "mips_le": ["a0", "a1", "a2", "a3"],
}

# Return-0 stub bytes per architecture family
_RET0_STUBS: dict[str, bytes] = {
    # xor eax, eax; ret
    "x86": b"\x31\xc0\xc3",
    "x86_64": b"\x31\xc0\xc3",
    # mov r0, #0; bx lr
    "arm": bytes.fromhex("0000a0e31eff2fe1"),
    "arm_thumb": bytes.fromhex("0020704700"),
    # mov x0, #0; ret
    "arm64": bytes.fromhex("000080d2c0035fd6"),
    # addiu $v0, $zero, 0; jr $ra; nop (big-endian)
    "mips": bytes.fromhex("24020000" "03e00008" "00000000"),
    # addiu $v0, $zero, 0; jr $ra; nop (little-endian)
    "mips_le": bytes.fromhex("00000224" "0800e003" "00000000"),
}


@mcp.tool()
def emu_load_function(
    binary_path: str,
    function_address: str,
    arch: str = "",
    args: list[str] | None = None,
    data_at: dict[str, str] | None = None,
    stub_imports: bool = True,
    enable_trace: bool = True,
    label: str = "",
    engine: str = "unicorn",
) -> str:
    """Load a function from a binary into a ready-to-run CPU emulation session.

    binary_path: Path to ELF/PE binary.
    function_address: Hex address of the function (e.g. "0xaf188"). Uses radare2 addresses.
    arch: Architecture override. Auto-detected if empty. Options: x86, x86_64, arm, mips, mips_le, etc.
    args: List of argument values as hex strings, mapped to arch calling convention registers.
    data_at: Dict mapping hex addresses to hex data to pre-load (e.g. {"0x2000000": "48656c6c6f00"}).
    stub_imports: If True, detect external calls (PLT/GOT) and stub them with ret-0.
    enable_trace: If True, enable instruction tracing from the start.
    label: Optional session label.
    engine: CPU engine for the session - "unicorn" (default) or "icicle".

    Returns session_id and setup summary. Use emu_run() with the returned addresses to execute.
    """
    if engine not in ("unicorn", "icicle"):
        return f"Error: emu_load_function supports 'unicorn' or 'icicle', not '{engine}'."
    if not is_installed(engine):
        return f"Error: Engine '{engine}' is not installed. See emu_list_engines."
    try:
        # EM-1: Validate binary path (raises ValueError if disallowed)
        _validate_binary_path(binary_path)

        # EM-2: Enforce session count limit
        if len(sessions.list_sessions()) >= MAX_SESSIONS:
            return f"Error: Maximum session limit ({MAX_SESSIONS}) reached. Close existing sessions first."

        func_addr_str = function_address.strip()

        # Validate address to prevent r2 command injection (r2 supports !shell_cmd)
        if not re.match(r'^(0x)?[0-9a-fA-F]+$', func_addr_str):
            return f"Error: Invalid function address '{func_addr_str}'. Must be a hex address (e.g. '0xaf188')."

        # ---------------------------------------------------------------
        # 1. Binary analysis with radare2
        # ---------------------------------------------------------------

        # Get binary info for arch detection + function metadata in ONE r2 call
        # r2 outputs: iIj JSON, then separator, then afij JSON
        batch1_cmds = [
            "iIj",
            f'echo "---FUNC_INFO---"',
            f"s {func_addr_str}",
            "af",
            "afij",
        ]
        batch1_raw = _r2_cmd(binary_path, batch1_cmds)

        # Split by marker
        if "---FUNC_INFO---" in batch1_raw:
            info_raw, func_raw = batch1_raw.split("---FUNC_INFO---", 1)
            info_raw = info_raw.strip()
            func_raw = func_raw.strip()
        else:
            # Fallback: treat entire output as info
            info_raw = batch1_raw
            func_raw = ""

        try:
            info_json = json.loads(info_raw)
        except json.JSONDecodeError:
            return f"Error: Failed to parse radare2 binary info. Raw output:\n{info_raw[:500]}"

        bin_info = info_json.get("bin", info_json)
        detected_arch = _detect_arch(bin_info)
        emu_arch = arch if arch else detected_arch
        if not emu_arch:
            return f"Error: Could not detect architecture. Specify arch= manually. r2 info: {bin_info}"

        # Parse function info from batch output
        func_size = 4096  # fallback
        func_name = f"fcn_{func_addr_str}"

        try:
            func_list = json.loads(func_raw)
            if isinstance(func_list, list) and len(func_list) > 0:
                fi = func_list[0]
                func_size = fi.get("size", 4096)
                func_name = fi.get("name", func_name)
        except json.JSONDecodeError:
            pass  # use fallback size

        if func_size <= 0:
            func_size = 4096

        # Get function bytes + xrefs in ONE r2 call (saves a full r2 startup + analysis)
        batch2_cmds = [
            f"s {func_addr_str}",
            "af",
            f"p8 {func_size}",
        ]
        if stub_imports:
            batch2_cmds.append(f'echo "---XREFS---"')
            batch2_cmds.append("afxj")

        batch2_raw = _r2_cmd(binary_path, batch2_cmds)

        # Split bytes from xrefs if present
        xrefs_raw_prefetched = ""
        if "---XREFS---" in batch2_raw:
            bytes_raw, xrefs_raw_prefetched = batch2_raw.split("---XREFS---", 1)
            bytes_raw = bytes_raw.strip()
            xrefs_raw_prefetched = xrefs_raw_prefetched.strip()
        else:
            bytes_raw = batch2_raw

        # p8 returns plain hex string
        hex_clean = bytes_raw.replace("\n", "").replace(" ", "").strip()
        if not hex_clean or not all(c in "0123456789abcdefABCDEF" for c in hex_clean):
            return f"Error: Failed to read function bytes at {func_addr_str}. r2 output:\n{bytes_raw[:500]}"

        func_bytes = bytes.fromhex(hex_clean)
        actual_size = len(func_bytes)

        # ---------------------------------------------------------------
        # 2. Create Unicorn session
        # ---------------------------------------------------------------
        engine = get_engine_class(engine)(arch=emu_arch)
        if enable_trace:
            engine.enable_tracing()

        # Map data region
        engine.memory_map(DATA_BASE, DATA_SIZE, 7)

        # ---------------------------------------------------------------
        # 3. Write function code
        # ---------------------------------------------------------------
        code_start = CODE_BASE
        engine.memory_write(code_start, func_bytes)
        code_end = code_start + actual_size

        # ---------------------------------------------------------------
        # 4. Set up return address (LR / stack)
        # ---------------------------------------------------------------
        # Write a return address that will cause clean stop
        ret_addr = code_end  # emulation will stop here
        if emu_arch in ("arm", "arm_thumb", "arm64"):
            engine.register_write("lr", ret_addr)
        elif emu_arch in ("mips", "mips_le"):
            engine.register_write("ra", ret_addr)
        elif emu_arch in ("x86", "x86_64"):
            # Push return address onto stack
            sp_reg = "esp" if emu_arch == "x86" else "rsp"
            sp = engine.register_read(sp_reg)
            addr_size = 4 if emu_arch == "x86" else 8
            sp -= addr_size
            engine.register_write(sp_reg, sp)
            engine.memory_write(sp, ret_addr.to_bytes(addr_size, byteorder="little"))

        # ---------------------------------------------------------------
        # 5. Stub external calls (PLT/GOT)
        # ---------------------------------------------------------------
        stubs_created = 0
        stub_details: list[str] = []
        if stub_imports:
            try:
                # Use prefetched xrefs from batch2 call (no extra r2 subprocess)
                xrefs = json.loads(xrefs_raw_prefetched) if xrefs_raw_prefetched else []
                if isinstance(xrefs, list):
                    stub_code = _RET0_STUBS.get(emu_arch, b"")
                    if stub_code:
                        orig_func_addr = _parse_addr(func_addr_str)
                        seen_targets: set[int] = set()
                        for xref in xrefs:
                            xref_type = xref.get("type", "")
                            xref_to = xref.get("to", 0)
                            if xref_type in ("CALL", "call", "C") and xref_to:
                                # Only stub targets outside our function
                                if xref_to < orig_func_addr or xref_to >= orig_func_addr + actual_size:
                                    seen_targets.add(xref_to)

                        for target in sorted(seen_targets):
                            # Rebase: original func_addr -> CODE_BASE
                            target_offset = target - orig_func_addr + CODE_BASE
                            if CODE_BASE <= target_offset < CODE_BASE + CODE_SIZE:
                                engine.memory_write(target_offset, stub_code)
                                stubs_created += 1
                                stub_details.append(f"0x{target:x} -> stub@0x{target_offset:x}")
                            else:
                                # Map a new page for the stub
                                page_addr = (target_offset >> 12) << 12
                                try:
                                    engine.memory_map(page_addr, 0x1000, 7)
                                    engine.memory_write(target_offset, stub_code)
                                    stubs_created += 1
                                    stub_details.append(f"0x{target:x} -> stub@0x{target_offset:x} (new map)")
                                except Exception:
                                    stub_details.append(f"0x{target:x} -> FAILED to map stub")
            except (json.JSONDecodeError, RuntimeError):
                stub_details.append("Warning: Could not parse xrefs for stub creation")

        # ---------------------------------------------------------------
        # 6. Write user data
        # ---------------------------------------------------------------
        data_written: list[str] = []
        for addr_str, hex_data in (data_at or {}).items():
            da = _parse_addr(addr_str)
            clean = hex_data.replace(" ", "")
            if clean.lower().startswith("0x"):
                clean = clean[2:]
            data = bytes.fromhex(clean)
            try:
                engine.memory_write(da, data)
                data_written.append(f"0x{da:x}: {len(data)} bytes")
            except Exception as e:
                data_written.append(f"0x{da:x}: FAILED ({e})")

        # ---------------------------------------------------------------
        # 7. Set up arguments
        # ---------------------------------------------------------------
        args_set: list[str] = []
        if args is not None and len(args) > 0:
            arg_regs = _ARG_REGS.get(emu_arch, [])
            for i, arg_val in enumerate(args):
                if i >= len(arg_regs):
                    args_set.append(f"arg{i}: SKIPPED (no register, would need stack)")
                    break
                val = _parse_addr(arg_val)
                reg_name = arg_regs[i]
                engine.register_write(reg_name, val)
                args_set.append(f"{reg_name}=0x{val:x}")

        # ---------------------------------------------------------------
        # 8. Register session and return summary
        # ---------------------------------------------------------------
        session_label = label or f"func:{func_name}@{func_addr_str}"
        session_id = sessions.create_session(engine, label=session_label)

        summary_parts = [
            f"Session created: {session_id}",
            f"Architecture: {emu_arch} (detected: {detected_arch})",
            f"Function: {func_name} at {func_addr_str}",
            f"Function size: {actual_size} bytes",
            f"Code loaded at: 0x{code_start:x} - 0x{code_end:x}",
            f"Run with: emu_run(session_id=\"{session_id}\", start_addr=\"0x{code_start:x}\", end_addr=\"0x{code_end:x}\")",
        ]
        if stubs_created:
            summary_parts.append(f"Import stubs: {stubs_created} created")
            for s in stub_details:
                summary_parts.append(f"  {s}")
        elif stub_imports:
            summary_parts.append("Import stubs: 0 (no external calls found or stubbing skipped)")
        if args_set:
            summary_parts.append(f"Arguments: {', '.join(args_set)}")
        if data_written:
            summary_parts.append(f"Data written: {', '.join(data_written)}")
        summary_parts.append(f"Data region: 0x{DATA_BASE:x} - 0x{DATA_BASE + DATA_SIZE:x} (available for buffers)")
        summary_parts.append(f"Stack top: 0x{STACK_TOP:x}")
        if enable_trace:
            summary_parts.append("Tracing: enabled")

        return "\n".join(summary_parts)

    except RuntimeError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error loading function: {e}"


# ===========================================================================
# Memory Tools
# ===========================================================================

@mcp.tool()
def emu_memory_read(session_id: str, address: str, size: int = 64, format: str = "default") -> str:
    """Read memory from an emulation session.

    session_id: Active session ID.
    address: Hex address to read from (e.g. "0x1000000").
    size: Number of bytes to read (default: 64, max: 4096).
    format: Output format - "default" for hex dump, "report" for markdown with analysis.

    Returns hex dump of memory.
    """
    if format not in ("default", "report"):
        return f"Error: Unknown format '{format}'. Use 'default' or 'report'."
    try:
        engine = sessions.get(session_id)
        addr = _parse_addr(address)
        # EM-4: Reject non-positive size
        if size <= 0:
            return "Error: size must be greater than 0."
        size = min(size, 4096)
        data = engine.memory_read(addr, size)

        if format == "report":
            return _report_memory(data, addr)

        return _hex_dump(data, addr)
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Memory read error: {e}"


@mcp.tool()
def emu_memory_write(session_id: str, address: str, data_hex: str) -> str:
    """Write data to memory in an emulation session.

    session_id: Active session ID.
    address: Hex address to write to (e.g. "0x1000000").
    data_hex: Hex-encoded bytes to write (e.g. "41424344" or "90 90 cc").
    """
    try:
        engine = sessions.get(session_id)
        addr = _parse_addr(address)
        clean_hex = data_hex.replace(" ", "")
        if clean_hex.lower().startswith("0x"):
            clean_hex = clean_hex[2:]
        data = bytes.fromhex(clean_hex)
        # EM-4: Reject empty writes
        if len(data) == 0:
            return "Error: data must not be empty."
        engine.memory_write(addr, data)
        return f"Wrote {len(data)} bytes to 0x{addr:x}."
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Memory write error: {e}"


@mcp.tool()
def emu_memory_map(session_id: str, address: str, size: int, perms: int = 7) -> str:
    """Map a new memory region in an emulation session.

    session_id: Active session ID.
    address: Start address (hex, must be page-aligned).
    size: Size in bytes (will be rounded up to page size).
    perms: Permission bitmask (7=rwx, 5=rx, 3=rw, 1=r). Default: 7.
    """
    try:
        engine = sessions.get(session_id)
        addr = _parse_addr(address)
        # EM-4: Reject non-positive sizes
        if size <= 0:
            return "Error: size must be positive."
        # EM-3: Reject oversized mappings
        if size > MAX_MEMORY_MAP_SIZE:
            return f"Error: size {size} exceeds maximum ({MAX_MEMORY_MAP_SIZE} bytes / 256 MB)."
        engine.memory_map(addr, size, perms)
        return f"Mapped 0x{size:x} bytes at 0x{addr:x} (perms={perms})."
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Memory map error: {e}"


@mcp.tool()
def emu_memory_unmap(session_id: str, address: str, size: int) -> str:
    """Unmap a memory region (Icicle sessions; 'memory_management' capability).

    session_id: Active session ID.
    address: Start address (hex, page-aligned).
    size: Size in bytes to unmap.
    """
    try:
        engine = sessions.get(session_id)
        addr = _parse_addr(address)
        if size <= 0:
            return "Error: size must be positive."
        engine.memory_unmap(addr, size)
        return f"Unmapped 0x{size:x} bytes at 0x{addr:x}."
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Memory unmap error: {e}"


@mcp.tool()
def emu_memory_protect(session_id: str, address: str, size: int, perms: int) -> str:
    """Change guest page permissions for a region ('memory_management' capability).

    Affects accesses made by the *emulated* code (e.g. to trigger a write or
    exec violation); the memory read/write tools bypass these permissions.

    session_id: Active session ID.
    address: Start address (hex, page-aligned).
    size: Size in bytes.
    perms: Permission bitmask (7=rwx, 5=rx, 4=r, 6=rw, 1=x).
    """
    try:
        engine = sessions.get(session_id)
        addr = _parse_addr(address)
        if size <= 0:
            return "Error: size must be positive."
        engine.memory_protect(addr, size, perms)
        return f"Set perms={perms} on 0x{size:x} bytes at 0x{addr:x}."
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Memory protect error: {e}"


@mcp.tool()
def emu_memory_search(session_id: str, pattern_hex: str) -> str:
    """Search all mapped memory for a byte pattern.

    session_id: Active session ID.
    pattern_hex: Hex-encoded pattern to search for (e.g. "deadbeef").

    Returns list of addresses where the pattern was found.
    """
    try:
        engine = sessions.get(session_id)
        clean_hex = pattern_hex.replace(" ", "")
        if clean_hex.lower().startswith("0x"):
            clean_hex = clean_hex[2:]
        pattern = bytes.fromhex(clean_hex)
        addrs = engine.memory_search(pattern)
        if not addrs:
            return "Pattern not found in mapped memory."
        lines = [f"Found {len(addrs)} match(es):"]
        for a in addrs[:50]:  # Limit output
            lines.append(f"  0x{a:08x}")
        if len(addrs) > 50:
            lines.append(f"  ... and {len(addrs) - 50} more")
        return "\n".join(lines)
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Memory search error: {e}"


# ===========================================================================
# Register Tools
# ===========================================================================

@mcp.tool()
def emu_registers_read(session_id: str, names: list[str] | None = None, format: str = "default") -> str:
    """Read registers from an emulation session.

    session_id: Active session ID.
    names: Optional list of specific register names. If empty, reads all GP registers.
    format: Output format - "default" for plain text, "report" for markdown table (omits zero registers).

    Returns register names and values.
    """
    if format not in ("default", "report"):
        return f"Error: Unknown format '{format}'. Use 'default' or 'report'."
    try:
        engine = sessions.get(session_id)
        if names:
            regs = {}
            for name in names:
                regs[name] = engine.register_read(name)
        else:
            regs = engine.registers_read_all()

        if format == "report":
            return _report_registers(regs)

        lines = [f"Registers ({len(regs)}):"]
        for k, v in regs.items():
            lines.append(f"  {k:>8} = 0x{v:016x}  ({v})")
        return "\n".join(lines)
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Register read error: {e}"


@mcp.tool()
def emu_register_write(session_id: str, name: str, value: str) -> str:
    """Write a value to a register.

    session_id: Active session ID.
    name: Register name (e.g. "rax", "r0", "sp").
    value: Value to write (hex or decimal, e.g. "0xdeadbeef" or "42").
    """
    try:
        engine = sessions.get(session_id)
        val = _parse_addr(value)
        engine.register_write(name, val)
        readback = engine.register_read(name)
        return f"Set {name} = 0x{val:x} (readback: 0x{readback:x})"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Register write error: {e}"


# ===========================================================================
# Hook Tools
# ===========================================================================

@mcp.tool()
def emu_hook_address(session_id: str, address: str, description: str = "") -> str:
    """Install a hook at a specific address. When execution reaches this address, it will be logged in the trace.

    session_id: Active session ID.
    address: Hex address to hook (e.g. "0x401234").
    description: Optional description of what this hook is for.
    """
    try:
        engine = sessions.get(session_id)
        addr = _parse_addr(address)
        hook_id = engine.hook_address(addr)
        if description:
            engine.hooks[hook_id].description = description
        return f"Hook installed: {hook_id} at 0x{addr:x}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Hook error: {e}"


@mcp.tool()
def emu_hook_syscall(session_id: str, syscall_name: str, description: str = "",
                     when: str = "call") -> str:
    """Hook a syscall by name. Qiling sessions only.

    session_id: Active session ID.
    syscall_name: Name of the syscall (e.g. "write", "open", "execve", "system").
    description: Optional description.
    when: "call" replaces the syscall; "enter"/"exit" observe it around the real
      handler (behaviour stays intact). Default "call".

    The hooked syscall will be logged in the trace with arguments.
    """
    try:
        engine = sessions.get(session_id)
        if not engine.has_capability("syscall_hooks"):
            return f"Error: Syscall hooks are not supported by the '{engine.engine_type}' engine (Qiling only)."
        hook_id = engine.hook_syscall(syscall_name, when=when)
        if description:
            engine.hooks[hook_id].description = description
        return f"Syscall hook installed: {hook_id} for '{syscall_name}' ({when})"
    except ValueError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Syscall hook error: {e}"


@mcp.tool()
def emu_hook_api(session_id: str, api_name: str, description: str = "",
                 when: str = "call") -> str:
    """Hook a library API call by name. Qiling sessions only.

    session_id: Active session ID.
    api_name: Function name (e.g. "system", "printf", "strcpy", "popen").
    description: Optional description.
    when: "call" replaces the function; "enter"/"exit" observe it around the real
      implementation. Default "call".

    The hooked API call will be logged in the trace with arguments.
    """
    try:
        engine = sessions.get(session_id)
        if not engine.has_capability("api_hooks"):
            return f"Error: API hooks are not supported by the '{engine.engine_type}' engine (Qiling only)."
        hook_id = engine.hook_api(api_name, when=when)
        if description:
            engine.hooks[hook_id].description = description
        return f"API hook installed: {hook_id} for '{api_name}' ({when})"
    except ValueError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"API hook error: {e}"


@mcp.tool()
def emu_list_hooks(session_id: str, format: str = "default") -> str:
    """List all active hooks in a session.

    session_id: Active session ID.
    format: Output format - "default" for plain text, "report" for markdown table.
    """
    if format not in ("default", "report"):
        return f"Error: Unknown format '{format}'. Use 'default' or 'report'."
    try:
        engine = sessions.get(session_id)
        hooks = engine.list_hooks()
        if not hooks:
            return "No active hooks."

        if format == "report":
            return _report_hooks(hooks)

        lines = [f"Active hooks ({len(hooks)}):"]
        for h in hooks:
            desc = f" - {h['description']}" if h['description'] else ""
            lines.append(f"  {h['hook_id']} | {h['type']} | {h['target']}{desc}")
        return "\n".join(lines)
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"List hooks error: {e}"


@mcp.tool()
def emu_remove_hook(session_id: str, hook_id: str) -> str:
    """Remove a hook from a session.

    session_id: Active session ID.
    hook_id: The hook ID returned by emu_hook_*.
    """
    try:
        engine = sessions.get(session_id)
        if engine.hook_remove(hook_id):
            return f"Hook {hook_id} removed."
        return f"Hook {hook_id} not found."
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Remove hook error: {e}"


# ===========================================================================
# Breakpoints & register introspection
# ===========================================================================

@mcp.tool()
def emu_breakpoint_add(session_id: str, address: str) -> str:
    """Set an execution breakpoint that halts a run for inspection ('breakpoints').

    Unlike an address hook (which observes and continues), a breakpoint stops
    the run; emu_run reports status "breakpoint". Resume by calling emu_run
    again with start_addr set to the current pc, or emu_step.

    session_id: Active session ID.
    address: Hex address to break on.
    """
    try:
        engine = sessions.get(session_id)
        addr = _parse_addr(address)
        engine.breakpoint_add(addr)
        return f"Breakpoint set at 0x{addr:x}."
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Breakpoint error: {e}"


@mcp.tool()
def emu_breakpoint_remove(session_id: str, address: str) -> str:
    """Remove an execution breakpoint ('breakpoints' capability).

    session_id: Active session ID.
    address: Hex address of the breakpoint to remove.
    """
    try:
        engine = sessions.get(session_id)
        addr = _parse_addr(address)
        if engine.breakpoint_remove(addr):
            return f"Breakpoint at 0x{addr:x} removed."
        return f"No breakpoint at 0x{addr:x}."
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Breakpoint error: {e}"


@mcp.tool()
def emu_list_registers(session_id: str) -> str:
    """List every register the engine exposes ('register_introspection').

    Icicle enumerates the full SLEIGH register file with byte offset and size
    (hundreds of entries, including vector/flag/system registers); Qiling
    enumerates its architecture register map with each register's current value.
    Read any of them by name with emu_registers_read.

    session_id: Active session ID.
    """
    try:
        engine = sessions.get(session_id)
        regs = engine.list_registers()
        lines = [f"Registers ({len(regs)}):"]
        for name in sorted(regs, key=lambda n: regs[n].get("offset", 0)):
            meta = regs[name]
            parts = []
            if "value" in meta:
                parts.append(f"value=0x{meta['value']:x}")
            if "offset" in meta:
                parts.append(f"offset={meta['offset']}")
            if "size" in meta:
                parts.append(f"size={meta['size']}")
            lines.append(f"  {name:<12} {' '.join(parts)}")
        return "\n".join(lines)
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"List registers error: {e}"


@mcp.tool()
def emu_register_read_wide(session_id: str, name: str) -> str:
    """Read a register wider than 64 bits as raw bytes ('wide_registers').

    For vector/flag aggregate registers (XMM/YMM/ZMM, ...) that don't fit in an
    integer. Returns little-endian hex.

    session_id: Active session ID.
    name: Register name (e.g. "xmm0").
    """
    try:
        engine = sessions.get(session_id)
        data = engine.register_read_bytes(name)
        return f"{name} = {data.hex()} ({len(data)} bytes, little-endian)"
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Wide register read error: {e}"


@mcp.tool()
def emu_register_write_wide(session_id: str, name: str, data_hex: str) -> str:
    """Write raw bytes to a register wider than 64 bits ('wide_registers').

    session_id: Active session ID.
    name: Register name (e.g. "xmm0").
    data_hex: Little-endian hex bytes (padded/truncated to the register width).
    """
    try:
        engine = sessions.get(session_id)
        clean = data_hex.replace(" ", "")
        if clean.lower().startswith("0x"):
            clean = clean[2:]
        data = bytes.fromhex(clean)
        if not data:
            return "Error: data must not be empty."
        engine.register_write_bytes(name, data)
        return f"Wrote {len(data)} bytes to {name}."
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Wide register write error: {e}"


# ===========================================================================
# Reverse execution, introspection & Linux mode (extended Icicle binding)
# ===========================================================================

@mcp.tool()
def emu_step_back(session_id: str, count: int = 1) -> str:
    """Reverse-execute: rewind `count` instructions ('reverse_execution').

    Requires the extended Icicle binding (icicle_ext/). The engine keeps a
    checkpoint at the start of the session and re-derives the earlier state.

    session_id: Active session ID.
    count: Number of instructions to step backward (default 1).
    """
    try:
        engine = sessions.get(session_id)
        if count < 1:
            return "Error: count must be at least 1."
        result = engine.step_back(count)
        return (f"Stepped back {count}. Now at icount={result['icount']}, pc={result['pc']} "
                f"(status {result['status']}).")
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Step back error: {e}"


@mcp.tool()
def emu_goto_icount(session_id: str, target: int) -> str:
    """Time-travel to an absolute instruction count ('reverse_execution').

    Forwards or backwards; requires the extended Icicle binding.

    session_id: Active session ID.
    target: The instruction count to travel to.
    """
    try:
        engine = sessions.get(session_id)
        if target < 0:
            return "Error: target must be non-negative."
        result = engine.goto_icount(target)
        return (f"At icount={result['icount']}, pc={result['pc']} (status {result['status']}).")
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Goto icount error: {e}"


@mcp.tool()
def emu_callstack(session_id: str) -> str:
    """Show the current return-address call stack ('callstack' capability).

    session_id: Active session ID.
    """
    try:
        engine = sessions.get(session_id)
        stack = engine.get_callstack()
        if not stack:
            return "Call stack is empty."
        lines = [f"Call stack ({len(stack)} frames, innermost last):"]
        for i, addr in enumerate(stack):
            lines.append(f"  #{i}: 0x{addr:x}")
        return "\n".join(lines)
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Callstack error: {e}"


@mcp.tool()
def emu_disassemble(session_id: str, address: str, count: int = 10) -> str:
    """Disassemble instructions using the engine's native semantics.

    Icicle ('disassembly' capability) uses SLEIGH directly, so no external
    disassembler is required and the output matches what the emulator executes.

    session_id: Active session ID.
    address: Hex address to disassemble from.
    count: Number of instructions (default 10).
    """
    try:
        engine = sessions.get(session_id)
        addr = _parse_addr(address)
        if count < 1:
            return "Error: count must be at least 1."
        insns = engine.disassemble(addr, count)
        if not insns:
            return f"Could not disassemble at 0x{addr:x} (unmapped or undecodable)."
        lines = [f"Disassembly at 0x{addr:x} ({len(insns)} instructions):"]
        for i in insns:
            lines.append(f"  {i['address']}: {i['instruction']}")
        return "\n".join(lines)
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Disassemble error: {e}"


@mcp.tool()
def emu_pcode(session_id: str, address: str) -> str:
    """Lift a block to p-code IL ('pcode_il' capability, extended Icicle).

    Returns the SLEIGH p-code — the intermediate language the emulator actually
    executes — for the basic block at `address`, with the original instructions
    interleaved. This is the semantic IR behind the disassembly, useful for
    taint, symbolic reasoning, and semantic diffing.

    session_id: Active session ID.
    address: Hex address of the block.
    """
    try:
        engine = sessions.get(session_id)
        return engine.get_pcode(_parse_addr(address))
    except NotImplementedError as e:
        return f"Error: {e}"
    except ValueError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"P-code error: {e}"


@mcp.tool()
def emu_cmplog(session_id: str, action: str = "get", instrument_calls: bool = False) -> str:
    """Record or read compare operands — RedQueen / input-to-state ('cmplog').

    Instrument comparisons so that, during a run, the concrete operand pairs seen
    at each compare are captured. This tells a fuzzer exactly which bytes a
    magic-value or checksum check wants. Enable it, run, then read.

    session_id: Active session ID.
    action: "enable" to install instrumentation (before running), "get" to read
      the observed compares (default), "clear" to reset the recorded operands.
    instrument_calls: with action="enable", also log memcmp/strcmp-style calls.

    Note: a compare whose operands are both statically constant in their block is
    dropped as uninteresting — the useful case has a runtime/input-derived side.
    """
    try:
        engine = sessions.get(session_id)
        if action == "enable":
            engine.enable_cmplog(instrument_calls)
            return "Compare logging enabled. Run the program, then call with action='get'."
        if action == "clear":
            engine.clear_cmplog()
            return "Compare log cleared."
        if action == "get":
            entries = engine.get_cmplog()
            if not entries:
                return "No compares recorded (enable before running; a runtime-derived operand is needed)."
            lines = [f"Compares observed ({len(entries)} sites):"]
            for e in entries[:200]:
                ops = ", ".join(f"({a:#x} vs {b:#x})" for a, b in e["operands"][:8])
                lines.append(f"  {e['address']} {e['kind']}: {ops}")
            return "\n".join(lines)
        return "Error: action must be 'enable', 'get', or 'clear'."
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Cmplog error: {e}"


@mcp.tool()
def emu_load_symbols(session_id: str, path: str, load_address: str = "0x0") -> str:
    """Load an ELF's symbols for symbolization ('symbols', extended Icicle).

    Reads the symbol table (and DWARF line info, if present) from the ELF at
    `path` so addresses can be resolved to names and back. Call it for each
    binary/library you want named.

    session_id: Active session ID.
    path: Host path to the ELF.
    load_address: Relocation base for PIE/dynamic objects (ignored for static /
      non-PIE). Hex or decimal.
    """
    try:
        engine = sessions.get(session_id)
        n = engine.load_symbols(path, _parse_addr(load_address))
        return f"Loaded {n} symbols from {path}."
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Load symbols error: {e}"


@mcp.tool()
def emu_symbolize(session_id: str, address: str) -> str:
    """Resolve an address to a symbol ('symbols', extended Icicle).

    Returns the covering symbol as `name+0xoffset` (and a DWARF source location
    when available). Load symbols first with emu_load_symbols.

    session_id: Active session ID.
    address: Hex address to resolve.
    """
    try:
        engine = sessions.get(session_id)
        addr = _parse_addr(address)
        res = engine.symbolize(addr)
        if res is None:
            return f"0x{addr:x}: no symbol (load symbols first, or address is unmapped)."
        off = f"+0x{res['offset']:x}" if res["offset"] else ""
        src = f"  [{res['source']}]" if res.get("source") else ""
        return f"0x{addr:x}: {res['name']}{off}{src}"
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Symbolize error: {e}"


@mcp.tool()
def emu_lookup_symbol(session_id: str, name: str) -> str:
    """Resolve a symbol name to its address ('symbols', extended Icicle).

    session_id: Active session ID.
    name: Symbol name (e.g. "main", "strcmp").
    """
    try:
        engine = sessions.get(session_id)
        addr = engine.lookup_symbol(name)
        if addr is None:
            return f"Symbol '{name}' not found (load symbols first)."
        return f"{name} = 0x{addr:x}"
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Lookup symbol error: {e}"


@mcp.tool()
def emu_list_symbols(session_id: str, filter: str = "", limit: int = 100) -> str:
    """List loaded symbols ('symbols', extended Icicle).

    session_id: Active session ID.
    filter: Case-insensitive substring to match symbol names (empty = all).
    limit: Max symbols to list (default 100).
    """
    try:
        engine = sessions.get(session_id)
        syms = engine.list_symbols()
        if filter:
            f = filter.lower()
            syms = [s for s in syms if f in s["name"].lower()]
        syms.sort(key=lambda s: int(s["address"], 16))
        lines = [f"Symbols ({len(syms)}" + (f" matching '{filter}'" if filter else "") + "):"]
        for s in syms[:limit]:
            lines.append(f"  {s['address']} {s['name']} (size {s['size']}, {s['kind']})")
        if len(syms) > limit:
            lines.append(f"  ... and {len(syms) - limit} more")
        return "\n".join(lines)
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"List symbols error: {e}"


@mcp.tool()
def emu_modules(session_id: str) -> str:
    """List the modules loaded in the guest (Sogen).

    Shows each loaded module (the executable and its shared objects/DLLs) with
    its image base, entry point, size and export count — useful to see what the
    loader brought in and where it landed. Run the program first so the loader
    has mapped its libraries.

    session_id: Active session ID.
    """
    try:
        engine = sessions.get(session_id)
        mods = engine.list_modules()
        if not mods:
            return "No modules loaded (run the program first)."
        lines = [f"Modules ({len(mods)}):"]
        for m in mods:
            base = m.get("image_base")
            base_s = f"0x{base:x}" if isinstance(base, int) else str(base)
            lines.append(f"  {base_s}  {m.get('name','')}  "
                         f"(exports {m.get('exports', 0)}, size {m.get('size')})")
        return "\n".join(lines)
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Modules error: {e}"


@mcp.tool()
def emu_memory_maps(session_id: str) -> str:
    """List the guest's mapped memory regions (Qiling).

    Shows each region's range, permissions and label/path — useful to see where
    the binary, stack, heap and shared objects landed.

    session_id: Active session ID.
    """
    try:
        engine = sessions.get(session_id)
        maps = engine.memory_maps()
        if not maps:
            return "No mapped regions."
        lines = [f"Memory maps ({len(maps)}):"]
        for m in maps:
            label = m["label"] + (f" {m['path']}" if m.get("path") else "")
            lines.append(f"  0x{m['start']:x}-0x{m['end']:x} {m['perms']:<4} {label}")
        return "\n".join(lines)
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Memory maps error: {e}"


@mcp.tool()
def emu_read_string(session_id: str, address: str, max_len: int = 1024) -> str:
    """Read a NUL-terminated string from guest memory (Qiling).

    session_id: Active session ID.
    address: Hex address of the string.
    max_len: Maximum bytes to scan for the terminator (default 1024).
    """
    try:
        engine = sessions.get(session_id)
        s = engine.read_string(_parse_addr(address), max_len)
        return f"0x{_parse_addr(address):x}: {s!r}"
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Read string error: {e}"


@mcp.tool()
def emu_fs_map(session_id: str, guest_path: str, host_path: str) -> str:
    """Map a host file/directory into the emulated filesystem ('filesystem', Qiling).

    When the guest opens `guest_path`, it sees the contents of `host_path`. Use it
    to supply inputs, config, device nodes, or a flag file the target reads.

    session_id: Active session ID.
    guest_path: Path inside the emulated FS (e.g. "/flag.txt", "/etc/passwd").
    host_path: Real path on this machine to serve for it.
    """
    try:
        engine = sessions.get(session_id)
        engine.add_fs_mapper(guest_path, host_path)
        return f"Mapped guest '{guest_path}' -> host '{host_path}'."
    except NotImplementedError as e:
        return f"Error: {e}"
    except FileNotFoundError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Filesystem map error: {e}"


@mcp.tool()
def emu_set_stdin(session_id: str, data: str, is_hex: bool = False) -> str:
    """Preload the guest's standard input ('io' capability, Qiling).

    session_id: Active session ID.
    data: Input to feed. UTF-8 text by default; set is_hex=true to pass raw bytes
      as a hex string.
    """
    try:
        engine = sessions.get(session_id)
        payload = bytes.fromhex(data) if is_hex else data.encode("utf-8")
        engine.set_stdin(payload)
        return f"stdin preloaded with {len(payload)} bytes."
    except NotImplementedError as e:
        return f"Error: {e}"
    except ValueError as e:
        return f"Error: invalid hex input: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"set stdin error: {e}"


@mcp.tool()
def emu_capture_output(session_id: str, action: str = "start") -> str:
    """Capture the guest's stdout/stderr ('io' capability, Qiling).

    Call with action="start" BEFORE emu_run, then action="get" afterward to read
    what the program printed.

    session_id: Active session ID.
    action: "start" to begin capturing, "get" to read what was captured.
    """
    try:
        engine = sessions.get(session_id)
        if action == "start":
            engine.capture_output()
            return "Output capture started. Run the program, then call with action='get'."
        if action == "get":
            out = engine.get_output()
            return (f"--- stdout ---\n{out['stdout']}\n"
                    f"--- stderr ---\n{out['stderr']}")
        return "Error: action must be 'start' or 'get'."
    except NotImplementedError as e:
        return f"Error: {e}"
    except RuntimeError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Capture output error: {e}"


@mcp.tool()
def emu_syscall_stats(session_id: str, limit: int = 40) -> str:
    """Show syscall usage counts after a run (Qiling).

    Reports how many times each syscall was invoked and a sample of strings the
    program passed to the OS — a quick behavioural fingerprint. Run the program
    first.

    session_id: Active session ID.
    limit: Max syscalls to list (default 40).
    """
    try:
        engine = sessions.get(session_id)
        r = engine.syscall_stats()
        sys = r.get("syscalls", {})
        if not sys:
            return "No syscalls recorded (run the program first)."
        items = sorted(sys.items(), key=lambda kv: kv[1], reverse=True)
        lines = [f"Syscalls ({r.get('total', sum(sys.values()))} total, {len(sys)} distinct):"]
        for name, count in items[:limit]:
            lines.append(f"  {count:>6}  {name}")
        strings = r.get("strings") or []
        if strings:
            lines.append(f"Observed strings ({len(strings)}): "
                         + ", ".join(repr(s) for s in strings[:8]))
        return "\n".join(lines)
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Syscall stats error: {e}"


@mcp.tool()
def emu_list_threads(session_id: str) -> str:
    """List the guest's threads (Qiling multithreaded runs).

    Multithreading is enabled per session with
    engine_options={"multithread": true} at creation; thread scheduling is
    best-effort. For a single-threaded program this reports that.

    session_id: Active session ID.
    """
    try:
        engine = sessions.get(session_id)
        r = engine.list_threads()
        if r.get("note"):
            return f"Threads: {r['note']} (multithread={r.get('multithread')})."
        lines = [f"Threads ({r.get('count', 0)}, current={r.get('current')}):"]
        for t in r.get("threads", []):
            lines.append(f"  id={t.get('id')} status={t.get('status')}")
        return "\n".join(lines)
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"List threads error: {e}"


@mcp.tool()
def emu_coverage(session_id: str, action: str = "get") -> str:
    """Record or read basic-block coverage ('coverage' capability).

    Coverage instruments blocks as they are lifted, so enable it before running.

    session_id: Active session ID.
    action: "enable" to start recording, "get" to read the hit blocks (default),
      "clear" to reset the set.
    """
    try:
        engine = sessions.get(session_id)
        if action == "enable":
            engine.enable_coverage()
            return "Coverage recording enabled (run the code now)."
        if action == "clear":
            engine.clear_coverage()
            return "Coverage cleared."
        if action == "get":
            blocks = engine.get_coverage()
            if not blocks:
                return "No blocks covered yet (enable coverage before running)."
            lines = [f"Covered basic blocks ({len(blocks)}):"]
            for a in blocks[:200]:
                lines.append(f"  0x{a:x}")
            if len(blocks) > 200:
                lines.append(f"  ... and {len(blocks) - 200} more")
            return "\n".join(lines)
        return f"Error: unknown action '{action}'. Use 'enable', 'get', or 'clear'."
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Coverage error: {e}"


@mcp.tool()
def emu_fuzz(
    session_id: str,
    input_addr: str,
    input_size: int,
    run_start: str,
    run_end: str = "",
    seeds_hex: list[str] | None = None,
    iterations: int = 1000,
    timeout_ms: int = 1000,
    wall_clock_s: float = 30.0,
    seed: int | None = None,
) -> str:
    """Coverage-guided fuzz a code region by mutating an input in memory.

    Each iteration restores a baseline snapshot, writes a mutated input to
    `input_addr`, runs `run_start`..`run_end`, and keeps inputs that reach new
    coverage. Inputs that fault are reported. Uses Icicle's block coverage when
    available, otherwise the instruction trace as the coverage signal.

    session_id: Active session ID (set up registers/memory and map input_addr first).
    input_addr: Hex address where the fuzzed bytes are written (must be mapped).
    input_size: Number of bytes of input.
    run_start: Hex start address for each run.
    run_end: Hex end address (empty => free run until halt/crash/budget).
    seeds_hex: Optional initial corpus as hex strings.
    iterations / wall_clock_s: stop after this many runs or this long.
    timeout_ms: Per-run execution budget.
    seed: Optional RNG seed for reproducibility.
    """
    try:
        engine = sessions.get(session_id)
        if input_size <= 0:
            return "Error: input_size must be positive."
        iaddr = _parse_addr(input_addr)
        begin = _parse_addr(run_start) if run_start else 0
        end = _parse_addr(run_end) if run_end else 0
        seeds = []
        for s in (seeds_hex or []):
            clean = s.replace(" ", "")
            if clean.lower().startswith("0x"):
                clean = clean[2:]
            seeds.append(bytes.fromhex(clean))
        iterations = min(max(iterations, 1), MAX_STEPS)
        result = fuzzing.run_fuzz(
            engine, iaddr, input_size, begin, end,
            seeds=seeds, iterations=iterations, timeout_ms=timeout_ms,
            wall_clock_s=wall_clock_s, seed=seed,
        )
        if "error" in result:
            return f"Error: {result['error']}"
        lines = [
            "### Fuzzing summary",
            f"- Coverage signal: {result['mode']}",
            f"- Executions: {result['executions']} in {result['elapsed_s']}s",
            f"- Corpus size: {result['corpus_size']}",
            f"- Coverage reached: {result['coverage']} "
            f"{'blocks' if result['mode'] == 'blocks' else 'unique PCs'}",
            f"- Inputs adding new coverage: {result['new_coverage_inputs']}",
            f"- Unique crashes: {result['unique_crashes']}",
        ]
        if result["crashes"]:
            lines.append("\n**Crashes:**")
            for c in result["crashes"]:
                lines.append(f"- input `{c['input']}` → {c['status']} "
                             f"{('at ' + c['pc']) if c.get('pc') else ''} "
                             f"{('— ' + str(c['error'])[:100]) if c.get('error') else ''}")
        return "\n".join(lines)
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Fuzz error: {type(e).__name__}: {e}"


@mcp.tool()
def emu_gdb_serve(
    session_id: str,
    address: str = "127.0.0.1:1234",
    timeout_secs: int = 120,
    background: bool = True,
) -> str:
    """Serve a GDB remote stub so a real debugger can attach ('gdb' capability).

    Attach from another terminal with:  gdb -ex "target remote <address>".

    background=True (default): the stub runs in a DETACHED SUBPROCESS seeded from
      a snapshot of the current session (all mapped memory + registers, incl.
      Linux/loader mappings), and this call returns immediately — the MCP session
      stays responsive. The subprocess waits up to `timeout_secs` for a client,
      then serves until it detaches. Use emu_gdb_stop to end it. The target is a
      memory+register copy with no live kernel, so for a Linux program you can
      inspect and single-step, but continuing through a syscall needs
      background=False.
    background=False: serve in-process (blocks this session until the client
      detaches or the wait times out), with the live kernel for Linux sessions.

    session_id: Active session ID.
    address: host:port to listen on (default 127.0.0.1:1234).
    timeout_secs: How long to wait for a client to connect.
    """
    try:
        engine = sessions.get(session_id)
        if not engine.has_capability("gdb"):
            return (f"Error: A GDB stub is not supported by the '{engine.engine_type}' engine "
                    f"(needs the extended Icicle binding, icicle_ext/).")
        if not background:
            return engine.gdb_serve(address, timeout_secs)

        # Non-blocking: dump state (incl. Linux/loader mappings via mem_map_ranges)
        # and serve from a detached subprocess.
        if getattr(engine, "_linux", False) and not hasattr(engine.vm, "mem_map_ranges"):
            return ("Error: background GDB for a Linux-mode session needs the "
                    "extended binding's mem_map_ranges(); rebuild with "
                    "icicle_ext/build.sh, or re-run with background=false.")
        if not os.path.exists(_GDB_RUNNER):
            return f"Error: GDB runner script not found at {_GDB_RUNNER}."
        _stop_gdb(session_id)  # replace any existing server for this session

        import tempfile
        import subprocess
        state = _dump_icicle_state(engine)
        fd, dump_path = tempfile.mkstemp(suffix=".json", prefix="emu_gdb_")
        with os.fdopen(fd, "w") as f:
            json.dump(state, f)
        proc = subprocess.Popen(
            [sys.executable, _GDB_RUNNER, dump_path, address, str(timeout_secs)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        _GDB_PROCS[session_id] = (proc, dump_path)
        return (
            f"GDB server started in the background (pid {proc.pid}) on {address}, "
            f"serving a snapshot of session {session_id}.\n"
            f"Attach:  gdb -ex 'target remote {address}'\n"
            f"It waits up to {timeout_secs}s for a client. Call emu_gdb_stop to end it."
        )
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"GDB serve error: {e}"


def _stop_gdb(session_id: str) -> bool:
    """Terminate a background GDB subprocess for a session, if any."""
    entry = _GDB_PROCS.pop(session_id, None)
    if entry is None:
        return False
    proc, dump_path = entry
    try:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
    except Exception:
        pass
    try:
        os.remove(dump_path)
    except OSError:
        pass
    return True


@mcp.tool()
def emu_gdb_stop(session_id: str) -> str:
    """Stop a background GDB server started by emu_gdb_serve for this session.

    session_id: Active session ID.
    """
    if _stop_gdb(session_id):
        return f"Stopped the background GDB server for session {session_id}."
    return f"No background GDB server running for session {session_id}."


# ===========================================================================
# Snapshot Tools
# ===========================================================================

@mcp.tool()
def emu_snapshot_save(session_id: str, label: str = "") -> str:
    """Save the current emulation state as a snapshot.

    session_id: Active session ID.
    label: Optional label for the snapshot.

    Use emu_snapshot_restore to return to this state later.
    """
    try:
        engine = sessions.get(session_id)
        snap_id = engine.snapshot_save(label)
        return f"Snapshot saved: {snap_id} (label: {label or 'none'})"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Snapshot save error: {e}"


@mcp.tool()
def emu_snapshot_restore(session_id: str, snapshot_id: str) -> str:
    """Restore emulation state from a previously saved snapshot.

    session_id: Active session ID.
    snapshot_id: The snapshot ID returned by emu_snapshot_save.
    """
    try:
        engine = sessions.get(session_id)
        engine.snapshot_restore(snapshot_id)
        return f"Snapshot {snapshot_id} restored. Emulation state rolled back."
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Snapshot restore error: {e}"


@mcp.tool()
def emu_snapshot_list(session_id: str) -> str:
    """List all saved snapshots for a session.

    session_id: Active session ID.
    """
    try:
        engine = sessions.get(session_id)
        snaps = engine.snapshot_list()
        if not snaps:
            return "No snapshots saved."
        lines = [f"Snapshots ({len(snaps)}):"]
        for s in snaps:
            lines.append(f"  {s['snapshot_id']} | label={s['label']} | created={s['created_at']:.0f}")
        return "\n".join(lines)
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Snapshot list error: {e}"


# ===========================================================================
# Trace / Analysis Tools
# ===========================================================================

@mcp.tool()
def emu_get_trace(session_id: str, limit: int = 200, format: str = "raw") -> str:
    """Get the execution trace from a session.

    session_id: Active session ID.
    limit: Maximum number of trace entries to return (default: 200).
    format: Output format - "raw" (instruction list), "smart" (analyzed summary), "report" (markdown for reports).

    Returns instruction trace (for Unicorn) or syscall/API call trace (for Qiling).
    """
    if format not in ("raw", "smart", "report"):
        return f"Error: Unknown format '{format}'. Use 'raw', 'smart', or 'report'."
    try:
        engine = sessions.get(session_id)
        trace = engine.get_trace(limit=limit)
        if not trace:
            return "No trace entries. Enable tracing with enable_trace=True or call emu_enable_trace first."

        if format == "smart":
            return _format_smart_trace(trace, engine.arch)
        elif format == "report":
            return _format_report_trace(trace, engine.arch)

        # Default raw format
        lines = [f"Trace ({len(trace)} entries):"]
        for t in trace:
            if t["type"] == "instruction":
                lines.append(f"  {t['address']}: {t['instruction']}")
            elif t["type"] in ("syscall", "api"):
                args_str = ", ".join(str(a) for a in t["args"])
                ret = f" -> {t['return_value']}" if t["return_value"] is not None else ""
                lines.append(f"  [{t['type']}] {t['name']}({args_str}){ret}")
            else:
                lines.append(f"  [{t['type']}] {t['address']}: {t['name']}")
        return "\n".join(lines)
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Trace error: {e}"


@mcp.tool()
def emu_enable_trace(session_id: str) -> str:
    """Enable instruction/call tracing for a session.

    session_id: Active session ID.
    """
    try:
        engine = sessions.get(session_id)
        engine.enable_tracing()
        return "Tracing enabled."
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Enable trace error: {e}"


@mcp.tool()
def emu_clear_trace(session_id: str) -> str:
    """Clear the trace buffer for a session.

    session_id: Active session ID.
    """
    try:
        engine = sessions.get(session_id)
        engine.clear_trace()
        return "Trace cleared."
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Clear trace error: {e}"


# ===========================================================================
# Evidence Export
# ===========================================================================

@mcp.tool()
def emu_export_evidence(
    session_id: str,
    finding_id: str,
    binary_name: str,
    test_input: str,
    verdict: str = "",
    notes: str = "",
) -> str:
    """Export current emulation session state as structured evidence for the Reversing Context MCP.

    Collects register state, trace summary, and session metadata into a format
    ready for reversing-context's import_emulation_evidence tool.

    session_id: Active emulation session.
    finding_id: ID of the vulnerability finding this evidence supports.
    binary_name: Name of the binary being analyzed.
    test_input: The test input/payload used.
    verdict: Assessment - 'vulnerable', 'safe', or 'inconclusive'.
    notes: Additional context.

    Returns a JSON object that can be passed directly to import_emulation_evidence.
    """
    try:
        engine = sessions.get(session_id)
        regs = engine.registers_read_all()
        trace = engine.get_trace(limit=50)

        # Build trace excerpt
        trace_lines = []
        if trace:
            instrs = [t for t in trace if t.get("type", "instruction") == "instruction"]
            if len(instrs) > 10:
                for t in instrs[:5]:
                    trace_lines.append(f"{t['address']}: {t['instruction']}")
                trace_lines.append(f"... ({len(instrs) - 10} instructions omitted) ...")
                for t in instrs[-5:]:
                    trace_lines.append(f"{t['address']}: {t['instruction']}")
            else:
                for t in instrs:
                    trace_lines.append(f"{t['address']}: {t['instruction']}")

        # Auto-detect verdict from return value registers if not provided
        auto_verdict = verdict
        if not auto_verdict:
            # Check common return value registers
            for ret_reg in ["v0", "rax", "eax", "r0", "x0"]:
                if ret_reg in regs:
                    val = regs[ret_reg]
                    if val == 0:
                        auto_verdict = "safe"
                    elif val == 1:
                        auto_verdict = "inconclusive"  # could be either
                    else:
                        auto_verdict = "inconclusive"
                    break
            if not auto_verdict:
                auto_verdict = "inconclusive"

        # Format registers as strings for JSON compatibility
        reg_export = {}
        for k, v in regs.items():
            if v != 0:  # skip zero registers for clarity
                reg_export[k] = f"0x{v:x}"

        evidence = {
            "finding_id": finding_id,
            "binary_name": binary_name,
            "arch": engine.arch,
            "emulation_type": engine.engine_type,
            "test_input": test_input,
            "result_summary": f"Emulation completed. {len(trace)} trace entries. " + (notes if notes else ""),
            "registers": reg_export,
            "instructions_executed": len([t for t in trace if t.get("type", "instruction") == "instruction"]),
            "verdict": auto_verdict,
            "trace_excerpt": "\n".join(trace_lines),
        }

        # Return as formatted JSON
        result = json.dumps(evidence, indent=2)
        return (
            f"Evidence exported for finding '{finding_id}':\n\n"
            f"```json\n{result}\n```\n\n"
            f"Pass this to reversing-context's `import_emulation_evidence` tool to save permanently."
        )
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Export error: {e}"


# ===========================================================================
# Engine discovery
# ===========================================================================

@mcp.tool()
def emu_list_engines() -> str:
    """List the available emulation engines, their install status and capabilities.

    Use this to discover which engines are usable in this environment and what
    each one can do (shellcode, OS emulation, symbolic execution, ...).
    """
    lines = ["Emulation engines:\n"]
    for info in describe_engines():
        status = "installed" if info["installed"] else "NOT installed"
        lines.append(f"### {info['name']}  [{status}]")
        lines.append(f"{info['description']}")
        if info["installed"]:
            lines.append(f"- Capabilities: {', '.join(info['capabilities'])}")
            if info["architectures"]:
                lines.append(f"- Architectures: {', '.join(info['architectures'])}")
        else:
            lines.append(f"- Install with: pip install {info['pip_package']}")
            if info.get("error"):
                lines.append(f"- Detail: {info['error']}")
        lines.append("")
    return "\n".join(lines)


# ===========================================================================
# Symbolic execution (angr)
# ===========================================================================

def _require_symbolic(engine) -> str:
    if not engine.has_capability("symbolic"):
        return (f"Error: Symbolic execution is not supported by the '{engine.engine_type}' engine. "
                f"Create an 'angr' session.")
    return ""


@mcp.tool()
def emu_set_symbolic_register(session_id: str, name: str, bits: int = 0) -> str:
    """Make a register symbolic (angr sessions only).

    session_id: Active angr session.
    name: Register name (e.g. "rdi", "r0", "a0").
    bits: Width in bits; defaults to the register's natural width.

    Returns the symbolic variable name to use with emu_solve.
    """
    try:
        engine = sessions.get(session_id)
        err = _require_symbolic(engine)
        if err:
            return err
        var = engine.set_symbolic_register(name, bits)
        return f"Register {name} is now symbolic. Variable: {var}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Symbolic register error: {e}"


@mcp.tool()
def emu_set_symbolic_memory(session_id: str, address: str, size: int, label: str = "") -> str:
    """Make a region of memory symbolic (angr sessions only).

    session_id: Active angr session.
    address: Hex address (e.g. "0x8000000").
    size: Number of bytes to make symbolic.
    label: Optional label used in the variable name.

    Returns the symbolic variable name to use with emu_solve.
    """
    try:
        engine = sessions.get(session_id)
        err = _require_symbolic(engine)
        if err:
            return err
        if size <= 0:
            return "Error: size must be greater than 0."
        addr = _parse_addr(address)
        var = engine.set_symbolic_memory(addr, size, label)
        return f"{size} bytes at 0x{addr:x} are now symbolic. Variable: {var}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Symbolic memory error: {e}"


@mcp.tool()
def emu_explore(
    session_id: str,
    find: list[str],
    avoid: list[str] | None = None,
    timeout_ms: int = 30000,
    num_find: int = 1,
    techniques: list[str] | None = None,
    veritesting: bool = False,
) -> str:
    """Symbolically explore paths to a target address (angr sessions only).

    session_id: Active angr session.
    find: One or more hex addresses to reach (e.g. ["0x1000011"]).
    avoid: Optional hex addresses to avoid.
    timeout_ms: Wall-clock budget for the search (default 30000).
    num_find: Number of distinct solutions to collect (default 1).
    techniques: Optional exploration techniques to attach, e.g.
      ["dfs", "loopseer:128", "lengthlimiter:2000", "oppologist"].
    veritesting: Enable Veritesting (static merging of paths) to tame path
      explosion.

    Returns the solved values for every symbolic variable on each found path.
    """
    try:
        engine = sessions.get(session_id)
        err = _require_symbolic(engine)
        if err:
            return err
        if not find:
            return "Error: at least one 'find' address is required."
        find_addrs = [_parse_addr(a) for a in find]
        avoid_addrs = [_parse_addr(a) for a in (avoid or [])]
        result = engine.explore(find_addrs, avoid_addrs, timeout_ms=timeout_ms,
                                num_find=num_find, techniques=techniques,
                                veritesting=veritesting)

        lines = [f"Exploration: {result['status']}"]
        lines.append(f"  found={result.get('found', 0)} avoided={result.get('avoided', 0)} "
                     f"deadended={result.get('deadended', 0)} "
                     f"active_remaining={result.get('active_remaining', 0)} "
                     f"elapsed={result.get('elapsed_ms', 0)} ms")
        for i, sol in enumerate(result.get("solutions", [])):
            lines.append(f"\nSolution #{i} (reached {sol['address']}):")
            if not sol["values"]:
                lines.append("  (no symbolic variables defined)")
            for var, v in sol["values"].items():
                if v is None:
                    lines.append(f"  {var}: <unsolvable>")
                else:
                    lines.append(f"  {var}: {v['hex']} ({v['int']})  bytes={v['bytes']}")
        if result["status"] != "found":
            lines.append("\nNo path reached the target. Try different find/avoid addresses, "
                         "a longer timeout, or check that inputs are symbolic.")
        return "\n".join(lines)
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Explore error: {e}"


@mcp.tool()
def emu_solve(session_id: str, variable: str, count: int = 1) -> str:
    """Solve for concrete values of a symbolic variable (angr sessions only).

    session_id: Active angr session.
    variable: The symbolic variable name returned by emu_set_symbolic_*.
    count: Maximum number of distinct solutions to return (default 1).

    Uses the most recent exploration result if one exists, else the current state.
    """
    try:
        engine = sessions.get(session_id)
        err = _require_symbolic(engine)
        if err:
            return err
        if count <= 0:
            return "Error: count must be greater than 0."
        sols = engine.solve(variable, count)
        if not sols:
            return f"No solutions found for '{variable}' (constraints may be unsatisfiable)."
        lines = [f"Solutions for {variable} ({len(sols)}):"]
        for v in sols:
            lines.append(f"  0x{v:x} ({v})")
        return "\n".join(lines)
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Solve error: {e}"


@mcp.tool()
def emu_cfg(session_id: str, fast: bool = True, limit: int = 100) -> str:
    """Recover a control-flow graph and list functions ('cfg' capability, angr).

    session_id: Active session ID.
    fast: Use CFGFast (quick, default) vs. CFGEmulated (precise, slower).
    limit: Max functions to list.
    """
    try:
        engine = sessions.get(session_id)
        result = engine.recover_cfg(fast=fast)
        if "error" in result:
            return f"Error: {result['error']}"
        funcs = result["functions"]
        lines = [f"CFG: {result['nodes']} nodes, {result['edges']} edges, "
                 f"{len(funcs)} functions."]
        for f in funcs[:limit]:
            plt = " [plt]" if f.get("is_plt") else ""
            lines.append(f"  {f['address']} {f['name']} (size {f['size']}){plt}")
        if len(funcs) > limit:
            lines.append(f"  ... and {len(funcs) - limit} more")
        return "\n".join(lines)
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"CFG error: {e}"


@mcp.tool()
def emu_call_function(session_id: str, address: str, args: list[str] | None = None) -> str:
    """Execute a function with concrete integer args ('function_call', angr).

    Uses angr's calling-convention-aware `callable`, so you pass arguments by
    value and get the return value, without setting up registers/stack yourself.

    session_id: Active session ID.
    address: Hex address of the function.
    args: Integer arguments (decimal or hex strings).
    """
    try:
        engine = sessions.get(session_id)
        addr = _parse_addr(address)
        call_args = [_parse_addr(a) for a in (args or [])]
        result = engine.call_function(addr, call_args)
        if "error" in result:
            return f"Error: {result['error']}"
        rv = result["return_value"]
        if rv is None:
            return f"Called {result['address']}({', '.join(map(str, call_args))}) -> (void/unknown)"
        return (f"Called {result['address']}({', '.join(hex(a) for a in call_args)}) "
                f"-> {rv['hex']} ({rv['int']})")
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Call function error: {e}"


@mcp.tool()
def emu_decompile(session_id: str, address: str) -> str:
    """Decompile a function to pseudo-C ('decompiler' capability, angr).

    Recovers a CFG first if needed, then runs angr's decompiler on the function
    containing `address`.

    session_id: Active session ID.
    address: Hex address of the function (its entry point).
    """
    try:
        engine = sessions.get(session_id)
        result = engine.decompile_function(_parse_addr(address))
        if "error" in result:
            return f"Error: {result['error']}"
        return (f"// {result['name']} @ {result['address']}\n{result['code']}")
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Decompile error: {e}"


@mcp.tool()
def emu_function_info(session_id: str, address: str) -> str:
    """Show metadata about one recovered function ('cfg' capability, angr).

    Reports size, block count, returning/PLT/syscall flags, and the function's
    callers and callees. Recovers a CFG first if needed.

    session_id: Active session ID.
    address: Hex address of the function.
    """
    try:
        engine = sessions.get(session_id)
        info = engine.function_info(_parse_addr(address))
        if "error" in info:
            return f"Error: {info['error']}"
        lines = [
            f"{info['name']} @ {info['address']}",
            f"  size={info['size']} blocks={info['blocks']} returning={info['returning']}"
            f" plt={info['is_plt']} syscall={info['is_syscall']}",
        ]
        if info.get("prototype"):
            lines.append(f"  prototype: {info['prototype']}")
        if info.get("calling_convention"):
            lines.append(f"  cc: {info['calling_convention']}")
        lines.append(f"  callers: {', '.join(info['callers']) or '(none)'}")
        lines.append(f"  callees: {', '.join(info['callees']) or '(none)'}")
        return "\n".join(lines)
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Function info error: {e}"


@mcp.tool()
def emu_reaching_definitions(session_id: str, address: str) -> str:
    """Summarize a function's reaching definitions ('dataflow' capability, angr).

    Reports how many register/memory definitions (writes that can be observed
    downstream) the function makes, broken down by kind.

    session_id: Active angr session.
    address: Hex address of the function.
    """
    try:
        engine = sessions.get(session_id)
        r = engine.reaching_definitions(_parse_addr(address))
        if "error" in r:
            return f"Error: {r['error']}"
        kinds = ", ".join(f"{k}={v}" for k, v in r["by_kind"].items()) or "(none)"
        return (f"{r['name']} @ {r['address']}: {r['definitions']} reaching "
                f"definitions ({kinds})")
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Reaching definitions error: {e}"


@mcp.tool()
def emu_data_dependencies(session_id: str, address: str, call_depth: int = 0) -> str:
    """Summarize a function's data-dependence graph ('dataflow' capability, angr).

    Builds a data-dependence graph (DDG) over the function and reports its size.
    Scoped to the one function (call_depth=0 does not descend into callees), so it
    stays tractable inside large binaries.

    session_id: Active angr session.
    address: Hex address of the function.
    call_depth: How many levels of callees to include (default 0).
    """
    try:
        engine = sessions.get(session_id)
        r = engine.data_dependencies(_parse_addr(address), call_depth)
        if "error" in r:
            return f"Error: {r['error']}"
        return (f"{r['name']} @ {r['address']}: data-dependence graph has "
                f"{r['nodes']} nodes, {r['edges']} edges")
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Data dependencies error: {e}"


@mcp.tool()
def emu_backward_slice(session_id: str, address: str, call_depth: int = 0) -> str:
    """Backward program slice to an instruction ('dataflow' capability, angr).

    Returns the set of basic blocks whose data or control flow the target
    instruction depends on. Scoped to the function containing `address`.
    A target with no predecessors (e.g. a function's first instruction) slices
    to nothing — point it at an instruction of interest downstream.

    session_id: Active angr session.
    address: Hex address of the instruction to slice back from.
    call_depth: How many levels of callees to include (default 0).
    """
    try:
        engine = sessions.get(session_id)
        r = engine.backward_slice(_parse_addr(address), call_depth)
        if "error" in r:
            return f"Error: {r['error']}"
        head = ", ".join(r["slice_blocks"][:16])
        more = f" (+{r['block_count'] - 16} more)" if r["block_count"] > 16 else ""
        return (f"Backward slice to {r['target']} in {r['name']}: "
                f"{r['block_count']} blocks, {r['statement_count']} statements\n"
                f"  blocks: {head}{more}")
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Backward slice error: {e}"


@mcp.tool()
def emu_constrain(session_id: str, variable: str, op: str, value: str) -> str:
    """Add a constraint on a symbolic variable ('constraints' capability, angr).

    Narrows the solver so later emu_solve / emu_value_range calls respect it.

    session_id: Active angr session.
    variable: Symbolic variable name (from emu_set_symbolic_*).
    op: One of ==, !=, <, <=, >, >= (comparisons are unsigned).
    value: Integer bound (decimal or hex string).
    """
    try:
        engine = sessions.get(session_id)
        result = engine.add_constraint(variable, op, _parse_int(value))
        sat = "satisfiable" if result["satisfiable"] else "UNSATISFIABLE (over-constrained)"
        return f"Constraint added: {variable} {op} {value}. State is now {sat}."
    except NotImplementedError as e:
        return f"Error: {e}"
    except (KeyError, ValueError) as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Constrain error: {e}"


@mcp.tool()
def emu_value_range(session_id: str, variable: str) -> str:
    """Report the min/max a symbolic variable can take ('constraints', angr).

    Respects all constraints added so far (and the most recent exploration).

    session_id: Active angr session.
    variable: Symbolic variable name (from emu_set_symbolic_*).
    """
    try:
        engine = sessions.get(session_id)
        r = engine.value_range(variable)
        if "error" in r:
            return f"Error: {r['error']}"
        uniq = " (unique)" if r["unique"] else ""
        return (f"{variable} ({r['bits']}-bit): min=0x{r['min']:x} ({r['min']}), "
                f"max=0x{r['max']:x} ({r['max']}){uniq}")
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Value range error: {e}"


@mcp.tool()
def emu_hook_function(session_id: str, address: str, return_value: str | None = None) -> str:
    """Replace a function with a stub that returns at once ('sim_procedures', angr).

    Stub out a function (checksum, libc call, ...) so exploration skips its body.

    session_id: Active angr session.
    address: Hex address of the function to replace.
    return_value: Force this concrete return (decimal/hex); omit for an
      unconstrained symbolic return.

    Returns a hook ID; remove it with emu_remove_hook.
    """
    try:
        engine = sessions.get(session_id)
        rv = _parse_int(return_value) if return_value is not None else None
        hook_id = engine.hook_function(_parse_addr(address), return_value=rv)
        tail = f"returning {return_value}" if return_value is not None else "returning unconstrained"
        return f"Hooked function at {address} ({tail}). Hook ID: {hook_id}"
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Hook function error: {e}"


@mcp.tool()
def emu_hook_skip(session_id: str, address: str, length: int = 0) -> str:
    """No-op bytes at an address so angr skips them ('sim_procedures', angr).

    session_id: Active angr session.
    address: Hex address to skip from.
    length: Number of bytes to skip (0 replaces the block in place).

    Returns a hook ID; remove it with emu_remove_hook.
    """
    try:
        engine = sessions.get(session_id)
        hook_id = engine.hook_skip(_parse_addr(address), length)
        return f"Skip hook at {address} (+{length} bytes). Hook ID: {hook_id}"
    except NotImplementedError as e:
        return f"Error: {e}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Hook skip error: {e}"


# ===========================================================================
# Cross-engine comparison
# ===========================================================================

@mcp.tool()
def emu_compare_engines(
    arch: str,
    code_hex: str,
    engines: list[str] | None = None,
    base_address: str = "0x1000000",
    timeout_ms: int = 5000,
) -> str:
    """Run the same shellcode on two CPU engines and diff the final register state.

    Useful as an independent check: if Unicorn and Icicle disagree on a result,
    one of them is likely mis-emulating the code.

    arch: Architecture ("x86", "x86_64", "arm", "mips", ...).
    code_hex: Hex-encoded shellcode bytes.
    engines: Which engines to compare (default ["unicorn", "icicle"]).
    base_address: Load address (default 0x1000000).
    timeout_ms: Per-engine execution budget.

    Returns each engine's status and a table of registers that differ.
    """
    engines = engines or ["unicorn", "icicle"]
    if len(engines) < 2:
        return "Error: provide at least two engines to compare."
    for name in engines:
        if name not in ("unicorn", "icicle"):
            return f"Error: emu_compare_engines supports 'unicorn' and 'icicle', not '{name}'."
        if not is_installed(name):
            return f"Error: Engine '{name}' is not installed. See emu_list_engines."
    try:
        clean_hex = code_hex.replace(" ", "")
        if clean_hex.lower().startswith("0x"):
            clean_hex = clean_hex[2:]
        code = bytes.fromhex(clean_hex)
        base = _parse_addr(base_address)

        results: dict[str, dict] = {}
        reg_states: dict[str, dict] = {}
        for name in engines:
            eng = get_engine_class(name)(arch=arch)
            try:
                eng.memory_write(base, code)
                results[name] = eng.start(base, base + len(code), timeout_ms=timeout_ms)
                reg_states[name] = eng.registers_read_all()
            finally:
                eng.close()

        lines = [f"Cross-engine comparison ({arch}, {len(code)} bytes):\n"]
        lines.append("| Engine | Status |")
        lines.append("|--------|--------|")
        for name in engines:
            lines.append(f"| {name} | {results[name].get('status', '?')} |")

        # Diff registers common to all engines.
        common = set.intersection(*(set(reg_states[n]) for n in engines))
        diffs = []
        for reg in sorted(common):
            vals = {n: reg_states[n][reg] for n in engines}
            if len(set(vals.values())) > 1:
                diffs.append((reg, vals))

        lines.append("")
        if not diffs:
            lines.append(f"✓ All {len(common)} common registers agree across {', '.join(engines)}.")
        else:
            lines.append(f"✗ {len(diffs)} register(s) differ:")
            lines.append("| Register | " + " | ".join(engines) + " |")
            lines.append("|----------|" + "|".join(["-------"] * len(engines)) + "|")
            for reg, vals in diffs:
                lines.append(f"| {reg} | " + " | ".join(f"0x{vals[n]:x}" for n in engines) + " |")
        return "\n".join(lines)
    except Exception as e:
        return f"Comparison error: {e}"


# ===========================================================================
# Reflective access: reach the full engine surface (emu_call / emu_describe / emu_eval)
# ===========================================================================

@mcp.tool()
def emu_describe(session_id: str, target: str = "native", filter: str = "") -> str:
    """Discover a session's full surface: capabilities + methods (with signatures).

    This is how the model self-serves instead of relying on one dedicated tool
    per capability: it reports the engine's live capability flags and every
    callable's signature, so you know exactly what this engine/arch supports and
    how to call it via emu_call. Signatures come from inspect when possible, else
    from the first line of the method's docstring (native/compiled methods carry
    their signature there).

    session_id: Active session ID.
    target: "native" for the underlying emulator object (icicle VM, unicorn Uc,
      qiling Ql, angr SimState, sogen Emulator), or "engine" for the wrapper
      (the emu_* methods behind every typed tool).
    filter: Optional case-insensitive substring to narrow the names.
    """
    try:
        engine = sessions.get(session_id)
        obj = _resolve_target(engine, target)
        names = [n for n in dir(obj) if not n.startswith("_")]
        if filter:
            f = filter.lower()
            names = [n for n in names if f in n.lower()]
        methods, attrs = [], []
        for n in sorted(names):
            try:
                member = getattr(obj, n)
            except Exception:
                attrs.append(f"  {n}")
                continue
            if callable(member):
                methods.append(f"  {n}{_describe_signature(member)}{_describe_doc(member)}")
            else:
                attrs.append(f"  {n} = {_format_value(member)}")
        caps = sorted(getattr(engine, "CAPABILITIES", ()) or ())
        lines = [f"{engine.engine_type} session, target='{target}' "
                 f"({type(obj).__module__}.{type(obj).__name__}):\n"]
        lines.append(f"Capabilities ({len(caps)}): {', '.join(caps) or '(none advertised)'}")
        lines.append("Invoke any method below with emu_call(session_id, method, "
                     f"args=[...], target='{target}').\n")
        lines.append(f"Methods ({len(methods)}):")
        lines.extend(methods)
        lines.append(f"\nAttributes ({len(attrs)}):")
        lines.extend(attrs)
        return "\n".join(lines)
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Describe error: {e}"


def _describe_signature(member) -> str:
    """Best-effort call signature for a method: inspect first, else docstring."""
    try:
        return str(inspect.signature(member))
    except (ValueError, TypeError):
        # Compiled/native methods (nanobind/pybind/builtins) have no inspectable
        # signature, but conventionally put it on the first docstring line, e.g.
        # "read_memory(self, arg0: int, arg1: int, /) -> bytes".
        doc = (getattr(member, "__doc__", "") or "").strip().splitlines()
        if doc and "(" in doc[0]:
            sig = doc[0].split("(", 1)[1]
            return "(" + sig
        return "(...)"


def _describe_doc(member) -> str:
    """The method's one-line summary, skipping a leading signature line."""
    doc = (getattr(member, "__doc__", "") or "").strip().splitlines()
    if not doc:
        return ""
    first = doc[0].strip()
    # If the first line is just the signature, use the next non-empty line.
    name = getattr(member, "__name__", "")
    if name and first.startswith(name + "(") and len(doc) > 1:
        for line in doc[1:]:
            if line.strip():
                return "  — " + line.strip()
        return ""
    return "  — " + first


@mcp.tool()
def emu_call(
    session_id: str,
    method: str,
    args: list | None = None,
    kwargs: dict | None = None,
    target: str = "native",
) -> str:
    """Invoke any method (or read any attribute) on a session's engine object.

    This is the general escape hatch that reaches the full engine API without a
    dedicated tool for each call. Use emu_describe to discover names.

    session_id: Active session ID.
    method: Name of the method or attribute (no leading underscore).
    args: Positional arguments (JSON). Convenience coercions: a hex string like
      "0x1000" becomes an int; {"hex": "deadbeef"} or {"bytes": [1,2,3]} becomes
      bytes; lists are coerced element-wise.
    kwargs: Keyword arguments (JSON, same coercions applied to values).
    target: "native" (underlying emulator object, default) or "engine" (wrapper).

    If `method` names a plain attribute, its value is returned. If it names a
    method, it is called with the given args and the result is returned.
    """
    try:
        engine = sessions.get(session_id)
        obj = _resolve_target(engine, target)
        if method.startswith("_"):
            return "Error: access to private members (leading underscore) is not allowed."
        if not hasattr(obj, method):
            return (f"Error: '{method}' not found on target '{target}'. "
                    f"Use emu_describe to list available names.")
        member = getattr(obj, method)
        if not callable(member):
            return f"{method} = {_format_value(member)}"
        call_args = [_coerce_arg(a) for a in (args or [])]
        call_kwargs = {k: _coerce_arg(v) for k, v in (kwargs or {}).items()}
        result = member(*call_args, **call_kwargs)
        return f"{method}(...) -> {_format_value(result)}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"Call error: {type(e).__name__}: {e}"


@mcp.tool()
def emu_eval(session_id: str, code: str) -> str:
    """Run a Python snippet against a session (DISABLED unless opted in).

    The snippet executes with `engine` (the wrapper), `native` (the underlying
    emulator object), and `icicle`/`unicorn`/`qiling`/`angr` modules in scope.
    Assign to `result` or end with an expression to return a value; anything
    printed is captured.

    This runs arbitrary Python in the server process and is therefore OFF by
    default. Enable it only in a trusted, local setup by starting the server
    with the environment variable EMU_ENABLE_EVAL=1.

    session_id: Active session ID.
    code: Python source to execute.
    """
    if not ENABLE_EVAL:
        return ("Error: emu_eval is disabled. It runs arbitrary Python in the "
                "server process. To enable it in a trusted local setup, restart "
                "the server with EMU_ENABLE_EVAL=1.")
    try:
        engine = sessions.get(session_id)
    except KeyError as e:
        return str(e)
    import io
    import contextlib
    ns = {
        "engine": engine,
        "native": _native_object(engine),
        "result": None,
    }
    # Make the engine framework modules available if imported.
    for mod in ("icicle", "unicorn", "qiling", "angr", "capstone"):
        try:
            ns[mod] = __import__(mod)
        except Exception:
            pass
    buf = io.StringIO()
    try:
        compiled = compile(code, "<emu_eval>", "exec")
        with contextlib.redirect_stdout(buf):
            exec(compiled, ns)  # noqa: S102 — intentional, gated by EMU_ENABLE_EVAL
        out = buf.getvalue()
        result = ns.get("result")
        parts = []
        if out:
            parts.append(f"stdout:\n{out.rstrip()}")
        parts.append(f"result: {_format_value(result)}")
        return "\n".join(parts)
    except Exception as e:
        out = buf.getvalue()
        prefix = f"stdout:\n{out.rstrip()}\n" if out else ""
        return f"{prefix}eval error: {type(e).__name__}: {e}"


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    mcp.run()
