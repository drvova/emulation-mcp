"""Server-level tests: engine registry and the MCP tools that wire engines in.

Run standalone: python tests/test_server.py
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import server
import engines

try:
    import icicle  # noqa: F401
    HAS_ICICLE = True
except ImportError:
    HAS_ICICLE = False

try:
    import angr  # noqa: F401
    from tests.test_angr import build_freestanding
    HAS_ANGR = True
    _ANGR_FREE = build_freestanding()
except Exception:
    HAS_ANGR = False
    _ANGR_FREE = None

try:
    import qiling  # noqa: F401
    from tests.test_qiling import build_mini_rootfs
    HAS_QILING = True
    _QL_MINI = build_mini_rootfs()
except Exception:
    HAS_QILING = False
    _QL_MINI = None


def _fn(tool):
    """Return the underlying function of a FastMCP tool (or the callable itself)."""
    return getattr(tool, "fn", tool)


# Isolate the persistent code harness so tests never touch the real
# ~/.emulation-mcp/harness: point it at a throwaway dir and ensure code is on.
import tempfile as _tempfile
import shutil as _shutil

_HARNESS_TMP = None
_SAVED_HARNESS_DIR = None


def setUpModule():
    global _HARNESS_TMP, _SAVED_HARNESS_DIR
    _HARNESS_TMP = _tempfile.mkdtemp(prefix="emu-harness-test-")
    _SAVED_HARNESS_DIR = server.HARNESS_DIR
    server.HARNESS_DIR = _HARNESS_TMP
    server._HARNESS_NS.clear()


def tearDownModule():
    server.HARNESS_DIR = _SAVED_HARNESS_DIR
    server._HARNESS_NS.clear()
    if _HARNESS_TMP:
        _shutil.rmtree(_HARNESS_TMP, ignore_errors=True)


def _new_session(**kwargs) -> str:
    out = _fn(server.emu_create_session)(**kwargs)
    assert out.startswith("Session created:"), out
    return out.split("\n")[0].split(": ", 1)[1].strip()


class TestEngineRegistry(unittest.TestCase):
    def test_known_engines(self):
        self.assertEqual(set(engines.ENGINE_NAMES), {"unicorn", "qiling", "icicle", "angr", "sogen"})

    def test_unicorn_installed(self):
        self.assertTrue(engines.is_installed("unicorn"))

    def test_get_unknown_engine(self):
        with self.assertRaises(ValueError):
            engines.get_engine_class("bochs")

    def test_lazy_attribute(self):
        self.assertTrue(callable(engines.UnicornEngine))

    def test_describe_engines_shape(self):
        described = engines.describe_engines()
        names = {d["name"] for d in described}
        self.assertEqual(names, set(engines.ENGINE_NAMES))
        for d in described:
            self.assertIn("installed", d)
            self.assertIn("capabilities", d)

    def test_capability_query(self):
        self.assertIn("unicorn", engines.engines_with_capability("shellcode"))


class TestListEnginesTool(unittest.TestCase):
    def test_list_engines(self):
        out = _fn(server.emu_list_engines)()
        self.assertIn("unicorn", out)
        self.assertIn("qiling", out)
        self.assertIn("icicle", out)
        self.assertIn("angr", out)
        self.assertIn("sogen", out)

    def test_unknown_engine_rejected(self):
        out = _fn(server.emu_create_session)(engine="bochs", arch="x86_64")
        self.assertIn("Unknown engine", out)


class TestUnicornThroughServer(unittest.TestCase):
    def test_create_and_run(self):
        sid = _new_session(engine="unicorn", arch="x86_64", enable_trace=True)
        try:
            _fn(server.emu_memory_write)(sid, "0x1000000", "48c7c041000000" "90")
            out = _fn(server.emu_run)(sid, "0x1000000", "0x1000008")
            self.assertIn("rax=0x41", out)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_syscall_hook_rejected(self):
        sid = _new_session(engine="unicorn", arch="x86_64")
        try:
            out = _fn(server.emu_hook_syscall)(sid, "write")
            self.assertIn("not supported", out)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_icicle_only_tools_rejected_on_unicorn(self):
        sid = _new_session(engine="unicorn", arch="x86_64")
        try:
            for out in (
                _fn(server.emu_breakpoint_add)(sid, "0x1000000"),
                _fn(server.emu_list_registers)(sid),
                _fn(server.emu_memory_unmap)(sid, "0x1000000", 0x1000),
            ):
                self.assertIn("not supported", out)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_extended_tools_report_requirement_on_unicorn(self):
        """Reverse-exec/disasm/callstack tools degrade cleanly on engines
        without the capability (e.g. Unicorn, or stock Icicle)."""
        sid = _new_session(engine="unicorn", arch="x86_64")
        try:
            for out in (
                _fn(server.emu_step_back)(sid, 1),
                _fn(server.emu_goto_icount)(sid, 0),
                _fn(server.emu_callstack)(sid),
                _fn(server.emu_disassemble)(sid, "0x1000000", 1),
                _fn(server.emu_coverage)(sid, "enable"),
                _fn(server.emu_gdb_serve)(sid, "127.0.0.1:54998", 1),
            ):
                self.assertTrue(out.startswith("Error:"), out)
        finally:
            _fn(server.emu_close_session)(sid)


def _icicle_is_extended():
    try:
        import engines
        if not engines.is_installed("icicle"):
            return False
        eng = engines.get_engine_class("icicle")(arch="x86_64")
        ok = "reverse_execution" in eng.CAPABILITIES
        eng.close()
        return ok
    except Exception:
        return False


ICICLE_EXTENDED = _icicle_is_extended()


class TestFuzzing(unittest.TestCase):
    """Coverage-guided fuzzing over the shared primitives (engine-agnostic)."""

    # read byte at HEAP (0x8000000); if == 0x41 -> read [0] (crash) else skip
    TARGET = ("48be0000000800000000"  # movabs rsi, 0x8000000
              "8a06"                    # mov al, [rsi]
              "3c41"                    # cmp al, 0x41
              "7508"                    # jne +8 (skip)
              "488b042500000000"        # mov rax, [0x0]  (crash: unmapped read)
              "9090")                   # skip: nop; nop

    def _engine(self):
        # Prefer icicle (full-fidelity snapshots); fall back to unicorn.
        return "icicle" if server.is_installed("icicle") else "unicorn"

    def test_finds_crash_and_coverage(self):
        sid = _new_session(engine=self._engine(), arch="x86_64")
        try:
            clen = len(self.TARGET) // 2
            _fn(server.emu_memory_write)(sid, "0x1000000", self.TARGET)
            out = _fn(server.emu_fuzz)(
                sid, input_addr="0x8000000", input_size=1,
                run_start="0x1000000", run_end=hex(0x1000000 + clen),
                iterations=400, timeout_ms=500, wall_clock_s=20, seed=1234,
            )
            # The fuzzer must discover the branch and the crashing input (0x41).
            self.assertIn("Unique crashes: 1", out, out)
            self.assertIn("input `41`", out, out)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_input_region_must_be_mapped(self):
        sid = _new_session(engine="unicorn", arch="x86_64")
        try:
            out = _fn(server.emu_fuzz)(
                sid, input_addr="0xdead0000", input_size=4,
                run_start="0x1000000", run_end="0x1000001",
                iterations=5, seed=1,
            )
            self.assertTrue(out.startswith("Error:"), out)
        finally:
            _fn(server.emu_close_session)(sid)


class TestReflectiveTools(unittest.TestCase):
    """The general 'reach everything' escape hatches."""

    def test_describe_lists_native_methods(self):
        sid = _new_session(engine="unicorn", arch="x86_64")
        try:
            out = _fn(server.emu_describe)(sid, "native", "mem")
            self.assertIn("mem_read", out)
            self.assertIn("mem_write", out)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_call_reflective_memory(self):
        sid = _new_session(engine="unicorn", arch="x86_64")
        try:
            w = _fn(server.emu_call)(sid, "mem_write",
                                     ["0x1000000", {"hex": "41424344"}], target="native")
            self.assertIn("None", w)
            r = _fn(server.emu_call)(sid, "mem_read", ["0x1000000", 4], target="native")
            self.assertIn("41424344", r)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_call_engine_target(self):
        sid = _new_session(engine="unicorn", arch="x86_64")
        try:
            _fn(server.emu_call)(sid, "register_write", ["rax", "0x1234"], target="engine")
            r = _fn(server.emu_call)(sid, "register_read", ["rax"], target="engine")
            self.assertIn("0x1234", r)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_call_private_blocked(self):
        sid = _new_session(engine="unicorn", arch="x86_64")
        try:
            out = _fn(server.emu_call)(sid, "__class__", target="native")
            self.assertIn("private", out.lower())
        finally:
            _fn(server.emu_close_session)(sid)

    def test_call_unknown_method(self):
        sid = _new_session(engine="unicorn", arch="x86_64")
        try:
            out = _fn(server.emu_call)(sid, "no_such_method_here", target="native")
            self.assertIn("not found", out)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_eval_runs_in_shared_harness(self):
        # emu_eval is a thin wrapper over the same persistent harness `emu` uses.
        sid = _new_session(engine="unicorn", arch="x86_64")
        try:
            out = _fn(server.emu_eval)(sid,
                "engine.memory_write(0x1000000, bytes.fromhex('9090'))\n"
                "print('ok')\n"
                "engine.memory_read(0x1000000, 2).hex()")
            self.assertIn("ok", out)
            self.assertIn("9090", out)
        finally:
            _fn(server.emu_close_session)(sid)


@unittest.skipUnless(ICICLE_EXTENDED, "extended Icicle binding (icicle_ext/) not installed")
class TestExtendedIcicleTools(unittest.TestCase):
    def test_reverse_and_disasm_via_server(self):
        sid = _new_session(engine="icicle", arch="x86_64", enable_trace=True)
        try:
            _fn(server.emu_memory_write)(sid, "0x1000000",
                                         "48c7c041000000" "48c7c342000000" "9090")
            _fn(server.emu_run)(sid, "0x1000000", "0x1000010")
            dis = _fn(server.emu_disassemble)(sid, "0x1000000", 2)
            self.assertIn("MOV", dis.upper())
            back = _fn(server.emu_step_back)(sid, 2)
            self.assertIn("icount=2", back)
            goto = _fn(server.emu_goto_icount)(sid, 1)
            self.assertIn("icount=1", goto)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_wide_registers_via_server(self):
        sid = _new_session(engine="icicle", arch="x86_64")
        try:
            caps = server.sessions.get(sid).CAPABILITIES
            if "wide_registers" not in caps:
                self.skipTest("binding lacks wide-register access")
            w = _fn(server.emu_register_write_wide)(sid, "xmm0", "000102030405060708090a0b0c0d0e0f")
            self.assertIn("Wrote", w)
            r = _fn(server.emu_register_read_wide)(sid, "xmm0")
            self.assertIn("000102030405060708090a0b0c0d0e0f", r)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_callback_hook_via_eval(self):
        """Python-callback hooks are driveable through emu_eval."""
        sid = _new_session(engine="icicle", arch="x86_64")
        try:
            caps = server.sessions.get(sid).CAPABILITIES
            if "callback_hooks" not in caps:
                self.skipTest("binding lacks callback hooks")
            _fn(server.emu_memory_write)(sid, "0x1000000", "9090909090")
            out = _fn(server.emu_eval)(sid,
                "hits = []\n"
                "engine.add_callback_hook(lambda a: hits.append(a))\n"
                "engine.start(0x1000000, 0x1000005)\n"
                "result = len(hits)")
            self.assertIn("result:", out)
            # at least one block entry recorded
            self.assertNotIn("result: 0", out)
        finally:
            _fn(server.emu_close_session)(sid)
    def test_memory_hook_via_eval(self):
        """Guest memory-access hooks are driveable through emu_eval."""
        sid = _new_session(engine="icicle", arch="x86_64")
        try:
            caps = server.sessions.get(sid).CAPABILITIES
            if "memory_hooks" not in caps:
                self.skipTest("binding lacks memory hooks")
            # mov [0x8000000], eax ; mov ebx, [0x8000000]
            _fn(server.emu_memory_write)(sid, "0x1000000",
                                         "89042500000008" "8b1c2500000008")
            out = _fn(server.emu_eval)(sid,
                "writes = []\n"
                "engine.add_mem_hook(lambda a, d: writes.append((a, bytes(d))),\n"
                "                    kind='write', start=0x8000000, end=0x8001000)\n"
                "engine.register_write('rip', 0x1000000)\n"
                "engine.register_write('rax', 0xdeadbeef)\n"
                "engine.step(1); engine.step(1)\n"
                "result = '%#x:%s' % (writes[0][0], writes[0][1].hex())")
            self.assertIn("result:", out)
            self.assertIn("0x8000000:efbeadde", out)
        finally:
            _fn(server.emu_close_session)(sid)
    def test_pcode_via_server(self):
        sid = _new_session(engine="icicle", arch="x86_64")
        try:
            if "pcode_il" not in server.sessions.get(sid).CAPABILITIES:
                self.skipTest("binding lacks p-code lifting")
            _fn(server.emu_memory_write)(sid, "0x1000000", "b80100000083c002")
            out = _fn(server.emu_pcode)(sid, "0x1000000")
            self.assertIn("MOV", out.upper())
            self.assertIn("RAX", out)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_mmio_via_eval(self):
        """MMIO regions are driveable through emu_eval (callbacks)."""
        sid = _new_session(engine="icicle", arch="x86_64")
        try:
            if "mmio" not in server.sessions.get(sid).CAPABILITIES:
                self.skipTest("binding lacks MMIO")
            _fn(server.emu_memory_write)(sid, "0x1000000", "8b042500000040")  # mov eax,[0x40000000]
            out = _fn(server.emu_eval)(sid,
                "engine.map_mmio(0x40000000, 0x1000, read_cb=lambda a, s: 0x11223344)\n"
                "engine.register_write('rip', 0x1000000)\n"
                "engine.step(1)\n"
                "result = hex(engine.register_read('rax'))")
            self.assertIn("0x11223344", out)
        finally:
            _fn(server.emu_close_session)(sid)
    def test_pcode_rejected_on_unicorn(self):
        sid = _new_session(engine="unicorn", arch="x86_64")
        try:
            self.assertIn("not supported", _fn(server.emu_pcode)(sid, "0x1000000"))
        finally:
            _fn(server.emu_close_session)(sid)

    def test_cmplog_via_server(self):
        sid = _new_session(engine="icicle", arch="x86_64")
        try:
            if "cmplog" not in server.sessions.get(sid).CAPABILITIES:
                self.skipTest("binding lacks compare logging")
            self.assertIn("enabled", _fn(server.emu_cmplog)(sid, "enable").lower())
            # cmp eax,0x1337cafe ; jne +3 ; nop*3 ; nop ; hlt  (rax set at runtime)
            _fn(server.emu_memory_write)(sid, "0x1000000", "3dfeca371375039090909090f4")
            _fn(server.emu_register_write)(sid, "rax", "0x41414141")
            _fn(server.emu_run)(sid, "0x1000000", "")
            out = _fn(server.emu_cmplog)(sid, "get")
            self.assertIn("0x41414141", out)
            self.assertIn("0x1337cafe", out)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_cmplog_rejected_on_unicorn(self):
        sid = _new_session(engine="unicorn", arch="x86_64")
        try:
            self.assertIn("not supported", _fn(server.emu_cmplog)(sid, "get"))
        finally:
            _fn(server.emu_close_session)(sid)

    def test_symbols_via_server(self):
        import shutil, subprocess, tempfile
        sid = _new_session(engine="icicle", arch="x86_64")
        has = "symbols" in server.sessions.get(sid).CAPABILITIES
        if not has:
            _fn(server.emu_close_session)(sid)
            self.skipTest("binding lacks symbolization")
        if shutil.which("gcc") is None:
            _fn(server.emu_close_session)(sid)
            self.skipTest("gcc unavailable")
        d = tempfile.mkdtemp()
        src, out = os.path.join(d, "s.c"), os.path.join(d, "s")
        with open(src, "w") as f:
            f.write("int my_secret_func(int a){return a*3+1;}\nint main(void){return my_secret_func(7);}\n")
        try:
            subprocess.run(["gcc", "-static", "-no-pie", "-g", "-O0", "-o", out, src],
                           check=True, capture_output=True, timeout=60)
        except Exception:
            _fn(server.emu_close_session)(sid)
            self.skipTest("could not build symbol'd binary")
        try:
            self.assertIn("Loaded", _fn(server.emu_load_symbols)(sid, out))
            lk = _fn(server.emu_lookup_symbol)(sid, "my_secret_func")
            self.assertIn("my_secret_func = 0x", lk)
            addr = lk.split("= ")[1]
            self.assertIn("my_secret_func", _fn(server.emu_symbolize)(sid, addr))
            self.assertIn("my_secret_func", _fn(server.emu_list_symbols)(sid, "secret"))
        finally:
            _fn(server.emu_close_session)(sid)

    def test_symbols_rejected_on_unicorn(self):
        sid = _new_session(engine="unicorn", arch="x86_64")
        try:
            self.assertIn("not supported", _fn(server.emu_lookup_symbol)(sid, "main"))
        finally:
            _fn(server.emu_close_session)(sid)

    def test_coverage_via_server(self):
        sid = _new_session(engine="icicle", arch="x86_64")
        try:
            self.assertIn("enabled", _fn(server.emu_coverage)(sid, "enable").lower())
            _fn(server.emu_memory_write)(sid, "0x1000000",
                                         "b801000000" "85c0" "7401" "90" "90")
            _fn(server.emu_run)(sid, "0x1000000", "0x100000b")
            out = _fn(server.emu_coverage)(sid, "get")
            self.assertIn("Covered basic blocks", out)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_background_gdb_non_blocking(self):
        sid = _new_session(engine="icicle", arch="x86_64")
        try:
            caps = server.sessions.get(sid).CAPABILITIES
            if "gdb" not in caps:
                self.skipTest("binding has no GDB stub")
            _fn(server.emu_memory_write)(sid, "0x1000000", "48c7c041000000")
            t = time.time()
            out = _fn(server.emu_gdb_serve)(sid, "127.0.0.1:54487",
                                            timeout_secs=10, background=True)
            # Must return promptly (not block for the serve duration).
            self.assertLess(time.time() - t, 5.0)
            self.assertIn("pid", out.lower())
            stop = _fn(server.emu_gdb_stop)(sid)
            self.assertIn("Stopped", stop)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_background_gdb_linux_session(self):
        """Background GDB now works for Linux-mode sessions (fixed caveat)."""
        import shutil, subprocess, tempfile, os as _os
        sid = _new_session(engine="icicle", arch="x86_64")
        has_gdb = "gdb" in server.sessions.get(sid).CAPABILITIES
        has_linux = getattr(server.sessions.get(sid), "_has_linux", False)
        _fn(server.emu_close_session)(sid)
        if not (has_gdb and has_linux):
            self.skipTest("binding lacks GDB or Linux support")
        if shutil.which("gcc") is None:
            self.skipTest("gcc unavailable")
        tmp = tempfile.mkdtemp()
        src, out = _os.path.join(tmp, "t.c"), _os.path.join(tmp, "t")
        with open(src, "w") as f:
            f.write("int main(){return 0;}\n")
        try:
            subprocess.run(["gcc", "-static", "-O2", "-o", out, src],
                           check=True, capture_output=True, timeout=60)
        except Exception:
            self.skipTest("could not build static binary")
        info = _fn(server.emu_create_session)(
            engine="icicle", arch="x86_64", binary_path=out,
            engine_options={"os": "linux"})
        sid = info.splitlines()[0].split(": ", 1)[1].strip()
        try:
            t = time.time()
            msg = _fn(server.emu_gdb_serve)(sid, "127.0.0.1:54489",
                                            timeout_secs=8, background=True)
            self.assertLess(time.time() - t, 5.0)
            self.assertIn("pid", msg.lower())  # no longer refused for Linux
            self.assertNotIn("does not support Linux", msg)
            self.assertIn("Stopped", _fn(server.emu_gdb_stop)(sid))
        finally:
            _fn(server.emu_close_session)(sid)


@unittest.skipUnless(HAS_ICICLE, "icicle not installed")
class TestIcicleThroughServer(unittest.TestCase):
    def test_create_and_run(self):
        sid = _new_session(engine="icicle", arch="x86_64", enable_trace=True)
        try:
            _fn(server.emu_memory_write)(sid, "0x1000000", "48c7c041000000" "48c7c342000000" "9090")
            _fn(server.emu_run)(sid, "0x1000000", "0x1000010")
            out = _fn(server.emu_registers_read)(sid, ["rax", "rbx"])
            self.assertIn("(65)", out)   # rax = 0x41
            self.assertIn("(66)", out)   # rbx = 0x42
        finally:
            _fn(server.emu_close_session)(sid)

    def test_riscv64_session(self):
        sid = _new_session(engine="icicle", arch="riscv64")
        try:
            out = _fn(server.emu_registers_read)(sid)
            self.assertIn("pc", out)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_shellcode_tool_with_icicle(self):
        out = _fn(server.emu_emulate_shellcode)(
            arch="x86_64", code_hex="48c7c0410000009090", engine="icicle",
        )
        self.assertIn("0x41", out)

    def test_list_registers_tool(self):
        sid = _new_session(engine="icicle", arch="x86_64")
        try:
            out = _fn(server.emu_list_registers)(sid)
            self.assertIn("RAX", out)
            self.assertIn("offset=", out)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_memory_unmap_and_protect_tools(self):
        sid = _new_session(engine="icicle", arch="x86_64")
        try:
            _fn(server.emu_memory_map)(sid, "0xA000000", 0x1000, 7)
            self.assertIn("Unmapped", _fn(server.emu_memory_unmap)(sid, "0xA000000", 0x1000))
            self.assertIn("perms=", _fn(server.emu_memory_protect)(sid, "0x1000000", 0x1000, 5))
        finally:
            _fn(server.emu_close_session)(sid)

    def test_breakpoint_tools(self):
        sid = _new_session(engine="icicle", arch="x86_64")
        try:
            _fn(server.emu_memory_write)(sid, "0x1000000", "9090909090f4")
            self.assertIn("Breakpoint set", _fn(server.emu_breakpoint_add)(sid, "0x1000003"))
            out = _fn(server.emu_run)(sid, "0x1000000", "")
            self.assertIn("breakpoint", out.lower())
            self.assertIn("removed", _fn(server.emu_breakpoint_remove)(sid, "0x1000003"))
        finally:
            _fn(server.emu_close_session)(sid)

    def test_engine_options_jit(self):
        sid = _new_session(engine="icicle", arch="x86_64", engine_options={"jit": True})
        try:
            _fn(server.emu_memory_write)(sid, "0x1000000", "48c7c0410000009090")
            _fn(server.emu_run)(sid, "0x1000000", "0x1000009")
            self.assertIn("(65)", _fn(server.emu_registers_read)(sid, ["rax"]))
        finally:
            _fn(server.emu_close_session)(sid)


@unittest.skipUnless(HAS_ICICLE, "icicle not installed")
class TestCompareEngines(unittest.TestCase):
    def test_agreement(self):
        # mov rax,0x41; mov rbx,0x42; nop; nop  (no ret, so both reach `end`)
        out = _fn(server.emu_compare_engines)(
            arch="x86_64", code_hex="48c7c041000000" "48c7c342000000" "9090",
        )
        self.assertIn("agree", out.lower())


@unittest.skipUnless(HAS_ANGR, "angr not installed")
class TestAngrThroughServer(unittest.TestCase):
    def test_symbolic_explore_and_solve(self):
        sid = _new_session(engine="angr", arch="x86_64")
        try:
            code = ("4889f8" "483534120000" "483d55550000"
                    "7506" "b801000000" "c3" "31c0" "c3")
            _fn(server.emu_memory_write)(sid, "0x1000000", code)
            _fn(server.emu_register_write)(sid, "rip", "0x1000000")
            var_out = _fn(server.emu_set_symbolic_register)(sid, "rdi")
            self.assertIn("Variable:", var_out)
            var = var_out.split("Variable:", 1)[1].strip()
            out = _fn(server.emu_explore)(sid, find=["0x1000011"], avoid=["0x1000017"])
            self.assertIn("found", out)
            self.assertIn("0x4761", out)
            solved = _fn(server.emu_solve)(sid, var)
            self.assertIn("0x4761", solved)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_symbolic_rejected_on_unicorn(self):
        sid = _new_session(engine="unicorn", arch="x86_64")
        try:
            out = _fn(server.emu_set_symbolic_register)(sid, "rax")
            self.assertIn("not supported", out)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_cfg_and_call_function_via_server(self):
        sid = _new_session(engine="angr", arch="x86_64")
        try:
            # f(a,b)=a+b : lea eax,[rdi+rsi]; ret
            _fn(server.emu_memory_write)(sid, "0x1000000", "8d0437c3")
            call = _fn(server.emu_call_function)(sid, "0x1000000", ["3", "4"])
            self.assertIn("(7)", call)
            cfg = _fn(server.emu_cfg)(sid)
            self.assertIn("functions", cfg)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_cfg_rejected_on_unicorn(self):
        sid = _new_session(engine="unicorn", arch="x86_64")
        try:
            self.assertIn("not supported", _fn(server.emu_cfg)(sid))
            self.assertIn("not supported",
                          _fn(server.emu_call_function)(sid, "0x1000000"))
        finally:
            _fn(server.emu_close_session)(sid)

    def test_decompile_and_function_info_via_server(self):
        sid = _new_session(engine="angr", arch="x86_64")
        try:
            _fn(server.emu_memory_write)(sid, "0x1000000", "8d0437c3")  # add; ret
            _fn(server.emu_cfg)(sid)
            info = _fn(server.emu_function_info)(sid, "0x1000000")
            self.assertIn("returning=True", info)
            dec = _fn(server.emu_decompile)(sid, "0x1000000")
            self.assertIn("return", dec)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_constrain_and_value_range_via_server(self):
        sid = _new_session(engine="angr", arch="x86_64")
        try:
            var = _fn(server.emu_set_symbolic_register)(sid, "rdi").split("Variable:", 1)[1].strip()
            # Decimal is decimal (not hex): >10 and <20 -> [11, 19].
            self.assertIn("satisfiable", _fn(server.emu_constrain)(sid, var, ">", "10"))
            _fn(server.emu_constrain)(sid, var, "<", "20")
            rng = _fn(server.emu_value_range)(sid, var)
            self.assertIn("min=0xb (11)", rng)
            self.assertIn("max=0x13 (19)", rng)
            # Over-constrain -> reported unsatisfiable.
            self.assertIn("UNSATISFIABLE", _fn(server.emu_constrain)(sid, var, ">", "100"))
        finally:
            _fn(server.emu_close_session)(sid)

    def test_hook_function_via_server(self):
        sid = _new_session(engine="angr", arch="x86_64")
        try:
            _fn(server.emu_memory_write)(sid, "0x1000000", "8d0437c3")  # add; ret
            self.assertIn("(7)", _fn(server.emu_call_function)(sid, "0x1000000", ["3", "4"]))
            out = _fn(server.emu_hook_function)(sid, "0x1000000", "99")  # decimal 99
            self.assertIn("Hook ID:", out)
            self.assertIn("(99)", _fn(server.emu_call_function)(sid, "0x1000000", ["3", "4"]))
        finally:
            _fn(server.emu_close_session)(sid)

    def test_inspect_hook_via_eval(self):
        """state.inspect breakpoints are driveable through emu_eval."""
        sid = _new_session(engine="angr", arch="x86_64")
        try:
            out = _fn(server.emu_eval)(sid,
                "seen = []\n"
                "engine.add_inspect_hook('mem_write',\n"
                "    lambda s: seen.append(s.solver.eval(s.inspect.attrs.mem_write_address)))\n"
                "engine.memory_write(0x8000000, b'\\xaa\\xbb\\xcc\\xdd')\n"
                "result = '0x%x' % seen[0]")
            self.assertIn("0x8000000", out)
        finally:
            _fn(server.emu_close_session)(sid)
    def test_new_tools_rejected_on_unicorn(self):
        sid = _new_session(engine="unicorn", arch="x86_64")
        try:
            self.assertIn("not supported", _fn(server.emu_decompile)(sid, "0x1000000"))
            self.assertIn("not supported", _fn(server.emu_hook_function)(sid, "0x1000000"))
            self.assertIn("not supported", _fn(server.emu_constrain)(sid, "x", "==", "1"))
        finally:
            _fn(server.emu_close_session)(sid)

    def test_binary_mode(self):
        if not os.path.exists("/bin/true"):
            self.skipTest("/bin/true not available")
        sid = _new_session(engine="angr", binary_path="/bin/true")
        try:
            out = _fn(server.emu_list_sessions)()
            self.assertIn(sid, out)
        finally:
            _fn(server.emu_close_session)(sid)

    def test_dataflow_via_server(self):
        if _ANGR_FREE is None:
            self.skipTest("gcc (for a freestanding binary) unavailable")
        sid = _new_session(engine="angr", binary_path=_ANGR_FREE)
        try:
            cfg = _fn(server.emu_cfg)(sid, True, 500)
            import re
            funcs = {}
            for line in cfg.splitlines()[1:]:
                m = re.match(r"\s*(0x[0-9a-f]+)\s+(\S+)", line)
                if m:
                    funcs[m.group(2)] = m.group(1)
            comp = funcs["compute"]
            self.assertIn("reaching definitions", _fn(server.emu_reaching_definitions)(sid, comp))
            self.assertIn("data-dependence graph", _fn(server.emu_data_dependencies)(sid, comp))
            self.assertIn("Backward slice", _fn(server.emu_backward_slice)(sid, comp))
        finally:
            _fn(server.emu_close_session)(sid)

    def test_dataflow_rejected_on_unicorn(self):
        sid = _new_session(engine="unicorn", arch="x86_64")
        try:
            self.assertIn("not supported", _fn(server.emu_reaching_definitions)(sid, "0x1000000"))
            self.assertIn("not supported", _fn(server.emu_backward_slice)(sid, "0x1000000"))
        finally:
            _fn(server.emu_close_session)(sid)


@unittest.skipUnless(HAS_QILING and _QL_MINI is not None,
                     "qiling or gcc (for the static-binary rootfs) not available")
class TestQilingThroughServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rootfs, cls.bins = _QL_MINI

    def _session(self, name) -> str:
        return _new_session(engine="qiling", binary_path=self.bins[name],
                            rootfs=self.rootfs, arch="x86_64", ostype="linux")

    def test_disassemble_and_maps_and_registers(self):
        sid = self._session("hello")
        try:
            entry = server.sessions.get(sid).ql.loader.entry_point
            dis = _fn(server.emu_disassemble)(sid, hex(entry), 2)
            self.assertIn("0x", dis)
            self.assertIn("Memory maps", _fn(server.emu_memory_maps)(sid))
            self.assertIn("rip", _fn(server.emu_list_registers)(sid))
        finally:
            _fn(server.emu_close_session)(sid)

    def test_capture_output_via_server(self):
        sid = self._session("hello")
        try:
            self.assertIn("capture started", _fn(server.emu_capture_output)(sid, "start"))
            _fn(server.emu_run)(sid)
            self.assertIn("hi from qiling", _fn(server.emu_capture_output)(sid, "get"))
        finally:
            _fn(server.emu_close_session)(sid)

    def test_fs_map_via_server(self):
        import tempfile
        d = tempfile.mkdtemp()
        flag = os.path.join(d, "flag")
        with open(flag, "w") as f:
            f.write("FLAG{server-qiling}")
        sid = self._session("catflag")
        try:
            self.assertIn("Mapped", _fn(server.emu_fs_map)(sid, "/flag.txt", flag))
            _fn(server.emu_capture_output)(sid, "start")
            _fn(server.emu_run)(sid)
            self.assertIn("FLAG{server-qiling}", _fn(server.emu_capture_output)(sid, "get"))
        finally:
            _fn(server.emu_close_session)(sid)

    def test_set_stdin_via_server(self):
        sid = self._session("echo")
        try:
            self.assertIn("preloaded", _fn(server.emu_set_stdin)(sid, "server-stdin\n"))
            _fn(server.emu_capture_output)(sid, "start")
            _fn(server.emu_run)(sid)
            self.assertIn("server-stdin", _fn(server.emu_capture_output)(sid, "get"))
        finally:
            _fn(server.emu_close_session)(sid)

    def test_syscall_observe_via_server(self):
        sid = self._session("hello")
        try:
            out = _fn(server.emu_hook_syscall)(sid, "write", when="enter")
            self.assertIn("(enter)", out)
            self.assertIn("Error", _fn(server.emu_hook_syscall)(sid, "write", when="bogus"))
        finally:
            _fn(server.emu_close_session)(sid)

    def test_io_tools_rejected_on_unicorn(self):
        sid = _new_session(engine="unicorn", arch="x86_64")
        try:
            self.assertIn("not supported", _fn(server.emu_fs_map)(sid, "/x", "/etc/hostname"))
            self.assertIn("not supported", _fn(server.emu_memory_maps)(sid))
            self.assertIn("not supported", _fn(server.emu_capture_output)(sid, "start"))
            self.assertIn("not supported", _fn(server.emu_syscall_stats)(sid))
        finally:
            _fn(server.emu_close_session)(sid)

    def test_syscall_stats_and_threads_via_server(self):
        sid = self._session("hello")
        try:
            _fn(server.emu_run)(sid)
            self.assertIn("Syscalls", _fn(server.emu_syscall_stats)(sid))
            self.assertIn("Threads", _fn(server.emu_list_threads)(sid))
        finally:
            _fn(server.emu_close_session)(sid)

    def test_multithread_option_via_server(self):
        sid = _new_session(engine="qiling", binary_path=self.bins["hello"],
                           rootfs=self.rootfs, arch="x86_64", ostype="linux",
                           engine_options={"multithread": True})
        try:
            self.assertTrue(server.sessions.get(sid)._multithread)
        finally:
            _fn(server.emu_close_session)(sid)


class TestToolSurface(unittest.TestCase):
    """One `emu` code tool is advertised; the model builds its own tooling in it."""

    def _advertised(self):
        import asyncio
        return {t.name for t in asyncio.run(server.mcp.list_tools())}

    def _create(self, **opts):
        out = _fn(server.emu)(code=f"create(**{opts!r})")
        return out.split("result:", 1)[1].strip().strip("'\"")

    def test_emu_is_the_only_tool(self):
        # `emu` is the whole interface: exactly one advertised tool, always.
        self.assertEqual(self._advertised(), {"emu"})
        # The other emu_* names stay defined on the module as plain functions
        # (the harness and tests call them); they are just not tools.
        self.assertTrue(callable(_fn(server.emu_create_session)))
        self.assertTrue(callable(_fn(server.emu_symbolize)))

    def test_empty_code_returns_manual_and_engines(self):
        out = _fn(server.emu)(code="")
        self.assertIn("one tool", out.lower())
        self.assertIn("create(", out)          # the manual documents the vocabulary
        self.assertIn("unicorn", out)          # installed engines are listed

    def test_build_and_reuse_persistent_helper(self):
        # The headline property: a helper defined in one call persists and is
        # reusable in the next -- the model builds its own tooling.
        sid = self._create(engine="unicorn", arch="x86_64")
        try:
            r1 = _fn(server.emu)(session_id=sid, strings={"x": "deadbeef"}, code=(
                "engine.memory_map(0x1000, 0x1000, 7)\n"
                "def poke(a, h):\n"
                "    engine.memory_write(a, bytes.fromhex(h))\n"
                "    return engine.memory_read(a, len(h)//2).hex()\n"
                "poke(0x1000, S['x'])"
            ))
            self.assertIn("deadbeef", r1)
            # NEXT call: reuse the persisted helper without redefining it
            r2 = _fn(server.emu)(session_id=sid, code="poke(0x1004, 'cafe')")
            self.assertIn("cafe", r2)
            # discovery is in-language
            self.assertIn("shellcode", _fn(server.emu)(session_id=sid, code="caps(session_id)"))
            self.assertIn("poke", _fn(server.emu)(code="kept()"))
        finally:
            _fn(server.emu)(session_id=sid, code=f"close({sid!r})")

    def test_definitions_persist_across_restart(self):
        # A definition is written to HARNESS_DIR and reloaded into a fresh
        # namespace -- it survives a server restart.
        _fn(server.emu)(code="def answer():\n    return 42")
        self.assertIn("answer", _fn(server.emu)(code="kept()"))
        server._HARNESS_NS.clear()                      # simulate a restart
        self.assertIn("42", _fn(server.emu)(code="answer()"))
        _fn(server.emu)(code="forget('answer')")        # clean up
        self.assertNotIn("answer", _fn(server.emu)(code="kept()"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
