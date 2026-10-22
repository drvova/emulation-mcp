"""Server-level tests: engine registry and the MCP tools that wire engines in.

Run standalone: python tests/test_server.py
"""

import os
import sys
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
    HAS_ANGR = True
except ImportError:
    HAS_ANGR = False


def _fn(tool):
    """Return the underlying function of a FastMCP tool (or the callable itself)."""
    return getattr(tool, "fn", tool)


def _new_session(**kwargs) -> str:
    out = _fn(server.emu_create_session)(**kwargs)
    assert out.startswith("Session created:"), out
    return out.split("\n")[0].split(": ", 1)[1].strip()


class TestEngineRegistry(unittest.TestCase):
    def test_known_engines(self):
        self.assertEqual(set(engines.ENGINE_NAMES), {"unicorn", "qiling", "icicle", "angr"})

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

    def test_binary_mode(self):
        if not os.path.exists("/bin/true"):
            self.skipTest("/bin/true not available")
        sid = _new_session(engine="angr", binary_path="/bin/true")
        try:
            out = _fn(server.emu_list_sessions)()
            self.assertIn(sid, out)
        finally:
            _fn(server.emu_close_session)(sid)


if __name__ == "__main__":
    unittest.main(verbosity=2)
