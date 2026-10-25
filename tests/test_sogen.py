"""Tests for the Sogen engine wrapper.

Sogen ships prebuilt wheels for CPython 3.9/3.10 only; on other interpreters it
is a source build.  These tests skip cleanly when `sogen` is not importable, and
exercise the real binding when it is (every check below was validated against a
source build of sogen 0.0.1.dev5822 on the Linux/unicorn backend).

Run standalone: python tests/test_sogen.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    import sogen  # noqa: F401
    HAS_SOGEN = True
except ImportError:
    HAS_SOGEN = False

if HAS_SOGEN:
    from engines.sogen_engine import SogenEngine, _norm_arch, _resolve_backend

# The engine registry is import-light and must list sogen whether or not the
# backing package is installed.
from engines import ENGINE_NAMES, ENGINE_SPECS, describe_engines


# mov rax, 0x2a ; nop ; inc rax  (x86-64) -- a self-contained snippet with no
# memory or OS dependencies, so it runs in an otherwise-empty emulator.
_CODE = bytes.fromhex("48c7c02a000000" "90" "48ffc0")
_CODE_BASE = 0x140000


class TestSogenRegistry(unittest.TestCase):
    """Registry wiring -- runs even without sogen installed."""

    def test_sogen_registered(self):
        self.assertIn("sogen", ENGINE_NAMES)
        spec = ENGINE_SPECS["sogen"]
        self.assertEqual(spec.class_name, "SogenEngine")
        self.assertEqual(spec.dependency, "sogen")

    def test_describe_engines_lists_sogen(self):
        names = {e["name"] for e in describe_engines()}
        self.assertIn("sogen", names)


@unittest.skipUnless(HAS_SOGEN, "sogen not installed")
class TestSogenHelpers(unittest.TestCase):
    def test_norm_arch(self):
        self.assertEqual(_norm_arch("x86_64"), "x86_64")
        self.assertEqual(_norm_arch("amd64"), "x86_64")
        self.assertEqual(_norm_arch("aarch64"), "arm64")
        with self.assertRaises(ValueError):
            _norm_arch("sparc")

    def test_resolve_backend(self):
        # unicorn/icicle are always valid backend names.
        self.assertIsNotNone(_resolve_backend("unicorn"))
        with self.assertRaises(ValueError):
            _resolve_backend("does_not_exist")


@unittest.skipUnless(HAS_SOGEN, "sogen not installed")
class TestSogenEngine(unittest.TestCase):
    """End-to-end against the real binding (Linux/unicorn, empty emulator)."""

    def setUp(self):
        # Linux empty emulator against the host '/', default unicorn backend.
        self.eng = SogenEngine(arch="x86_64", ostype="linux", backend="unicorn")

    def tearDown(self):
        try:
            self.eng.close()
        except Exception:
            pass

    def test_info_and_capabilities(self):
        self.assertEqual(self.eng.engine_type, "sogen")
        self.assertEqual(self.eng.arch, "x86_64")
        caps = self.eng.CAPABILITIES
        for expected in ("binary_loading", "os_emulation", "register_introspection",
                         "snapshots", "callback_hooks", "memory_hooks",
                         "memory_management", "io"):
            self.assertIn(expected, caps)
        info = self.eng.get_info()
        self.assertEqual(info["backend"], "unicorn")
        self.assertEqual(info["ostype"], "linux")

    def test_memory_roundtrip(self):
        self.eng.memory_map(_CODE_BASE, 0x1000, perms=7)
        self.eng.memory_write(_CODE_BASE, _CODE)
        self.assertEqual(self.eng.memory_read(_CODE_BASE, len(_CODE)), _CODE)

    def test_register_roundtrip_and_list(self):
        self.eng.register_write("rbx", 0x1122334455667788)
        self.assertEqual(self.eng.register_read("rbx"), 0x1122334455667788)
        regs = self.eng.list_registers()
        self.assertIn("rax", regs)
        self.assertIn("rip", regs)
        self.assertGreater(len(regs), 10)
        allregs = self.eng.registers_read_all()
        self.assertIn("rsp", allregs)

    def test_step_executes_code(self):
        self.eng.memory_map(_CODE_BASE, 0x1000, perms=7)
        self.eng.memory_write(_CODE_BASE, _CODE)
        self.eng.register_write("rip", _CODE_BASE)
        stepped = self.eng.step(2)             # mov rax,0x2a ; nop
        self.assertEqual(len(stepped), 2)
        self.assertEqual(self.eng.register_read("rax"), 0x2a)
        # First instruction is the 7-byte mov.
        self.assertEqual(stepped[0].size, 7)

    def test_code_hook_fires(self):
        self.eng.memory_map(_CODE_BASE, 0x1000, perms=7)
        self.eng.memory_write(_CODE_BASE, _CODE)
        self.eng.register_write("rip", _CODE_BASE)
        hits = []
        hid = self.eng.add_code_hook(lambda *a: hits.append(a))
        self.eng.step(2)
        self.assertEqual(len(hits), 2)
        self.assertTrue(self.eng.hook_remove(hid))

    def test_address_hook_fires(self):
        self.eng.memory_map(_CODE_BASE, 0x1000, perms=7)
        self.eng.memory_write(_CODE_BASE, _CODE)
        self.eng.register_write("rip", _CODE_BASE)
        hits = []
        self.eng.hook_address(_CODE_BASE, lambda *a: hits.append(a))
        self.eng.step(1)
        self.assertGreaterEqual(len(hits), 1)

    def test_snapshot_save_restore(self):
        self.eng.register_write("rbx", 0xAAAA)
        sid = self.eng.snapshot_save("s1")
        self.eng.register_write("rbx", 0x0)
        self.eng.snapshot_restore(sid)
        self.assertEqual(self.eng.register_read("rbx"), 0xAAAA)
        self.assertEqual(len(self.eng.snapshot_list()), 1)

    def test_memory_management(self):
        self.eng.memory_map(_CODE_BASE, 0x1000, perms=7)
        self.eng.memory_protect(_CODE_BASE, 0x1000, perms=5)   # r-x
        self.eng.memory_unmap(_CODE_BASE, 0x1000)              # release

    def test_region_info(self):
        self.eng.memory_map(0x200000, 0x2000, perms=6)
        ri = self.eng.region_info(0x200000)
        self.assertEqual(ri["start"], 0x200000)
        self.assertEqual(ri["length"], 0x2000)
        self.assertTrue(ri["is_committed"])

    def test_start_reports_stop_reason(self):
        self.eng.memory_map(0x300000, 0x1000, perms=7)
        self.eng.memory_write(0x300000, b"\x90" * 16)          # 16 nops
        self.eng.register_write("rip", 0x300000)
        self.eng._insn_limit = 4
        result = self.eng.start()
        self.assertEqual(result["status"], "stopped")
        self.assertIn("instruction_limit", str(result["stop_reason"]))

    def test_capture_output_wiring(self):
        self.eng.capture_output()
        out = self.eng.get_output()
        self.assertEqual(out["stdout"], "")
        self.assertEqual(out["stderr"], "")

    def test_memory_search_is_honest(self):
        # Sogen exposes no region enumeration; search must say so rather than
        # silently return nothing.
        with self.assertRaises(NotImplementedError):
            self.eng.memory_search(b"\x90")


if __name__ == "__main__":
    unittest.main(verbosity=2)
