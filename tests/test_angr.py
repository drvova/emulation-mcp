"""Tests for the angr engine wrapper.

Run standalone: python tests/test_angr.py
Skipped entirely if the `angr` package is not installed.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    import angr  # noqa: F401
    HAS_ANGR = True
except ImportError:
    HAS_ANGR = False

if HAS_ANGR:
    from engines.angr_engine import AngrEngine, ARCH_MAP, COMMON_REGS
    from engines.base import CODE_BASE


@unittest.skipUnless(HAS_ANGR, "angr package not installed")
class TestAngrEngine(unittest.TestCase):
    def test_create_engine(self):
        eng = AngrEngine(arch="x86_64")
        self.assertEqual(eng.arch, "x86_64")
        self.assertEqual(eng.engine_type, "angr")
        info = eng.get_info()
        self.assertIn("symbolic", info["capabilities"])
        eng.close()

    def test_invalid_arch(self):
        with self.assertRaises(ValueError):
            AngrEngine(arch="pdp11")

    def test_memory_read_write(self):
        eng = AngrEngine(arch="x86_64")
        eng.memory_write(CODE_BASE, b"\x41\x42\x43\x44")
        self.assertEqual(eng.memory_read(CODE_BASE, 4), b"\x41\x42\x43\x44")
        eng.close()

    def test_register_read_write(self):
        eng = AngrEngine(arch="x86_64")
        eng.register_write("rax", 0x1234)
        self.assertEqual(eng.register_read("rax"), 0x1234)
        eng.close()

    def test_invalid_register(self):
        eng = AngrEngine(arch="x86_64")
        with self.assertRaises(ValueError):
            eng.register_read("nonexistent_reg")
        eng.close()

    def test_concrete_run(self):
        eng = AngrEngine(arch="x86_64")
        code = (
            b"\x48\xc7\xc0\x41\x00\x00\x00"  # mov rax, 0x41
            b"\x48\xc7\xc3\x42\x00\x00\x00"  # mov rbx, 0x42
            b"\x90\x90"                        # nop; nop
        )
        eng.memory_write(CODE_BASE, code)
        result = eng.start(CODE_BASE, CODE_BASE + len(code))
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(eng.register_read("rax"), 0x41)
        self.assertEqual(eng.register_read("rbx"), 0x42)
        eng.close()

    def test_step(self):
        # step() must return the stepped instruction even without pre-enabling
        # tracing, matching the other engines.
        eng = AngrEngine(arch="x86_64")
        code = (
            b"\x48\xc7\xc0\x01\x00\x00\x00"  # mov rax, 1
            b"\x48\xc7\xc3\x02\x00\x00\x00"  # mov rbx, 2
            b"\x90"
        )
        eng.memory_write(CODE_BASE, code)
        eng.state.regs.pc = CODE_BASE
        stepped = eng.step(1)
        self.assertEqual(len(stepped), 1)
        self.assertIn("mov", stepped[0].instruction.lower())
        self.assertEqual(eng.register_read("rax"), 1)
        eng.step(1)
        self.assertEqual(eng.register_read("rbx"), 2)
        eng.close()

    def test_trace(self):
        eng = AngrEngine(arch="x86_64")
        eng.enable_tracing()
        code = b"\x48\xc7\xc0\x41\x00\x00\x00\x90"  # mov rax,0x41; nop
        eng.memory_write(CODE_BASE, code)
        eng.start(CODE_BASE, CODE_BASE + len(code))
        trace = eng.get_trace()
        self.assertTrue(any("mov" in t["instruction"].lower() for t in trace), trace)
        eng.close()

    def test_hook_address(self):
        eng = AngrEngine(arch="x86_64")
        eng.enable_tracing()
        hits = []
        eng.memory_write(CODE_BASE, b"\x90\x90\x90\x90")
        hook_id = eng.hook_address(CODE_BASE + 2, lambda e, a: hits.append(a))
        self.assertEqual(len(eng.list_hooks()), 1)
        eng.start(CODE_BASE, CODE_BASE + 4)
        self.assertTrue(any((h & ~1) == CODE_BASE + 2 for h in hits), hits)
        self.assertTrue(eng.hook_remove(hook_id))
        eng.close()

    def test_snapshot_save_restore(self):
        eng = AngrEngine(arch="x86_64")
        eng.register_write("rax", 0x1111)
        eng.memory_write(CODE_BASE, b"\xca\xfe\xba\xbe")
        snap_id = eng.snapshot_save("before")
        eng.register_write("rax", 0x9999)
        eng.memory_write(CODE_BASE, b"\x00\x00\x00\x00")
        eng.snapshot_restore(snap_id)
        self.assertEqual(eng.register_read("rax"), 0x1111)
        self.assertEqual(eng.memory_read(CODE_BASE, 4), b"\xca\xfe\xba\xbe")
        eng.close()

    def test_memory_search(self):
        eng = AngrEngine(arch="x86_64")
        pattern = b"\xCA\xFE\xBA\xBE"
        eng.memory_write(CODE_BASE + 0x100, pattern)
        results = eng.memory_search(pattern)
        self.assertIn(CODE_BASE + 0x100, results)
        eng.close()

    def test_symbolic_explore(self):
        """The headline capability: solve for an input that reaches a target.

        if ((rdi ^ 0x1234) == 0x5555) return 1 else return 0
        The solver must recover rdi = 0x1234 ^ 0x5555 = 0x4761.
        """
        eng = AngrEngine(arch="x86_64")
        code = bytes.fromhex(
            "4889f8"        # mov rax, rdi
            "483534120000"  # xor rax, 0x1234
            "483d55550000"  # cmp rax, 0x5555
            "7506"          # jne +6  -> bad
            "b801000000"    # mov eax, 1   (good, at +0x11)
            "c3"            # ret
            "31c0"          # xor eax, eax (bad, at +0x17)
            "c3"            # ret
        )
        eng.memory_write(CODE_BASE, code)
        eng.state.regs.pc = CODE_BASE
        var = eng.set_symbolic_register("rdi")
        result = eng.explore(find=[CODE_BASE + 0x11], avoid=[CODE_BASE + 0x17])
        self.assertEqual(result["status"], "found", result)
        self.assertEqual(result["found"], 1)
        sols = eng.solve(var, count=1)
        self.assertEqual(sols[0], 0x1234 ^ 0x5555)
        eng.close()

    def test_symbolic_memory(self):
        eng = AngrEngine(arch="x86_64")
        var = eng.set_symbolic_memory(0x8000000, 4, label="buf")
        self.assertTrue(any(s["name"] == var for s in eng.list_symbolic()))
        eng.close()

    def test_register_is_symbolic(self):
        eng = AngrEngine(arch="x86_64")
        self.assertFalse(eng.register_is_symbolic("rax"))
        eng.set_symbolic_register("rax")
        self.assertTrue(eng.register_is_symbolic("rax"))
        eng.close()

    def test_binary_mode(self):
        """Load a real ELF and confirm entry point / arch detection."""
        if not os.path.exists("/bin/true"):
            self.skipTest("/bin/true not available")
        eng = AngrEngine(binary_path="/bin/true")
        self.assertEqual(eng.engine_type, "angr")
        info = eng.get_info()
        self.assertIn("binary_loading", info["capabilities"])
        self.assertTrue(len(eng._regions) > 0)
        eng.close()

    def test_supported_archs_have_regs(self):
        for arch in ARCH_MAP:
            self.assertIn(arch, COMMON_REGS, f"No COMMON_REGS for {arch}")


if __name__ == "__main__":
    if not HAS_ANGR:
        print("angr not installed; skipping angr engine tests")
        sys.exit(0)
    unittest.main(verbosity=2)
