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

    def test_call_function(self):
        # int f(int a, int b){ return a + b; }  ->  lea eax,[rdi+rsi]; ret
        eng = AngrEngine(arch="x86_64")
        eng.memory_write(CODE_BASE, bytes.fromhex("8d0437" "c3"))
        result = eng.call_function(CODE_BASE, [3, 4])
        self.assertIsNotNone(result.get("return_value"), result)
        self.assertEqual(result["return_value"]["int"], 7)
        self.assertIn("function_call", eng.CAPABILITIES)
        eng.close()

    def test_cfg_and_functions(self):
        eng = AngrEngine(arch="x86_64")
        eng.memory_write(CODE_BASE, bytes.fromhex("8d0437" "c3" "9090" "b800000000" "c3"))
        cfg = eng.recover_cfg(fast=True)
        self.assertNotIn("error", cfg, cfg)
        self.assertGreaterEqual(len(cfg["functions"]), 1)
        self.assertGreaterEqual(len(eng.list_functions()), 1)
        self.assertIn("cfg", eng.CAPABILITIES)
        eng.close()

    def test_explore_with_techniques(self):
        # Same crackme as test_symbolic_explore, but drive it with DFS + a
        # length limiter to prove techniques are accepted and still solve.
        eng = AngrEngine(arch="x86_64")
        code = ("4889f8" "483534120000" "483d55550000"
                "7506" "b801000000" "c3" "31c0" "c3")
        eng.memory_write(CODE_BASE, bytes.fromhex(code))
        eng.state.regs.pc = CODE_BASE
        var = eng.set_symbolic_register("rdi")
        result = eng.explore(find=[CODE_BASE + 0x11], avoid=[CODE_BASE + 0x17],
                             techniques=["dfs", "lengthlimiter:1000"])
        self.assertEqual(result["status"], "found", result)
        self.assertEqual(eng.solve(var, 1)[0], 0x1234 ^ 0x5555)
        eng.close()


@unittest.skipUnless(HAS_ANGR, "angr package not installed")
class TestAngrInspectHooks(unittest.TestCase):
    def test_mem_write_inspect_fires_and_removes(self):
        eng = AngrEngine(arch="x86_64")
        self.assertIn("inspection", eng.CAPABILITIES)
        seen = []
        hid = eng.add_inspect_hook(
            "mem_write",
            lambda s: seen.append((
                s.solver.eval(s.inspect.attrs.mem_write_address),
                s.solver.eval(s.inspect.attrs.mem_write_expr))),
            when="before")
        eng.memory_write(0x8000000, b"\xde\xad\xbe\xef")
        self.assertIn((0x8000000, 0xdeadbeef), seen)
        self.assertTrue(eng.hook_remove(hid))
        seen.clear()
        eng.memory_write(0x8000000, b"\x11\x22\x33\x44")
        self.assertEqual(seen, [])  # removed -> no more events
        eng.close()

    def test_bad_event_rejected(self):
        eng = AngrEngine(arch="x86_64")
        with self.assertRaises(ValueError):
            eng.add_inspect_hook("not_an_event", lambda s: None)
        eng.close()


@unittest.skipUnless(HAS_ANGR, "angr package not installed")
class TestAngrConstraints(unittest.TestCase):
    def test_range_and_satisfiability(self):
        eng = AngrEngine(arch="x86_64")
        self.assertIn("constraints", eng.CAPABILITIES)
        var = eng.set_symbolic_register("rdi")
        self.assertTrue(eng.add_constraint(var, ">", 10)["satisfiable"])
        self.assertTrue(eng.add_constraint(var, "<", 20)["satisfiable"])
        r = eng.value_range(var)
        self.assertEqual((r["min"], r["max"]), (11, 19))
        self.assertTrue(eng.is_satisfiable())
        # Over-constrain into unsatisfiability.
        self.assertFalse(eng.add_constraint(var, ">", 100)["satisfiable"])
        self.assertFalse(eng.is_satisfiable())
        eng.close()

    def test_unique_value(self):
        eng = AngrEngine(arch="x86_64")
        var = eng.set_symbolic_register("rsi")
        eng.add_constraint(var, "==", 0x2a)
        r = eng.value_range(var)
        self.assertTrue(r["unique"])
        self.assertEqual(r["min"], 0x2a)
        eng.close()

    def test_unknown_var_and_bad_op(self):
        eng = AngrEngine(arch="x86_64")
        with self.assertRaises(KeyError):
            eng.add_constraint("nope", "==", 1)
        var = eng.set_symbolic_register("rdi")
        with self.assertRaises(ValueError):
            eng.add_constraint(var, "<=>", 1)
        eng.close()


@unittest.skipUnless(HAS_ANGR, "angr package not installed")
class TestAngrSimProcedures(unittest.TestCase):
    # int add(int a,int b){return a+b;}  ->  lea eax,[rdi+rsi]; ret
    _ADD = bytes.fromhex("8d0437" "c3")

    def test_hook_function_forces_return(self):
        eng = AngrEngine(arch="x86_64")
        self.assertIn("sim_procedures", eng.CAPABILITIES)
        eng.memory_write(CODE_BASE, self._ADD)
        self.assertEqual(eng.call_function(CODE_BASE, [3, 4])["return_value"]["int"], 7)
        hid = eng.hook_function(CODE_BASE, return_value=0x63)
        self.assertEqual(eng.call_function(CODE_BASE, [3, 4])["return_value"]["int"], 0x63)
        # Removing the hook restores the real implementation.
        self.assertTrue(eng.hook_remove(hid))
        self.assertEqual(eng.call_function(CODE_BASE, [3, 4])["return_value"]["int"], 7)
        eng.close()

    def test_hook_function_unconstrained(self):
        eng = AngrEngine(arch="x86_64")
        eng.memory_write(CODE_BASE, self._ADD)
        hid = eng.hook_function(CODE_BASE, return_value=None)
        # Must not raise; returns a (symbolic -> concretized) value.
        res = eng.call_function(CODE_BASE, [3, 4])
        self.assertNotIn("error", res, res)
        self.assertTrue(eng.hook_remove(hid))
        eng.close()

    def test_hook_skip_install_remove(self):
        eng = AngrEngine(arch="x86_64")
        eng.memory_write(CODE_BASE, self._ADD)
        hid = eng.hook_skip(CODE_BASE, 0)
        self.assertEqual(len(eng.list_hooks()), 1)
        self.assertTrue(eng.hook_remove(hid))
        self.assertEqual(eng.list_hooks(), [])
        eng.close()


@unittest.skipUnless(HAS_ANGR, "angr package not installed")
class TestAngrDecompiler(unittest.TestCase):
    def test_decompile_and_function_info_shellcode(self):
        eng = AngrEngine(arch="x86_64")
        self.assertIn("decompiler", eng.CAPABILITIES)
        eng.memory_write(CODE_BASE, bytes.fromhex("8d0437" "c3"))  # add; ret
        eng.recover_cfg(fast=True)
        info = eng.function_info(CODE_BASE)
        self.assertNotIn("error", info, info)
        self.assertTrue(info["returning"])
        self.assertGreaterEqual(info["size"], 1)
        dec = eng.decompile_function(CODE_BASE)
        self.assertNotIn("error", dec, dec)
        self.assertIn("return", dec["code"])
        eng.close()

    def test_function_info_missing(self):
        eng = AngrEngine(arch="x86_64")
        eng.recover_cfg(fast=True)
        res = eng.function_info(CODE_BASE + 0x3000)  # nothing recovered there
        self.assertIn("error", res)
        eng.close()

    def test_callers_callees_on_binary(self):
        import shutil, subprocess, tempfile
        if shutil.which("gcc") is None:
            self.skipTest("gcc unavailable")
        tmp = tempfile.mkdtemp()
        src, out = os.path.join(tmp, "t.c"), os.path.join(tmp, "t")
        with open(src, "w") as f:
            f.write("int add(int a,int b){return a+b;}\n"
                    "int main(int c,char**v){return add(c,7);}\n")
        try:
            subprocess.run(["gcc", "-static", "-O0", "-o", out, src],
                           check=True, capture_output=True, timeout=60)
        except Exception:
            self.skipTest("could not build static binary")
        eng = AngrEngine(binary_path=out)
        cfg = eng.recover_cfg(fast=True)
        byname = {f["name"]: int(f["address"], 16) for f in cfg["functions"]}
        self.assertIn("add", byname)
        self.assertIn("main", byname)
        self.assertIn("add", eng.function_info(byname["main"])["callees"])
        self.assertIn("main", eng.function_info(byname["add"])["callers"])
        eng.close()


# A freestanding (no-libc) binary keeps angr's heavy emulated analyses (DDG/CDG/
# backward slice) tractable; built once, gated on gcc.
_FREESTANDING_SRC = (
    'static long _x(int c){long r;__asm__ volatile("syscall":"=a"(r):"a"(60),"D"(c)'
    ':"rcx","r11","memory");return r;}\n'
    'int compute(int a,int b){int s=a+b;if(s==12)return s*2;return s;}\n'
    'void _start(void){int r=compute(5,7);_x(r);}\n'
)
_free_bin_cache = {}


def build_freestanding():
    import shutil, subprocess, tempfile
    if "p" in _free_bin_cache:
        return _free_bin_cache["p"]
    p = None
    if shutil.which("gcc") is not None:
        d = tempfile.mkdtemp(prefix="angr_free_")
        src, out = os.path.join(d, "f.c"), os.path.join(d, "f")
        with open(src, "w") as f:
            f.write(_FREESTANDING_SRC)
        try:
            subprocess.run(["gcc", "-nostdlib", "-static", "-O0", "-o", out, src],
                           check=True, capture_output=True, timeout=60)
            p = out
        except Exception:
            p = None
    _free_bin_cache["p"] = p
    return p


HAS_FREESTANDING = HAS_ANGR and build_freestanding() is not None


@unittest.skipUnless(HAS_FREESTANDING, "angr or gcc (for a freestanding binary) not available")
class TestAngrDataflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bin = build_freestanding()

    def _loaded(self):
        eng = AngrEngine(binary_path=self.bin)
        cfg = eng.recover_cfg(fast=True)
        byname = {f["name"]: int(f["address"], 16) for f in cfg["functions"]}
        return eng, byname

    def test_capability(self):
        eng = AngrEngine(binary_path=self.bin)
        self.assertIn("dataflow", eng.CAPABILITIES)
        eng.close()

    def test_reaching_definitions(self):
        eng, byname = self._loaded()
        r = eng.reaching_definitions(byname["compute"])
        self.assertNotIn("error", r, r)
        self.assertGreater(r["definitions"], 0)
        self.assertIn("Register", r["by_kind"])
        eng.close()

    def test_data_dependencies(self):
        eng, byname = self._loaded()
        r = eng.data_dependencies(byname["compute"])
        self.assertNotIn("error", r, r)
        self.assertGreater(r["nodes"], 0)
        eng.close()

    def test_backward_slice_nonempty_somewhere(self):
        eng, byname = self._loaded()
        fn = eng.proj.kb.functions.get_by_addr(byname["compute"])
        # Some target in the function must yield a non-empty slice.
        best = 0
        for baddr in sorted(fn.block_addrs):
            r = eng.backward_slice(baddr)
            self.assertNotIn("error", r, r)
            best = max(best, r["block_count"])
        self.assertGreater(best, 0, "no block produced a non-empty backward slice")
        eng.close()

    def test_dataflow_missing_function(self):
        eng = AngrEngine(binary_path=self.bin)
        eng.recover_cfg(fast=True)
        self.assertIn("error", eng.reaching_definitions(0xdeadbeef))
        eng.close()


if __name__ == "__main__":
    if not HAS_ANGR:
        print("angr not installed; skipping angr engine tests")
        sys.exit(0)
    unittest.main(verbosity=2)
