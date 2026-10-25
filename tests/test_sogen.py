"""Tests for the Sogen engine wrapper.

Sogen ships prebuilt wheels for CPython 3.9/3.10 only; on other interpreters it
is a source build.  These tests skip cleanly when `sogen` is not importable, and
exercise the real binding when it is (every check below was validated against a
source build of sogen 0.0.1.dev5822 on the Linux/unicorn backend).

Run standalone: python tests/test_sogen.py
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    import sogen  # noqa: F401
    HAS_SOGEN = True
except ImportError:
    HAS_SOGEN = False

if HAS_SOGEN:
    from engines.sogen_engine import SogenEngine, _norm_arch, _resolve_backend

HAS_GCC = shutil.which("gcc") is not None

# A freestanding, statically-linked x86-64 ELF: raw write() + exit(42) syscalls,
# no libc. Loads fast and deterministically, yet exercises binary loading, OS
# syscall emulation, stdout capture, module loading and symbolization (_start).
_FREESTANDING_C = r'''
static long sw(long fd,const void*b,long n){long r;__asm__ volatile(
  "syscall":"=a"(r):"a"(1),"D"(fd),"S"(b),"d"(n):"rcx","r11","memory");return r;}
static void sx(long c){__asm__ volatile("syscall"::"a"(60),"D"(c));}
void _start(void){const char m[]="hi from sogen test\n";sw(1,m,sizeof(m)-1);sx(42);}
'''

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

    def test_disassemble_via_capstone(self):
        self.assertIn("disassembly", self.eng.CAPABILITIES)
        self.eng.memory_map(_CODE_BASE, 0x1000, perms=7)
        self.eng.memory_write(_CODE_BASE, _CODE)       # mov rax,0x2a ; nop ; inc rax
        dis = self.eng.disassemble(_CODE_BASE, 3)
        self.assertEqual(len(dis), 3)
        self.assertTrue(dis[0]["instruction"].startswith("mov"))
        self.assertEqual(dis[1]["mnemonic"], "nop")

    def test_memory_search_scans_module_regions(self):
        # No modules loaded in an empty emulator -> nothing to scan, empty list
        # (not an error). The real search is exercised in TestSogenBinary.
        self.assertEqual(self.eng.memory_search(b"\x90"), [])

    def test_memory_stats(self):
        st = self.eng.memory_stats()
        self.assertIn("region_count", st)


@unittest.skipUnless(HAS_SOGEN, "sogen not installed")
class TestSogenBackends(unittest.TestCase):
    def test_icicle_backend_constructs(self):
        # The Ghidra SLEIGH specs ship in the sogen package; the engine points
        # the CWD at them so the icicle backend initializes instead of aborting.
        eng = SogenEngine(arch="x86_64", ostype="linux", backend="icicle")
        try:
            self.assertIn("icicle", eng.app.backend_name.lower())
        finally:
            eng.close()


@unittest.skipUnless(HAS_SOGEN and HAS_GCC, "sogen or gcc not available")
class TestSogenBinary(unittest.TestCase):
    """Real Linux ELF end-to-end: binary loading, OS emulation, symbolization."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sogen-test-")
        src = os.path.join(cls.tmp, "free.c")
        cls.bin = os.path.join(cls.tmp, "free")
        with open(src, "w") as f:
            f.write(_FREESTANDING_C)
        r = subprocess.run(["gcc", "-nostdlib", "-static", "-no-pie", "-O0",
                            "-o", cls.bin, src], capture_output=True, text=True)
        if r.returncode != 0:
            raise unittest.SkipTest(f"gcc failed: {r.stderr}")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.eng = SogenEngine(arch="x86_64", ostype="linux", binary_path=self.bin)

    def tearDown(self):
        try:
            self.eng.close()
        except Exception:
            pass

    def test_run_captures_stdout_and_exit(self):
        self.eng.capture_output()
        res = self.eng.start()
        self.assertEqual(res["status"], "stopped")
        self.assertEqual(self.eng.get_output()["stdout"], "hi from sogen test\n")
        self.assertEqual(self.eng._exit_status(), 42)

    def test_syscall_stats(self):
        self.eng.start()
        ss = self.eng.syscall_stats()
        self.assertGreater(ss["total"], 0)
        self.assertIn("write", ss["syscalls"])

    def test_list_modules(self):
        self.eng.start()
        mods = self.eng.list_modules()
        self.assertTrue(any(m["name"] == "free" for m in mods))
        free = next(m for m in mods if m["name"] == "free")
        self.assertIsNotNone(free["image_base"])
        self.assertGreater(free["exports"], 0)

    def test_symbolization_roundtrip(self):
        self.eng.start()
        self.assertGreater(self.eng.load_symbols(), 0)
        addr = self.eng.lookup_symbol("_start")
        self.assertIsNotNone(addr)
        sym = self.eng.symbolize(addr)
        self.assertEqual(sym["name"], "_start")
        self.assertEqual(sym["offset"], 0)

    def test_list_symbols(self):
        self.eng.start()
        syms = self.eng.list_symbols()
        self.assertTrue(any(s["name"] == "_start" for s in syms))
        self.assertTrue(all(s["address"].startswith("0x") for s in syms))

    def test_memory_maps_and_search(self):
        self.eng.start()
        maps = self.eng.memory_maps()
        self.assertTrue(any(m["label"] == "free" for m in maps))
        # The ELF header magic lives at the image base of the loaded module.
        hits = self.eng.memory_search(b"\x7fELF")
        self.assertGreater(len(hits), 0)

    def test_disassemble_entry(self):
        self.eng.start()
        mods = self.eng.list_modules()
        entry = next(m for m in mods if m["name"] == "free")["entry_point"]
        dis = self.eng.disassemble(entry, 2)
        self.assertEqual(len(dis), 2)
        self.assertTrue(all("instruction" in d for d in dis))


if __name__ == "__main__":
    unittest.main(verbosity=2)
