"""Tests for the Qiling engine wrapper.

Run standalone: python tests/test_qiling.py
"""

import os
import sys
import unittest

# Ensure the project root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    import qiling  # noqa: F401
    HAS_QILING = True
except ImportError:
    HAS_QILING = False

if HAS_QILING:
    from engines.qiling_engine import (
        QilingEngine,
        resolve_arch,
        resolve_os,
        ARCH_MAP,
        OS_MAP,
        COMMON_REGS,
    )
    from engines.base import HookInfo, SnapshotInfo, TraceEntry
    from qiling.const import QL_ARCH, QL_OS


# Path to an optional real rootfs for integration tests
ROOTFS_PATH = os.environ.get("QILING_ROOTFS", "")
HAS_ROOTFS = os.path.isdir(ROOTFS_PATH)


# A self-contained rootfs of tiny *statically linked* Linux/x86-64 binaries.
# Static linking means no shared libraries are needed, so Qiling can run them
# with a minimal rootfs (just the binaries) and the extended-feature tests work
# anywhere gcc is available — no external rootfs download required.
_MINI_SOURCES = {
    "hello": '#include <unistd.h>\n#include <string.h>\n'
             'int main(void){const char*m="hi from qiling\\n";write(1,m,strlen(m));return 7;}\n',
    "echo":  '#include <unistd.h>\n'
             'int main(void){char b[64];int n=read(0,b,sizeof b);if(n>0)write(1,b,n);return 0;}\n',
    "catflag": '#include <unistd.h>\n#include <fcntl.h>\n'
               'int main(void){char b[64];int fd=open("/flag.txt",0);'
               'if(fd<0){write(1,"noflag\\n",7);return 1;}'
               'int n=read(fd,b,sizeof b);if(n>0)write(1,b,n);return 0;}\n',
}
_mini_rootfs_cache = {}  # None = build attempted and failed


def build_mini_rootfs():
    """Build the static-binary rootfs once; return (rootfs_dir, {name: path}) or None."""
    import shutil, subprocess, tempfile
    if "result" in _mini_rootfs_cache:
        return _mini_rootfs_cache["result"]
    result = None
    if shutil.which("gcc") is not None:
        d = tempfile.mkdtemp(prefix="ql_mini_rootfs_")
        paths = {}
        ok = True
        for name, src in _MINI_SOURCES.items():
            cpath = os.path.join(d, name + ".c")
            opath = os.path.join(d, name)
            with open(cpath, "w") as f:
                f.write(src)
            try:
                subprocess.run(["gcc", "-static", "-O0", "-o", opath, cpath],
                               check=True, capture_output=True, timeout=60)
                paths[name] = opath
            except Exception:
                ok = False
                break
        result = (d, paths) if ok else None
    _mini_rootfs_cache["result"] = result
    return result


HAS_MINI_ROOTFS = build_mini_rootfs() is not None


@unittest.skipUnless(HAS_QILING, "qiling not installed")
class TestArchMapping(unittest.TestCase):
    """Test architecture and OS string resolution."""

    def test_resolve_arch_x86(self):
        self.assertEqual(resolve_arch("x86"), QL_ARCH.X86)

    def test_resolve_arch_x86_64(self):
        self.assertEqual(resolve_arch("x86_64"), QL_ARCH.X8664)

    def test_resolve_arch_arm(self):
        self.assertEqual(resolve_arch("arm"), QL_ARCH.ARM)

    def test_resolve_arch_arm64(self):
        self.assertEqual(resolve_arch("arm64"), QL_ARCH.ARM64)

    def test_resolve_arch_mips(self):
        self.assertEqual(resolve_arch("mips"), QL_ARCH.MIPS)

    def test_resolve_arch_case_insensitive(self):
        self.assertEqual(resolve_arch("X86"), QL_ARCH.X86)
        self.assertEqual(resolve_arch("ARM64"), QL_ARCH.ARM64)
        self.assertEqual(resolve_arch("MIPS"), QL_ARCH.MIPS)

    def test_resolve_arch_invalid(self):
        with self.assertRaises(ValueError) as ctx:
            resolve_arch("sparc")
        self.assertIn("Unsupported architecture", str(ctx.exception))
        self.assertIn("sparc", str(ctx.exception))

    def test_resolve_os_linux(self):
        self.assertEqual(resolve_os("linux"), QL_OS.LINUX)

    def test_resolve_os_windows(self):
        self.assertEqual(resolve_os("windows"), QL_OS.WINDOWS)

    def test_resolve_os_freebsd(self):
        self.assertEqual(resolve_os("freebsd"), QL_OS.FREEBSD)

    def test_resolve_os_case_insensitive(self):
        self.assertEqual(resolve_os("LINUX"), QL_OS.LINUX)
        self.assertEqual(resolve_os("Windows"), QL_OS.WINDOWS)

    def test_resolve_os_invalid(self):
        with self.assertRaises(ValueError) as ctx:
            resolve_os("solaris")
        self.assertIn("Unsupported OS type", str(ctx.exception))


@unittest.skipUnless(HAS_QILING, "qiling not installed")
class TestCommonRegs(unittest.TestCase):
    """Test that common register lists are defined for key architectures."""

    def test_x86_regs_defined(self):
        self.assertIn("x86", COMMON_REGS)
        self.assertIn("eax", COMMON_REGS["x86"])
        self.assertIn("eip", COMMON_REGS["x86"])

    def test_x86_64_regs_defined(self):
        self.assertIn("x86_64", COMMON_REGS)
        self.assertIn("rax", COMMON_REGS["x86_64"])
        self.assertIn("rip", COMMON_REGS["x86_64"])

    def test_arm_regs_defined(self):
        self.assertIn("arm", COMMON_REGS)
        self.assertIn("r0", COMMON_REGS["arm"])
        self.assertIn("pc", COMMON_REGS["arm"])

    def test_mips_regs_defined(self):
        self.assertIn("mips", COMMON_REGS)
        self.assertIn("v0", COMMON_REGS["mips"])
        self.assertIn("ra", COMMON_REGS["mips"])


@unittest.skipUnless(HAS_QILING, "qiling not installed")
class TestQilingEngineInit(unittest.TestCase):
    """Test QilingEngine initialization and error handling."""

    def test_missing_binary_gives_clear_error(self):
        """A non-existent binary should produce a clear RuntimeError."""
        with self.assertRaises(RuntimeError) as ctx:
            QilingEngine(
                binary_path="/nonexistent/binary",
                rootfs="/tmp",
                arch="arm",
                ostype="linux",
            )
        error_msg = str(ctx.exception)
        self.assertTrue(
            "not found" in error_msg.lower()
            or "failed to initialize" in error_msg.lower()
            or "no such file" in error_msg.lower(),
            f"Expected clear error message, got: {error_msg}"
        )

    def test_invalid_arch_raises(self):
        """An unsupported arch string should raise ValueError."""
        with self.assertRaises(ValueError):
            QilingEngine(
                binary_path="/bin/ls",
                rootfs="/tmp",
                arch="sparc",
            )

    def test_invalid_os_raises(self):
        """An unsupported OS type should raise ValueError."""
        with self.assertRaises(ValueError):
            QilingEngine(
                binary_path="/bin/ls",
                rootfs="/tmp",
                arch="arm",
                ostype="solaris",
            )


@unittest.skipUnless(HAS_QILING, "qiling not installed")
class TestQilingEngineImport(unittest.TestCase):
    """Verify that the module imports cleanly."""

    def test_import_engine(self):
        from engines.qiling_engine import QilingEngine
        self.assertTrue(callable(QilingEngine))

    def test_inherits_base(self):
        from engines.base import BaseEngine
        self.assertTrue(issubclass(QilingEngine, BaseEngine))

    def test_arch_map_completeness(self):
        """All key architectures are in the map."""
        for name in ("x86", "x86_64", "arm", "arm64", "mips"):
            self.assertIn(name, ARCH_MAP, f"Missing arch: {name}")

    def test_os_map_completeness(self):
        """All key OS types are in the map."""
        for name in ("linux", "windows", "freebsd"):
            self.assertIn(name, OS_MAP, f"Missing OS: {name}")


@unittest.skipUnless(HAS_QILING and HAS_ROOTFS, f"qiling/rootfs not available ({ROOTFS_PATH})")
class TestQilingEngineIntegration(unittest.TestCase):
    """Integration tests that require a real rootfs.

    These are skipped unless the Netgear rootfs is available.
    """

    def _find_test_binary(self) -> str | None:
        """Find a small ARM binary in the rootfs for testing."""
        candidates = [
            os.path.join(ROOTFS_PATH, "bin", "busybox"),
            os.path.join(ROOTFS_PATH, "bin", "ls"),
            os.path.join(ROOTFS_PATH, "bin", "echo"),
            os.path.join(ROOTFS_PATH, "usr", "bin", "id"),
        ]
        for path in candidates:
            if os.path.isfile(path):
                return path
        return None

    def test_engine_instantiation(self):
        """Can create a QilingEngine with a real binary and rootfs."""
        binary = self._find_test_binary()
        if binary is None:
            self.skipTest("No suitable test binary found in rootfs")

        engine = QilingEngine(
            binary_path=binary,
            rootfs=ROOTFS_PATH,
            arch="arm",
            ostype="linux",
        )
        self.assertEqual(engine.engine_type, "qiling")
        self.assertEqual(engine.arch, "arm")
        info = engine.get_info()
        self.assertEqual(info["engine_type"], "qiling")
        engine.close()


@unittest.skipUnless(HAS_QILING and HAS_MINI_ROOTFS,
                     "qiling or gcc (for the static-binary rootfs) not available")
class TestQilingExtended(unittest.TestCase):
    """Extended-feature tests on a self-built static-binary rootfs."""

    @classmethod
    def setUpClass(cls):
        cls.rootfs, cls.bins = build_mini_rootfs()

    def _engine(self, name):
        return QilingEngine(binary_path=self.bins[name], rootfs=self.rootfs,
                            arch="x86_64", ostype="linux")

    def test_capabilities_present(self):
        eng = self._engine("hello")
        for cap in ("memory_hooks", "callback_hooks", "disassembly",
                    "register_introspection", "filesystem", "io"):
            self.assertIn(cap, eng.CAPABILITIES)
        eng.close()

    def test_disassemble(self):
        eng = self._engine("hello")
        insns = eng.disassemble(eng.ql.loader.entry_point, 3)
        self.assertEqual(len(insns), 3)
        self.assertTrue(all("instruction" in i and i["address"].startswith("0x") for i in insns))
        eng.close()

    def test_list_registers(self):
        eng = self._engine("hello")
        regs = eng.list_registers()
        self.assertGreater(len(regs), 50)
        self.assertIn("rip", regs)
        self.assertIn("value", regs["rip"])
        eng.close()

    def test_memory_maps(self):
        eng = self._engine("hello")
        maps = eng.memory_maps()
        self.assertGreater(len(maps), 0)
        self.assertTrue(all({"start", "end", "perms"} <= set(m) for m in maps))
        eng.close()

    def test_code_and_mem_hooks_fire(self):
        eng = self._engine("hello")
        hits = [0]
        writes = []
        eng.add_code_hook(lambda ql, a, s: hits.__setitem__(0, hits[0] + 1))
        eng.add_mem_hook(lambda ql, acc, a, s, v: writes.append(a), kind="write")
        eng.start()
        self.assertGreater(hits[0], 0)
        self.assertGreater(len(writes), 0)
        eng.close()

    def test_hook_remove(self):
        eng = self._engine("hello")
        hid = eng.add_code_hook(lambda ql, a, s: None)
        self.assertEqual(len(eng.list_hooks()), 1)
        self.assertTrue(eng.hook_remove(hid))
        self.assertEqual(eng.list_hooks(), [])
        eng.close()

    def test_bad_mem_hook_kind(self):
        eng = self._engine("hello")
        with self.assertRaises(ValueError):
            eng.add_mem_hook(lambda *a: None, kind="exec")
        eng.close()

    def test_capture_stdout(self):
        eng = self._engine("hello")
        eng.capture_output()
        eng.start()
        self.assertEqual(eng.get_output()["stdout"], "hi from qiling\n")
        eng.close()

    def test_get_output_before_capture_errors(self):
        eng = self._engine("hello")
        with self.assertRaises(RuntimeError):
            eng.get_output()
        eng.close()

    def test_set_stdin_echo(self):
        eng = self._engine("echo")
        eng.set_stdin(b"piped-input\n")
        eng.capture_output()
        eng.start()
        self.assertEqual(eng.get_output()["stdout"], "piped-input\n")
        eng.close()

    def test_fs_mapper(self):
        import tempfile
        d = tempfile.mkdtemp()
        flag = os.path.join(d, "flag")
        with open(flag, "w") as f:
            f.write("FLAG{qiling-fs}")
        eng = self._engine("catflag")
        eng.add_fs_mapper("/flag.txt", flag)
        eng.capture_output()
        eng.start()
        self.assertEqual(eng.get_output()["stdout"], "FLAG{qiling-fs}")
        eng.close()

    def test_fs_mapper_missing_host(self):
        eng = self._engine("hello")
        with self.assertRaises(FileNotFoundError):
            eng.add_fs_mapper("/x", "/no/such/host/path/xyz")
        eng.close()

    def test_syscall_observe_keeps_behaviour(self):
        eng = self._engine("hello")
        seen = []
        eng.hook_syscall("write", lambda ql, *a, **k: seen.append(1), when="enter")
        eng.capture_output()
        eng.start()
        self.assertGreater(len(seen), 0)               # observer fired
        self.assertEqual(eng.get_output()["stdout"], "hi from qiling\n")  # behaviour intact
        eng.close()

    def test_bad_when_rejected(self):
        eng = self._engine("hello")
        with self.assertRaises(ValueError):
            eng.hook_syscall("write", when="whenever")
        eng.close()

    def test_read_string(self):
        eng = self._engine("hello")
        addr = eng.ql.loader.entry_point
        eng.memory_write(addr, b"hello world\x00trailing")
        self.assertEqual(eng.read_string(addr), "hello world")
        eng.close()


if __name__ == "__main__":
    # Print diagnostic info
    print(f"Qiling engine test suite")
    print(f"Rootfs at {ROOTFS_PATH}: {'FOUND' if HAS_ROOTFS else 'NOT FOUND (integration tests will be skipped)'}")
    print()
    unittest.main(verbosity=2)
