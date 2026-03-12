"""Tests for the Qiling engine wrapper.

Run standalone: python tests/test_qiling.py
"""

import os
import sys
import unittest

# Ensure the project root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

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


@unittest.skipUnless(HAS_ROOTFS, f"Rootfs not found at {ROOTFS_PATH}")
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


if __name__ == "__main__":
    # Print diagnostic info
    print(f"Qiling engine test suite")
    print(f"Rootfs at {ROOTFS_PATH}: {'FOUND' if HAS_ROOTFS else 'NOT FOUND (integration tests will be skipped)'}")
    print()
    unittest.main(verbosity=2)
