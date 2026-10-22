"""Tests for the Icicle engine wrapper.

Run standalone: python tests/test_icicle.py
Skipped entirely if the `icicle` package is not installed.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    import icicle  # noqa: F401
    HAS_ICICLE = True
except ImportError:
    HAS_ICICLE = False

if HAS_ICICLE:
    from engines.icicle_engine import IcicleEngine, ARCH_MAP, COMMON_REGS
    from engines.base import CODE_BASE, HEAP_BASE

    def _detect_caps():
        eng = IcicleEngine(arch="x86_64")
        caps = set(eng.CAPABILITIES)
        has_linux = eng._has_linux
        eng.close()
        return caps, has_linux

    EXT_CAPS, HAS_LINUX_BINDING = _detect_caps()
else:
    EXT_CAPS, HAS_LINUX_BINDING = set(), False


@unittest.skipUnless(HAS_ICICLE, "icicle package not installed")
class TestIcicleEngine(unittest.TestCase):
    def test_create_engine(self):
        eng = IcicleEngine(arch="x86_64")
        self.assertEqual(eng.arch, "x86_64")
        self.assertEqual(eng.engine_type, "icicle")
        info = eng.get_info()
        self.assertEqual(info["engine_type"], "icicle")
        self.assertIn("shellcode", info["capabilities"])
        eng.close()

    def test_invalid_arch(self):
        with self.assertRaises(ValueError):
            IcicleEngine(arch="pdp11")

    def test_memory_read_write(self):
        eng = IcicleEngine(arch="x86_64")
        eng.memory_write(CODE_BASE, b"\x41\x42\x43\x44")
        self.assertEqual(eng.memory_read(CODE_BASE, 4), b"\x41\x42\x43\x44")
        eng.memory_write(CODE_BASE + 0x100, b"\xde\xad\xbe\xef")
        self.assertEqual(eng.memory_read(CODE_BASE + 0x100, 4), b"\xde\xad\xbe\xef")
        eng.close()

    def test_register_read_write(self):
        eng = IcicleEngine(arch="x86_64")
        eng.register_write("rax", 0x1234)
        self.assertEqual(eng.register_read("rax"), 0x1234)
        eng.register_write("rbx", 0xDEADBEEF)
        self.assertEqual(eng.register_read("rbx"), 0xDEADBEEF)
        eng.close()

    def test_registers_read_all(self):
        eng = IcicleEngine(arch="x86_64")
        eng.register_write("rax", 0xAAAA)
        regs = eng.registers_read_all()
        self.assertIn("rax", regs)
        self.assertIn("rsp", regs)
        self.assertEqual(regs["rax"], 0xAAAA)
        eng.close()

    def test_invalid_register(self):
        eng = IcicleEngine(arch="x86_64")
        with self.assertRaises(ValueError):
            eng.register_read("nonexistent_reg")
        eng.close()

    def test_execute_shellcode_native(self):
        """Run without tracing (native run_until path)."""
        eng = IcicleEngine(arch="x86_64")
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

    def test_execute_shellcode_traced(self):
        """Run with tracing (step loop path) and verify the trace."""
        eng = IcicleEngine(arch="x86_64")
        eng.enable_tracing()
        code = (
            b"\x48\xc7\xc0\x41\x00\x00\x00"  # mov rax, 0x41
            b"\x48\xc7\xc3\x42\x00\x00\x00"  # mov rbx, 0x42
            b"\x90\x90"                        # nop; nop
        )
        eng.memory_write(CODE_BASE, code)
        result = eng.start(CODE_BASE, CODE_BASE + len(code))
        self.assertEqual(result["status"], "ok", result)
        trace = eng.get_trace()
        self.assertEqual(len(trace), 4, trace)
        self.assertIn("mov", trace[0]["instruction"].lower())
        self.assertIn("nop", trace[2]["instruction"].lower())
        eng.close()

    def test_step(self):
        eng = IcicleEngine(arch="x86_64")
        code = (
            b"\x48\xc7\xc0\x01\x00\x00\x00"  # mov rax, 1
            b"\x48\xc7\xc3\x02\x00\x00\x00"  # mov rbx, 2
            b"\x90"                            # nop
        )
        eng.memory_write(CODE_BASE, code)
        eng.vm.pc = CODE_BASE
        stepped = eng.step(1)
        self.assertEqual(len(stepped), 1)
        self.assertEqual(eng.register_read("rax"), 1)
        stepped = eng.step(1)
        self.assertEqual(eng.register_read("rbx"), 2)
        eng.close()

    def test_hook_address(self):
        eng = IcicleEngine(arch="x86_64")
        hits = []

        def my_hook(engine, address):
            hits.append(address)

        eng.memory_write(CODE_BASE, b"\x90\x90\x90\x90")  # nop x4
        hook_id = eng.hook_address(CODE_BASE + 2, my_hook)
        self.assertTrue(hook_id.startswith("hook-"))
        self.assertEqual(len(eng.list_hooks()), 1)
        result = eng.start(CODE_BASE, CODE_BASE + 4)
        self.assertEqual(result["status"], "ok", result)
        # The hook must fire exactly once — a stalled step loop would record it
        # thousands of times before the deadline.
        self.assertEqual(hits, [CODE_BASE + 2])
        self.assertTrue(eng.hook_remove(hook_id))
        self.assertEqual(len(eng.hooks), 0)
        eng.close()

    def test_logging_hook_terminates(self):
        """A hook with no callback must not stall the run loop."""
        eng = IcicleEngine(arch="x86_64")
        eng.memory_write(CODE_BASE, b"\x90\x90\x90\x90")
        eng.hook_address(CODE_BASE + 1)  # logging-only hook
        result = eng.start(CODE_BASE, CODE_BASE + 4, timeout_ms=5000)
        self.assertEqual(result["status"], "ok", result)
        logged = [t for t in eng.get_trace() if t["type"] == "hook"]
        self.assertEqual(len(logged), 1, logged)
        eng.close()

    def test_self_modifying_code_reported(self):
        """Intra-block self-modification is reported, not silently mis-run."""
        eng = IcicleEngine(arch="x86_64")
        # lea rsi,[rip+N]; add byte [rsi], 0xff; mov rax, <imm>
        code = bytearray.fromhex("488d3500000000" "8006ff" "48c7c011000000")
        imm_off = 13
        code[3] = imm_off - 7
        eng.memory_write(CODE_BASE, bytes(code))
        result = eng.start(CODE_BASE, CODE_BASE + len(code))
        self.assertEqual(result["status"], "self_modifying_code", result)
        self.assertIn("self-modifying", result["error"].lower())
        eng.close()

    def test_snapshot_save_restore(self):
        eng = IcicleEngine(arch="x86_64")
        eng.register_write("rax", 0x1111)
        eng.register_write("rbx", 0x2222)
        eng.memory_write(CODE_BASE, b"\xca\xfe\xba\xbe")
        snap_id = eng.snapshot_save("before")
        eng.register_write("rax", 0x9999)
        eng.memory_write(CODE_BASE, b"\x00\x00\x00\x00")
        eng.snapshot_restore(snap_id)
        self.assertEqual(eng.register_read("rax"), 0x1111)
        self.assertEqual(eng.register_read("rbx"), 0x2222)
        self.assertEqual(eng.memory_read(CODE_BASE, 4), b"\xca\xfe\xba\xbe")
        self.assertEqual(len(eng.snapshot_list()), 1)
        eng.close()

    def test_memory_search(self):
        eng = IcicleEngine(arch="x86_64")
        pattern = b"\xCA\xFE\xBA\xBE"
        eng.memory_write(CODE_BASE + 0x100, pattern)
        eng.memory_write(CODE_BASE + 0x500, pattern)
        results = eng.memory_search(pattern)
        self.assertIn(CODE_BASE + 0x100, results)
        self.assertIn(CODE_BASE + 0x500, results)
        self.assertEqual(eng.memory_search(b"\xFF\xFE\xFD\xFC\xFB\xFA"), [])
        eng.close()

    def test_memory_map(self):
        eng = IcicleEngine(arch="x86_64")
        eng.memory_map(0xA000000, 0x1000, perms=7)
        eng.memory_write(0xA000000, b"\x41\x42\x43")
        self.assertEqual(eng.memory_read(0xA000000, 3), b"\x41\x42\x43")
        eng.close()

    def test_error_handling(self):
        eng = IcicleEngine(arch="x86_64")
        with self.assertRaises(RuntimeError):
            eng.memory_read(0xFFFF0000000, 4)
        eng.close()

    def test_supported_architectures(self):
        """Every mapped architecture instantiates and runs a trivial snippet."""
        # (arch, shellcode setting a return reg to 0x41, reg name, expected)
        snippets = {
            "x86":       ("b841000000", "eax", 0x41),
            "x86_64":    ("48c7c041000000", "rax", 0x41),
            "arm":       ("4100a0e3", "r0", 0x41),
            "arm_thumb": ("4120", "r0", 0x41),
            "arm64":     ("200880d2", "x0", 0x41),
            "mips":      ("24020041", "v0", 0x41),
            "mips_le":   ("41000224", "v0", 0x41),
            "riscv64":   ("13051004", "a0", 0x41),
            "riscv32":   ("13051004", "a0", 0x41),
            "ppc":       ("38600041", "r3", 0x41),
            "ppc64":     ("38600041", "r3", 0x41),
        }
        for arch in ARCH_MAP:
            eng = IcicleEngine(arch=arch)
            self.assertEqual(eng.arch, arch)
            self.assertTrue(len(eng.registers_read_all()) > 0, f"{arch} has no registers")
            if arch in snippets:
                hx, reg, want = snippets[arch]
                code = bytes.fromhex(hx)
                eng.memory_write(CODE_BASE, code)
                eng.vm.pc = CODE_BASE
                eng.step(1)
                self.assertEqual(eng.register_read(reg), want,
                                 f"{arch}: {reg}=0x{eng.register_read(reg):x}")
            eng.close()

    def test_arch_map_has_common_regs(self):
        for arch in ARCH_MAP:
            self.assertIn(arch, COMMON_REGS, f"No COMMON_REGS for {arch}")

    # -- Extended binding coverage --

    def test_capabilities(self):
        eng = IcicleEngine(arch="x86_64")
        caps = eng.CAPABILITIES
        for c in ("memory_management", "breakpoints", "register_introspection"):
            self.assertIn(c, caps)
        eng.close()

    def test_memory_unmap(self):
        eng = IcicleEngine(arch="x86_64")
        eng.memory_map(0xA000000, 0x1000, perms=7)
        eng.memory_write(0xA000000, b"\x41")
        eng.memory_unmap(0xA000000, 0x1000)
        with self.assertRaises(RuntimeError):
            eng.memory_read(0xA000000, 1)
        eng.close()

    def test_memory_protect(self):
        # mem_protect governs guest execution; a guest write to a read-only page
        # raises a write violation. (Host memory_write bypasses perms by design.)
        eng = IcicleEngine(arch="x86_64")
        eng.memory_protect(CODE_BASE, 0x1000, 5)  # r-x
        # mov [rax], al  with rax -> the protected page => write violation
        eng.register_write("rax", CODE_BASE)
        eng.memory_write(CODE_BASE + 0x200, b"\x88\x00")  # mov [rax], al (host write ok)
        result = eng.start(CODE_BASE + 0x200, CODE_BASE + 0x202)
        self.assertEqual(result["status"], "error", result)
        eng.close()

    def test_list_registers(self):
        eng = IcicleEngine(arch="x86_64")
        regs = eng.list_registers()
        self.assertGreater(len(regs), 100)
        self.assertIn("RAX", regs)
        self.assertEqual(regs["RAX"]["size"], 8)
        self.assertIn("offset", regs["RAX"])
        eng.close()

    def test_breakpoint_halt_and_resume(self):
        eng = IcicleEngine(arch="x86_64")
        # nop;nop;nop;nop;nop;hlt
        eng.memory_write(CODE_BASE, b"\x90\x90\x90\x90\x90\xf4")
        eng.breakpoint_add(CODE_BASE + 3)
        r1 = eng.start(CODE_BASE)  # free run -> should stop at the breakpoint
        self.assertEqual(r1["status"], "breakpoint", r1)
        self.assertEqual(eng.register_read("rip"), CODE_BASE + 3)
        # Resume from the breakpoint; remove it so we run to the end.
        eng.breakpoint_remove(CODE_BASE + 3)
        r2 = eng.start(CODE_BASE + 3, CODE_BASE + 5)
        self.assertEqual(r2["status"], "ok", r2)
        eng.close()

    def test_breakpoint_with_tracing(self):
        eng = IcicleEngine(arch="x86_64")
        eng.enable_tracing()
        eng.memory_write(CODE_BASE, b"\x90\x90\x90\x90")
        eng.breakpoint_add(CODE_BASE + 2)
        r = eng.start(CODE_BASE, CODE_BASE + 4)
        self.assertEqual(r["status"], "breakpoint", r)
        self.assertEqual(eng.register_read("rip"), CODE_BASE + 2)
        eng.close()

    def test_free_run_to_halt(self):
        eng = IcicleEngine(arch="x86_64")
        eng.memory_write(CODE_BASE, b"\xff\xc0\xff\xc0\xf4")  # inc eax; inc eax; hlt
        r = eng.start(CODE_BASE)  # no end -> free run
        self.assertIn(r["status"], ("ok", "timeout", "error"))
        self.assertEqual(eng.register_read("eax"), 2)
        eng.close()

    def test_constructor_options(self):
        # jit=True is accepted; mem_capacity knob applies.
        eng = IcicleEngine(arch="x86_64", jit=True, mem_capacity=60000)
        self.assertEqual(eng.vm_options["jit"], True)
        eng.memory_write(CODE_BASE, b"\x48\xc7\xc0\x41\x00\x00\x00\x90")
        eng.start(CODE_BASE, CODE_BASE + 8)
        self.assertEqual(eng.register_read("rax"), 0x41)
        eng.close()


@unittest.skipUnless(HAS_ICICLE and "reverse_execution" in EXT_CAPS,
                     "extended Icicle binding (icicle_ext/) not installed")
class TestIcicleReverseExecution(unittest.TestCase):
    """Features that require the extended binding; skipped on the stock wheel."""

    def _engine(self):
        eng = IcicleEngine(arch="x86_64")
        # mov rax,0x41 ; mov rbx,0x42 ; nop ; nop
        eng.memory_write(CODE_BASE, bytes.fromhex("48c7c041000000" "48c7c342000000" "9090"))
        return eng

    def test_step_back(self):
        eng = self._engine()
        eng.start(CODE_BASE, CODE_BASE + 16)
        self.assertEqual(eng.register_read("rax"), 0x41)
        self.assertEqual(eng.register_read("rbx"), 0x42)
        r = eng.step_back(2)
        self.assertEqual(r["icount"], 2)
        eng.close()

    def test_goto_icount(self):
        eng = self._engine()
        eng.start(CODE_BASE, CODE_BASE + 16)
        r = eng.goto_icount(1)
        self.assertEqual(r["icount"], 1)
        # Only the first instruction (mov rax) has executed.
        self.assertEqual(eng.register_read("rax"), 0x41)
        self.assertEqual(eng.register_read("rbx"), 0)
        eng.close()

    def test_native_snapshot_roundtrip(self):
        eng = self._engine()
        eng.start(CODE_BASE, CODE_BASE + 16)
        snap = eng.snapshot_save("post")
        self.assertIn("native", eng.snapshots[snap]._data)
        eng.register_write("rax", 0x9999)
        eng.snapshot_restore(snap)
        self.assertEqual(eng.register_read("rax"), 0x41)
        eng.close()


@unittest.skipUnless(HAS_ICICLE and "disassembly" in EXT_CAPS,
                     "extended Icicle binding (icicle_ext/) not installed")
class TestIcicleDisassembly(unittest.TestCase):
    def test_disassemble(self):
        eng = IcicleEngine(arch="x86_64")
        eng.memory_write(CODE_BASE, bytes.fromhex("48c7c041000000" "48c7c342000000" "90"))
        insns = eng.disassemble(CODE_BASE, 3)
        self.assertEqual(len(insns), 3)
        self.assertIn("mov", insns[0]["instruction"].lower())
        self.assertIn("nop", insns[2]["instruction"].lower())
        eng.close()

    def test_callstack_available(self):
        eng = IcicleEngine(arch="x86_64")
        self.assertIsInstance(eng.get_callstack(), list)
        eng.close()


@unittest.skipUnless(HAS_ICICLE and "coverage" in EXT_CAPS,
                     "extended Icicle binding (icicle_ext/) not installed")
class TestIcicleCoverage(unittest.TestCase):
    def test_block_coverage(self):
        eng = IcicleEngine(arch="x86_64")
        # mov eax,1 ; test eax,eax ; jz +1 ; nop ; nop  -> two basic blocks
        eng.memory_write(CODE_BASE, bytes.fromhex("b801000000" "85c0" "7401" "90" "90"))
        eng.enable_coverage()
        eng.start(CODE_BASE, CODE_BASE + 11)
        blocks = eng.get_coverage()
        self.assertGreaterEqual(len(blocks), 2, blocks)
        self.assertIn(CODE_BASE, blocks)
        eng.clear_coverage()
        self.assertEqual(eng.get_coverage(), [])
        eng.close()

    def test_coverage_capability(self):
        eng = IcicleEngine(arch="x86_64")
        self.assertIn("coverage", eng.CAPABILITIES)
        eng.close()


@unittest.skipUnless(HAS_ICICLE and "callback_hooks" in EXT_CAPS,
                     "extended Icicle binding (icicle_ext/) not installed")
class TestIcicleCallbackHooks(unittest.TestCase):
    def test_block_callback(self):
        eng = IcicleEngine(arch="x86_64")
        hits = []
        eng.add_callback_hook(lambda a: hits.append(a))  # every basic block
        eng.memory_write(CODE_BASE, bytes.fromhex("b801000000" "85c0" "7401" "90" "90"))
        eng.start(CODE_BASE, CODE_BASE + 11)
        self.assertIn(CODE_BASE, hits)
        self.assertGreaterEqual(len(hits), 2, hits)
        eng.close()

    def test_address_callback(self):
        eng = IcicleEngine(arch="x86_64")
        hits = []
        eng.add_callback_hook(lambda a: hits.append(a), address=CODE_BASE + 5)
        eng.memory_write(CODE_BASE, bytes.fromhex("90" * 10))
        eng.start(CODE_BASE, CODE_BASE + 10)
        self.assertEqual(hits, [CODE_BASE + 5])
        eng.close()


@unittest.skipUnless(HAS_ICICLE and "memory_hooks" in EXT_CAPS,
                     "extended Icicle binding (icicle_ext/) not installed")
class TestIcicleMemoryHooks(unittest.TestCase):
    # mov [HEAP_BASE], eax ; mov ebx, [HEAP_BASE]  (disp32 = 0x08000000)
    _CODE = bytes.fromhex("89042500000008" "8b1c2500000008")

    def test_write_and_read_hooks_fire(self):
        eng = IcicleEngine(arch="x86_64")
        writes, reads = [], []
        wid = eng.add_mem_hook(lambda a, d: writes.append((a, bytes(d))),
                               kind="write", start=HEAP_BASE, end=HEAP_BASE + 0xfff)
        rid = eng.add_mem_hook(lambda a, s: reads.append((a, s)),
                               kind="read", start=HEAP_BASE, end=HEAP_BASE + 0xfff)
        self.assertNotEqual(wid, rid)
        eng.memory_write(CODE_BASE, self._CODE)
        eng.register_write("rip", CODE_BASE)
        eng.register_write("rax", 0xdeadbeef)
        for _ in range(2):
            eng.step(1)
        self.assertEqual(writes, [(HEAP_BASE, b"\xef\xbe\xad\xde")])
        self.assertEqual(reads, [(HEAP_BASE, 4)])
        self.assertEqual(eng.register_read("rbx"), 0xdeadbeef)
        eng.close()

    def test_hook_remove_stops_callbacks(self):
        eng = IcicleEngine(arch="x86_64")
        writes = []
        wid = eng.add_mem_hook(lambda a, d: writes.append(a),
                               kind="write", start=HEAP_BASE, end=HEAP_BASE + 0xfff)
        self.assertEqual(len(eng.list_hooks()), 1)
        self.assertTrue(eng.hook_remove(wid))
        self.assertEqual(eng.list_hooks(), [])
        eng.memory_write(CODE_BASE, self._CODE)
        eng.register_write("rip", CODE_BASE)
        eng.register_write("rax", 1)
        eng.step(1)
        self.assertEqual(writes, [])  # hook removed before the write executed
        eng.close()

    def test_out_of_range_write_not_hooked(self):
        eng = IcicleEngine(arch="x86_64")
        writes = []
        # Watch a window that the store (to HEAP_BASE) falls outside of.
        eng.add_mem_hook(lambda a, d: writes.append(a),
                         kind="write", start=HEAP_BASE + 0x800, end=HEAP_BASE + 0xfff)
        eng.memory_write(CODE_BASE, self._CODE)
        eng.register_write("rip", CODE_BASE)
        eng.register_write("rax", 1)
        eng.step(1)
        self.assertEqual(writes, [])
        eng.close()

    def test_bad_kind_rejected(self):
        eng = IcicleEngine(arch="x86_64")
        with self.assertRaises(ValueError):
            eng.add_mem_hook(lambda a, d: None, kind="exec")
        eng.close()

    def test_memory_hooks_capability(self):
        eng = IcicleEngine(arch="x86_64")
        self.assertIn("memory_hooks", eng.CAPABILITIES)
        eng.close()


@unittest.skipUnless(HAS_ICICLE and "pcode_il" in EXT_CAPS,
                     "extended Icicle binding (icicle_ext/) not installed")
class TestIciclePcode(unittest.TestCase):
    def test_pcode_lift(self):
        eng = IcicleEngine(arch="x86_64")
        # mov eax, 1 ; add eax, 2
        eng.memory_write(CODE_BASE, bytes.fromhex("b801000000" "83c002"))
        text = eng.get_pcode(CODE_BASE)
        # The IL carries the disassembly plus the micro-ops it expands to.
        self.assertIn("MOV", text.upper())
        self.assertIn("RAX", text)      # the p-code writes the full 64-bit reg
        self.assertIn("ADD", text.upper())
        eng.close()

    def test_pcode_capability(self):
        eng = IcicleEngine(arch="x86_64")
        self.assertIn("pcode_il", eng.CAPABILITIES)
        eng.close()


@unittest.skipUnless(HAS_ICICLE and "mmio" in EXT_CAPS,
                     "extended Icicle binding (icicle_ext/) not installed")
class TestIcicleMmio(unittest.TestCase):
    # disp32 with the high bit clear (0x40000000) so x86-64 does not
    # sign-extend the displacement.
    MMIO = 0x40000000

    def test_mmio_read_and_write_serviced(self):
        eng = IcicleEngine(arch="x86_64")
        writes = []
        eng.map_mmio(self.MMIO, 0x1000,
                     read_cb=lambda a, s: 0x11223344,
                     write_cb=lambda a, d: writes.append((a, bytes(d))))
        # mov eax, [MMIO] ; mov [MMIO+4], eax
        eng.memory_write(CODE_BASE, bytes.fromhex("8b042500000040" "89042504000040"))
        eng.register_write("rip", CODE_BASE)
        eng.step(1)
        self.assertEqual(eng.register_read("rax"), 0x11223344)   # read serviced
        eng.step(1)
        self.assertEqual(writes, [(self.MMIO + 4, b"\x44\x33\x22\x11")])  # write serviced (LE)
        eng.close()

    def test_mmio_default_read_zero(self):
        eng = IcicleEngine(arch="x86_64")
        eng.map_mmio(self.MMIO, 0x1000)  # no callbacks
        eng.register_write("rax", 0xdead)
        eng.memory_write(CODE_BASE, bytes.fromhex("8b042500000040"))  # mov eax,[MMIO]
        eng.register_write("rip", CODE_BASE)
        eng.step(1)
        self.assertEqual(eng.register_read("rax"), 0)  # unbacked read -> zero
        eng.close()

    def test_mmio_capability(self):
        eng = IcicleEngine(arch="x86_64")
        self.assertIn("mmio", eng.CAPABILITIES)
        eng.close()


@unittest.skipUnless(HAS_ICICLE and "wide_registers" in EXT_CAPS,
                     "extended Icicle binding (icicle_ext/) not installed")
class TestIcicleWideRegisters(unittest.TestCase):
    def test_xmm_roundtrip(self):
        eng = IcicleEngine(arch="x86_64")
        eng.register_write_bytes("xmm0", bytes(range(16)))
        self.assertEqual(eng.register_read_bytes("xmm0"), bytes(range(16)))
        eng.close()


@unittest.skipUnless(HAS_ICICLE and "gdb" in EXT_CAPS,
                     "extended Icicle binding (icicle_ext/) not installed")
class TestIcicleGdb(unittest.TestCase):
    def test_gdb_serve_times_out_without_client(self):
        eng = IcicleEngine(arch="x86_64")
        with self.assertRaises(Exception):
            # No client connects -> bounded wait then raises.
            eng.gdb_serve("127.0.0.1:54399", timeout_secs=1)
        eng.close()


@unittest.skipUnless(HAS_ICICLE and HAS_LINUX_BINDING,
                     "extended Icicle binding with Linux support not installed")
class TestIcicleLinux(unittest.TestCase):
    """Full Linux userspace emulation: load a static ELF and run it."""

    @classmethod
    def setUpClass(cls):
        import shutil, subprocess, tempfile, os as _os
        cls._bin = None
        if shutil.which("gcc") is None:
            return
        cls._tmp = tempfile.mkdtemp()
        src = _os.path.join(cls._tmp, "t.c")
        out = _os.path.join(cls._tmp, "t")
        with open(src, "w") as f:
            f.write('int main(){return 7;}\n')
        try:
            subprocess.run(["gcc", "-static", "-O2", "-o", out, src],
                           check=True, capture_output=True, timeout=60)
            cls._bin = out
        except Exception:
            cls._bin = None

    def test_load_and_run(self):
        if not self._bin:
            self.skipTest("could not compile a static test binary (gcc unavailable)")
        eng = IcicleEngine(arch="x86_64", os="linux", binary_path=self._bin)
        self.assertEqual(eng.ostype, "linux")
        self.assertIn("os_emulation", eng.CAPABILITIES)
        entry = eng.vm.pc
        self.assertNotEqual(entry, 0)
        result = eng.start(0, 0, timeout_ms=20000)  # free run to exit
        self.assertIn(result["status"], ("ok", "timeout"))
        self.assertGreater(result["instructions_executed"], 100)
        eng.close()

    def test_mem_map_ranges_cover_loaded_image(self):
        if not self._bin:
            self.skipTest("could not compile a static test binary (gcc unavailable)")
        eng = IcicleEngine(arch="x86_64", os="linux", binary_path=self._bin)
        # The MMU enumeration should expose the loader's mappings (many more
        # than a shellcode session's three), enabling background GDB on Linux.
        ranges = eng.vm.mem_map_ranges()
        self.assertGreater(len(ranges), 10, len(ranges))
        self.assertGreater(sum(s for _, s in ranges), 0)
        eng.close()


if __name__ == "__main__":
    if not HAS_ICICLE:
        print("icicle not installed; skipping Icicle engine tests")
        sys.exit(0)
    unittest.main(verbosity=2)
