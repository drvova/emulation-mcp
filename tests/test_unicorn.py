"""Tests for UnicornEngine wrapper."""

import sys
import os

# Allow running as standalone script. The engines package imports backends
# lazily, so importing the Unicorn engine alone does not require qiling/icicle/angr.
_project_root = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, _project_root)

from engines.unicorn_engine import UnicornEngine, CODE_BASE


def test_create_engine():
    """Test creating a UnicornEngine with x86_64 architecture."""
    eng = UnicornEngine(arch="x86_64")
    assert eng.arch == "x86_64"
    assert eng.engine_type == "unicorn"
    info = eng.get_info()
    assert info["engine_type"] == "unicorn"
    assert info["arch"] == "x86_64"
    eng.close()
    print("  PASS: test_create_engine")


def test_memory_read_write():
    """Test memory read and write operations."""
    eng = UnicornEngine(arch="x86_64")

    # Write and read back
    data = b"\x41\x42\x43\x44"
    eng.memory_write(CODE_BASE, data)
    result = eng.memory_read(CODE_BASE, len(data))
    assert result == data, f"Expected {data!r}, got {result!r}"

    # Write at a different offset
    eng.memory_write(CODE_BASE + 0x100, b"\xDE\xAD\xBE\xEF")
    result = eng.memory_read(CODE_BASE + 0x100, 4)
    assert result == b"\xDE\xAD\xBE\xEF"

    eng.close()
    print("  PASS: test_memory_read_write")


def test_register_read_write():
    """Test register read and write operations."""
    eng = UnicornEngine(arch="x86_64")

    eng.register_write("rax", 0x1234)
    val = eng.register_read("rax")
    assert val == 0x1234, f"Expected 0x1234, got 0x{val:x}"

    eng.register_write("rbx", 0xDEADBEEF)
    val = eng.register_read("rbx")
    assert val == 0xDEADBEEF, f"Expected 0xDEADBEEF, got 0x{val:x}"

    eng.close()
    print("  PASS: test_register_read_write")


def test_registers_read_all():
    """Test reading all registers at once."""
    eng = UnicornEngine(arch="x86_64")
    eng.register_write("rax", 0xAAAA)
    eng.register_write("rbx", 0xBBBB)

    regs = eng.registers_read_all()
    assert "rax" in regs
    assert "rbx" in regs
    assert "rsp" in regs
    assert "rip" in regs
    assert regs["rax"] == 0xAAAA
    assert regs["rbx"] == 0xBBBB

    eng.close()
    print("  PASS: test_registers_read_all")


def test_execute_shellcode():
    """Test executing simple x86_64 shellcode with tracing."""
    eng = UnicornEngine(arch="x86_64")
    eng.enable_tracing()

    # mov rax, 0x41; mov rbx, 0x42; nop; nop
    code = (
        b"\x48\xc7\xc0\x41\x00\x00\x00"  # mov rax, 0x41
        b"\x48\xc7\xc3\x42\x00\x00\x00"  # mov rbx, 0x42
        b"\x90"                            # nop
        b"\x90"                            # nop
    )
    eng.memory_write(CODE_BASE, code)

    result = eng.start(CODE_BASE, CODE_BASE + len(code), timeout_ms=5000)
    assert result["status"] == "ok", f"Execution failed: {result}"

    # Verify register values
    rax = eng.register_read("rax")
    rbx = eng.register_read("rbx")
    assert rax == 0x41, f"Expected rax=0x41, got 0x{rax:x}"
    assert rbx == 0x42, f"Expected rbx=0x42, got 0x{rbx:x}"

    # Check that trace was recorded
    trace = eng.get_trace()
    assert len(trace) == 4, f"Expected 4 trace entries, got {len(trace)}"
    assert "mov" in trace[0]["instruction"].lower()
    assert "nop" in trace[2]["instruction"].lower()

    eng.close()
    print("  PASS: test_execute_shellcode")


def test_step():
    """Test single-stepping through instructions."""
    eng = UnicornEngine(arch="x86_64")

    # mov rax, 1; mov rbx, 2; mov rcx, 3; nop
    code = (
        b"\x48\xc7\xc0\x01\x00\x00\x00"  # mov rax, 1
        b"\x48\xc7\xc3\x02\x00\x00\x00"  # mov rbx, 2
        b"\x48\xc7\xc1\x03\x00\x00\x00"  # mov rcx, 3
        b"\x90"                            # nop
    )
    eng.memory_write(CODE_BASE, code)
    eng.register_write("rip", CODE_BASE)

    # Step one instruction
    stepped = eng.step(1)
    assert len(stepped) == 1, f"Expected 1 stepped entry, got {len(stepped)}"
    assert eng.register_read("rax") == 1

    # Step another
    stepped = eng.step(1)
    assert len(stepped) == 1
    assert eng.register_read("rbx") == 2

    eng.close()
    print("  PASS: test_step")


def test_snapshot_save_restore():
    """Test saving and restoring snapshots."""
    eng = UnicornEngine(arch="x86_64")

    # Set initial state
    eng.register_write("rax", 0x1111)
    eng.register_write("rbx", 0x2222)

    # Save snapshot
    snap_id = eng.snapshot_save("before_change")

    # Modify state
    eng.register_write("rax", 0x9999)
    eng.register_write("rbx", 0x8888)
    assert eng.register_read("rax") == 0x9999
    assert eng.register_read("rbx") == 0x8888

    # Restore snapshot
    eng.snapshot_restore(snap_id)
    assert eng.register_read("rax") == 0x1111, f"Expected 0x1111, got 0x{eng.register_read('rax'):x}"
    assert eng.register_read("rbx") == 0x2222, f"Expected 0x2222, got 0x{eng.register_read('rbx'):x}"

    # Verify snapshot listing
    snaps = eng.snapshot_list()
    assert len(snaps) == 1
    assert snaps[0]["label"] == "before_change"

    eng.close()
    print("  PASS: test_snapshot_save_restore")


def test_snapshot_memory_rollback():
    """Snapshots roll back memory as well as registers."""
    eng = UnicornEngine(arch="x86_64")

    eng.memory_write(CODE_BASE, b"\xAA\xBB\xCC\xDD")
    snap_id = eng.snapshot_save("mem")

    # Mutate existing bytes and write to a region that was zero at save time.
    eng.memory_write(CODE_BASE, b"\x00\x11\x22\x33")
    eng.memory_write(CODE_BASE + 0x40, b"\xFF\xFF")
    assert eng.memory_read(CODE_BASE, 4) == b"\x00\x11\x22\x33"

    eng.snapshot_restore(snap_id)
    assert eng.memory_read(CODE_BASE, 4) == b"\xAA\xBB\xCC\xDD", "saved bytes not restored"
    assert eng.memory_read(CODE_BASE + 0x40, 2) == b"\x00\x00", "post-snapshot write not rolled back"

    eng.close()
    print("  PASS: test_snapshot_memory_rollback")


def test_memory_search():
    """Test searching for byte patterns in mapped memory."""
    eng = UnicornEngine(arch="x86_64")

    # Write a distinctive pattern
    pattern = b"\xCA\xFE\xBA\xBE"
    eng.memory_write(CODE_BASE + 0x100, pattern)
    eng.memory_write(CODE_BASE + 0x500, pattern)

    # Search for the pattern
    results = eng.memory_search(pattern)
    assert len(results) >= 2, f"Expected at least 2 results, got {len(results)}: {[hex(a) for a in results]}"
    assert (CODE_BASE + 0x100) in results
    assert (CODE_BASE + 0x500) in results

    # Search for something that doesn't exist
    results = eng.memory_search(b"\xFF\xFE\xFD\xFC\xFB\xFA")
    assert len(results) == 0

    eng.close()
    print("  PASS: test_memory_search")


def test_memory_map():
    """Test mapping additional memory regions."""
    eng = UnicornEngine(arch="x86_64")

    # Map a new region
    eng.memory_map(0xA000000, 0x1000, perms=7)
    eng.memory_write(0xA000000, b"\x41\x42\x43")
    result = eng.memory_read(0xA000000, 3)
    assert result == b"\x41\x42\x43"

    eng.close()
    print("  PASS: test_memory_map")


def test_hook_address():
    """Test installing and triggering an address hook."""
    eng = UnicornEngine(arch="x86_64")

    hook_triggered = []

    def my_hook(engine, address):
        hook_triggered.append(address)

    # nop; nop; nop; nop
    code = b"\x90\x90\x90\x90"
    eng.memory_write(CODE_BASE, code)

    # Hook the third nop
    hook_id = eng.hook_address(CODE_BASE + 2, my_hook)
    assert hook_id.startswith("hook-")

    # List hooks
    hooks = eng.list_hooks()
    assert len(hooks) == 1
    assert hooks[0]["type"] == "address"

    # Execute
    eng.start(CODE_BASE, CODE_BASE + len(code))
    assert len(hook_triggered) == 1
    assert hook_triggered[0] == CODE_BASE + 2

    # Remove hook
    assert eng.hook_remove(hook_id) is True
    assert len(eng.hooks) == 0

    eng.close()
    print("  PASS: test_hook_address")


def test_error_handling():
    """Test that errors are properly caught and translated."""
    eng = UnicornEngine(arch="x86_64")

    # Read from unmapped memory should raise
    try:
        eng.memory_read(0xFFFF0000, 4)
        assert False, "Should have raised"
    except RuntimeError as e:
        assert "unmapped" in str(e).lower() or "error" in str(e).lower()

    # Invalid register name
    try:
        eng.register_read("nonexistent_reg")
        assert False, "Should have raised"
    except ValueError as e:
        assert "unknown register" in str(e).lower()

    # Invalid architecture
    try:
        UnicornEngine(arch="pdp11")
        assert False, "Should have raised"
    except ValueError as e:
        assert "unsupported" in str(e).lower()

    eng.close()
    print("  PASS: test_error_handling")


def test_tracing_toggle():
    """Test enabling and disabling tracing."""
    eng = UnicornEngine(arch="x86_64")

    code = b"\x90\x90\x90\x90"
    eng.memory_write(CODE_BASE, code)

    # Run without tracing - should not record instructions
    eng.start(CODE_BASE, CODE_BASE + len(code))
    trace_count_off = len(eng.trace)

    # Enable tracing and run again
    eng.register_write("rip", CODE_BASE)
    eng.enable_tracing()
    eng.clear_trace()
    eng.start(CODE_BASE, CODE_BASE + len(code))
    trace_count_on = len(eng.trace)

    assert trace_count_off == 0, f"Expected 0 traces when disabled, got {trace_count_off}"
    assert trace_count_on == 4, f"Expected 4 traces when enabled, got {trace_count_on}"

    eng.close()
    print("  PASS: test_tracing_toggle")


def test_supported_architectures():
    """Test that all supported architectures can be instantiated."""
    archs = ["x86", "x86_64", "arm", "arm_thumb", "arm64", "mips", "mips_le", "mips64"]
    for arch in archs:
        eng = UnicornEngine(arch=arch)
        assert eng.arch == arch
        regs = eng.registers_read_all()
        assert len(regs) > 0, f"Arch {arch} should have registers"
        eng.close()
    print("  PASS: test_supported_architectures")


ALL_TESTS = [
    test_create_engine,
    test_memory_read_write,
    test_register_read_write,
    test_registers_read_all,
    test_execute_shellcode,
    test_step,
    test_snapshot_save_restore,
    test_snapshot_memory_rollback,
    test_memory_search,
    test_memory_map,
    test_hook_address,
    test_error_handling,
    test_tracing_toggle,
    test_supported_architectures,
]


if __name__ == "__main__":
    print("Running UnicornEngine tests...\n")
    passed = 0
    failed = 0
    errors = []

    for test_fn in ALL_TESTS:
        try:
            test_fn()
            passed += 1
        except Exception as e:
            failed += 1
            errors.append((test_fn.__name__, e))
            print(f"  FAIL: {test_fn.__name__}: {e}")

    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    if errors:
        print("\nFailed tests:")
        for name, err in errors:
            print(f"  - {name}: {err}")
        sys.exit(1)
    else:
        print("All tests passed!")
        sys.exit(0)
