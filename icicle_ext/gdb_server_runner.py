"""Standalone GDB-stub server, run as a detached subprocess.

The MCP server can't serve a GDB stub in-process without blocking (the emulated
VM is single-threaded and !Send). So `emu_gdb_serve` dumps the session's state
to a JSON file and spawns this script, which rebuilds a fresh Icicle VM from the
dump and serves the (blocking) GDB stub here — leaving the MCP session free.

Usage: python gdb_server_runner.py <dump.json> <host:port> <timeout_secs>
"""

import json
import sys


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: gdb_server_runner.py <dump.json> <host:port> <timeout_secs>",
              file=sys.stderr)
        return 2
    dump_path, addr, timeout_s = sys.argv[1], sys.argv[2], int(sys.argv[3])

    import icicle
    with open(dump_path) as f:
        d = json.load(f)

    vm = icicle.Icicle(d["arch"], jit=False)
    P = icicle.MemoryProtection
    perm_map = {
        7: P.ExecuteReadWrite, 6: P.ReadWrite, 5: P.ExecuteRead,
        4: P.ReadOnly, 1: P.ExecuteOnly, 0: P.NoAccess,
    }
    for base, size, perms, hexbytes in d["regions"]:
        try:
            vm.mem_map(base, size, perm_map.get(perms, P.ExecuteReadWrite))
        except Exception:
            pass
        if hexbytes:
            try:
                vm.mem_write(base, bytes.fromhex(hexbytes))
            except Exception:
                pass
    for name, val in d["regs"].items():
        try:
            vm.reg_write(name, val)
        except Exception:
            pass
    for attr in ("pc", "sp"):
        if attr in d:
            try:
                setattr(vm, attr, d[attr])
            except Exception:
                pass

    print(f"[gdb_server_runner] serving {addr} (arch {d['arch']}); "
          f"attach with: gdb -ex 'target remote {addr}'", flush=True)
    try:
        vm.gdb_serve(addr, timeout_s)
    except Exception as e:
        print(f"[gdb_server_runner] {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
