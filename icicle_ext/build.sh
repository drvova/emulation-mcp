#!/usr/bin/env bash
#
# Build and install the EXTENDED Icicle Python binding.
#
# The stock `icicle-emu` wheel on PyPI exposes only a thin slice of the Icicle
# framework. This script rebuilds the binding from source with an extended
# src/lib.rs (icicle_ext/lib.rs in this repo) that additionally exposes:
#
#   - native VM snapshot/restore (snapshot/restore/snapshot_count)
#   - reverse execution & time-travel (save_snapshot/step_back/goto_icount)
#   - call stack (get_callstack)
#   - SLEIGH-native disassembly and block info (get_disasm/get_block_info)
#   - Linux userspace emulation (os="linux" + linux_load: load an ELF with
#     argv/env and emulate syscalls)
#
# Requirements: a Rust toolchain (rustc/cargo), a C compiler, and maturin
# (`pip install maturin`). The build takes a couple of minutes.
#
# Usage:
#   ./icicle_ext/build.sh [/path/to/python]
#
# With no argument it uses the python on PATH. Install the resulting wheel into
# the environment that runs the MCP server; the IcicleEngine wrapper detects the
# extended methods and unlocks the extra capabilities automatically.

set -euo pipefail

# Pinned upstream commits for reproducibility.
ICICLE_PYTHON_COMMIT="ba5d00218cab007be3ace4965c6d9ea1b28128a7"

PYTHON="${1:-$(command -v python3 || command -v python)}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo ">> Using python: $PYTHON"
echo ">> Work dir: $WORK"

if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo (Rust toolchain) not found. Install from https://rustup.rs" >&2
    exit 1
fi
if ! "$PYTHON" -m maturin --version >/dev/null 2>&1 && ! command -v maturin >/dev/null 2>&1; then
    echo "error: maturin not found. Install with: $PYTHON -m pip install maturin" >&2
    exit 1
fi
MATURIN=(maturin)
command -v maturin >/dev/null 2>&1 || MATURIN=("$PYTHON" -m maturin)

echo ">> Cloning icicle-python @ $ICICLE_PYTHON_COMMIT (with submodules)"
git clone --recurse-submodules https://github.com/icicle-emu/icicle-python "$WORK/icicle-python"
git -C "$WORK/icicle-python" checkout --quiet "$ICICLE_PYTHON_COMMIT"
git -C "$WORK/icicle-python" submodule update --init --recursive --quiet

echo ">> Overlaying extended src/lib.rs and Cargo.toml"
cp "$HERE/lib.rs" "$WORK/icicle-python/src/lib.rs"
cp "$HERE/Cargo.toml" "$WORK/icicle-python/Cargo.toml"

echo ">> Building wheel"
( cd "$WORK/icicle-python" && "${MATURIN[@]}" build --release --interpreter "$PYTHON" --out dist )

WHEEL="$(ls "$WORK"/icicle-python/dist/icicle_emu-*.whl | head -n1)"
echo ">> Built: $WHEEL"
echo ">> Installing (force reinstall)"
"$PYTHON" -m pip install --force-reinstall --no-deps "$WHEEL"

echo ">> Done. Verify with:"
echo "   $PYTHON -c 'import icicle; v=icicle.Icicle(\"x86_64\"); print([m for m in (\"step_back\",\"get_callstack\",\"linux_load\") if hasattr(v,m)])'"
