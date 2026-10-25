#!/usr/bin/env bash
#
# Install the Sogen Python binding for the emulation-mcp `sogen` engine.
#
# Sogen (https://github.com/momo5502/sogen) is a Windows & Linux user-mode
# emulator with an official `sogen` PyPI package.  Prebuilt wheels are published
# for CPython 3.9 and 3.10 only -- on those interpreters `pip install sogen`
# just works.  On any other Python version it has to be built from source
# (CMake + a C++/Rust toolchain).  The Python binding does not need Sogen's
# SDL3 GUI/audio backends or its standalone tools, so this script turns them off
# -- that both speeds up the build and avoids SDL3's X11/audio dev-package
# requirements.
#
# Usage:
#   ./scripts/build-sogen.sh [/path/to/python]
#
#   # into a specific venv, pinned to a particular build:
#   SOGEN_VERSION=0.0.1.dev5822 ./scripts/build-sogen.sh /path/to/venv/bin/python
#
#   # install the newest published version instead of the pinned default:
#   SOGEN_VERSION=latest ./scripts/build-sogen.sh
#
# With no argument it uses the python on PATH.  Install it into the interpreter
# that runs the MCP server; the SogenEngine wrapper feature-detects whatever the
# resulting build exposes.  Sogen is GPL-2.0-only.
#
# Source builds need: cmake, a C++ compiler (g++ or clang++), and a Rust
# toolchain (cargo, https://rustup.rs); ninja is used if present.

set -euo pipefail

# Default to a pinned, verified build for reproducibility; SOGEN_VERSION=latest
# installs the newest published version (there is no stable/tagged release yet).
SOGEN_VERSION="${SOGEN_VERSION:-0.0.1.dev5822}"
PYTHON="${1:-$(command -v python3 || command -v python || true)}"

if [ -z "$PYTHON" ] || ! "$PYTHON" -c 'import sys' >/dev/null 2>&1; then
    echo "error: no usable python interpreter (pass one as the first argument)" >&2
    exit 1
fi

echo ">> Using python: $PYTHON ($("$PYTHON" --version 2>&1))"

spec="sogen"
if [ "$SOGEN_VERSION" != "latest" ]; then
    spec="sogen==$SOGEN_VERSION"
fi

# Sogen publishes wheels only for cp39/cp310; use one directly when available.
PYTAG="$("$PYTHON" -c 'import sys;print("cp%d%d"%sys.version_info[:2])')"
if [ "$PYTAG" = "cp39" ] || [ "$PYTAG" = "cp310" ]; then
    echo ">> $PYTAG has a prebuilt wheel; installing it directly."
    "$PYTHON" -m pip install "$spec"
    "$PYTHON" -c 'import sogen; print(">> sogen import OK")'
    exit 0
fi

echo ">> No prebuilt wheel for $PYTAG; building from source."

missing=()
command -v cmake >/dev/null 2>&1 || missing+=("cmake")
{ command -v g++ >/dev/null 2>&1 || command -v clang++ >/dev/null 2>&1; } \
    || missing+=("a C++ compiler (g++ or clang++)")
command -v cargo >/dev/null 2>&1 || missing+=("cargo (Rust toolchain; https://rustup.rs)")
if [ "${#missing[@]}" -ne 0 ]; then
    echo "error: missing build prerequisites: ${missing[*]}" >&2
    exit 1
fi
command -v ninja >/dev/null 2>&1 \
    || echo ">> note: ninja not found; CMake will fall back to its default generator (slower)."

export CMAKE_BUILD_PARALLEL_LEVEL="${CMAKE_BUILD_PARALLEL_LEVEL:-$(nproc 2>/dev/null || echo 4)}"
echo ">> Building sogen $SOGEN_VERSION from source (SDL3 + tools off); this takes several minutes..."

"$PYTHON" -m pip install "$spec" \
    --no-binary sogen \
    --config-settings=cmake.define.SOGEN_ENABLE_SDL3=OFF \
    --config-settings=cmake.define.SOGEN_BUILD_TOOLS=OFF

"$PYTHON" -c 'import sogen; print(">> sogen import OK")'
echo ">> Done. Installed sogen into: $PYTHON"
