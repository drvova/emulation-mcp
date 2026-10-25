"""Emulation engine registry.

Engines are imported lazily so optional backends (qiling, icicle, angr) only
need to be installed when a session actually uses them.
"""

from dataclasses import dataclass
from importlib import import_module
from importlib.util import find_spec
from typing import Any

from .base import BaseEngine, CAPABILITY_DESCRIPTIONS


@dataclass(frozen=True)
class EngineSpec:
    """Static description of an engine backend."""
    name: str
    module: str          # module inside the engines package
    class_name: str
    dependency: str      # top-level import name of the backing framework
    pip_package: str
    description: str


ENGINE_SPECS: dict[str, EngineSpec] = {
    "unicorn": EngineSpec(
        "unicorn", "unicorn_engine", "UnicornEngine", "unicorn", "unicorn",
        "Fast QEMU-based CPU emulator for shellcode and code snippets. No OS, no syscalls.",
    ),
    "qiling": EngineSpec(
        "qiling", "qiling_engine", "QilingEngine", "qiling", "qiling",
        "Full binary emulation with OS support (Linux/Windows/...). Needs a rootfs for shared libs.",
    ),
    "icicle": EngineSpec(
        "icicle", "icicle_engine", "IcicleEngine", "icicle", "icicle-emu",
        "CPU emulator built on Ghidra SLEIGH semantics. Adds RISC-V and PowerPC; "
        "an independent implementation for cross-checking Unicorn results. With the "
        "extended binding (icicle_ext/) it also gains reverse execution, native "
        "snapshots, SLEIGH disassembly, call stacks and Linux userspace emulation.",
    ),
    "angr": EngineSpec(
        "angr", "angr_engine", "AngrEngine", "angr", "angr",
        "Symbolic execution: make registers/memory symbolic, explore paths to a target "
        "address, and solve for the inputs that reach it.",
    ),
    "sogen": EngineSpec(
        "sogen", "sogen_engine", "SogenEngine", "sogen", "sogen",
        "High-performance Windows and Linux user-mode emulator. Loads real PE/ELF "
        "binaries and the genuine system libraries (ntdll/kernel32 on Windows), with a "
        "selectable CPU backend (Unicorn or Icicle). Needs a prepared emulation root "
        "for Windows (system DLLs + registry); Linux can run against the host '/'.",
    ),
}

ENGINE_NAMES: tuple[str, ...] = tuple(ENGINE_SPECS)


def is_installed(name: str) -> bool:
    """True if the framework backing engine `name` can be imported."""
    spec = ENGINE_SPECS.get(name)
    return spec is not None and find_spec(spec.dependency) is not None


def get_engine_class(name: str) -> type[BaseEngine]:
    """Import and return the engine class for `name`.

    Raises ValueError for unknown engines and RuntimeError when the backing
    framework is not installed.
    """
    spec = ENGINE_SPECS.get(name)
    if spec is None:
        raise ValueError(f"Unknown engine '{name}'. Available: {', '.join(ENGINE_NAMES)}")
    if find_spec(spec.dependency) is None:
        raise RuntimeError(
            f"Engine '{name}' requires the '{spec.pip_package}' package. "
            f"Install it with: pip install {spec.pip_package}"
        )
    module = import_module(f".{spec.module}", __name__)
    return getattr(module, spec.class_name)


def engines_with_capability(capability: str) -> list[str]:
    """Names of installed engines that advertise `capability`."""
    return [
        info["name"] for info in describe_engines()
        if info["installed"] and capability in info["capabilities"]
    ]


def describe_engines() -> list[dict[str, Any]]:
    """Describe every known engine: install status, capabilities and architectures."""
    result = []
    for name, spec in ENGINE_SPECS.items():
        info: dict[str, Any] = {
            "name": name,
            "description": spec.description,
            "pip_package": spec.pip_package,
            "installed": False,
            "capabilities": [],
            "architectures": [],
        }
        try:
            cls = get_engine_class(name)
        except Exception as e:
            info["error"] = str(e)
        else:
            info["installed"] = True
            info["capabilities"] = sorted(cls.CAPABILITIES)
            info["architectures"] = list(getattr(cls, "SUPPORTED_ARCHS", ()))
        result.append(info)
    return result


def __getattr__(attr: str) -> Any:
    # Keep `from engines import UnicornEngine` working without eager imports.
    for spec in ENGINE_SPECS.values():
        if spec.class_name == attr:
            return get_engine_class(spec.name)
    raise AttributeError(f"module {__name__!r} has no attribute {attr!r}")


__all__ = [
    "BaseEngine", "CAPABILITY_DESCRIPTIONS", "ENGINE_NAMES", "ENGINE_SPECS", "EngineSpec",
    "describe_engines", "engines_with_capability", "get_engine_class", "is_installed",
]
