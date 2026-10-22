"""Engine-agnostic coverage-guided fuzzing loop.

Builds on primitives every engine already exposes — snapshot/restore, a run with
a bounded budget, and a coverage signal — so it works without any engine-specific
fuzzing framework:

* Coverage signal: Icicle's native block coverage when available
  ('coverage' capability), otherwise the instruction trace (unique PCs) as a
  fallback for engines that can trace.
* State reset: a baseline snapshot restored before every run.
* Input injection: the fuzzed bytes are written to a chosen memory address
  before each run (map it first, or use a mapped region).

The loop keeps inputs that reach new coverage (a simple corpus), applies havoc
mutations, and records inputs that make a run fault.
"""

from __future__ import annotations

import random
import time
from typing import Any, Callable

# Run statuses that indicate a fault worth reporting (not a clean stop/timeout).
_CRASH_STATUSES = {"error", "self_modifying_code"}
# Statuses that are a normal, non-crash end to a run.
_OK_STATUSES = {"ok", "stopped", "breakpoint", "timeout", "halt",
                "found", "no_active_states", "state_explosion"}


def _coverage_signal(engine) -> tuple[str, Callable[[], set], Callable[[], None]]:
    """Return (mode, read_coverage, clear_coverage) for the best signal available."""
    if engine.has_capability("coverage"):
        engine.enable_coverage()
        return "blocks", (lambda: set(engine.get_coverage())), engine.clear_coverage
    if engine.has_capability("instruction_trace"):
        engine.enable_tracing()

        def read() -> set:
            out = set()
            for t in engine.get_trace(limit=1_000_000):
                if t.get("type") == "instruction":
                    try:
                        out.add(int(t["address"], 16))
                    except (ValueError, KeyError):
                        pass
            return out

        return "trace", read, engine.clear_trace
    raise RuntimeError(
        f"The '{engine.engine_type}' engine provides no coverage signal "
        f"(needs 'coverage' or 'instruction_trace')."
    )


# --- Mutators (classic havoc) ---

def _mutate(data: bytes, rng: random.Random, max_size: int) -> bytes:
    b = bytearray(data) if data else bytearray(1)
    n_ops = rng.randint(1, 5)
    for _ in range(n_ops):
        if not b:
            b.append(rng.randint(0, 255))
            continue
        op = rng.randint(0, 5)
        i = rng.randrange(len(b))
        if op == 0:                              # bit flip
            b[i] ^= 1 << rng.randint(0, 7)
        elif op == 1:                            # random byte
            b[i] = rng.randint(0, 255)
        elif op == 2:                            # small arithmetic
            b[i] = (b[i] + rng.randint(-16, 16)) & 0xFF
        elif op == 3:                            # interesting value
            b[i] = rng.choice((0x00, 0x01, 0x7F, 0x80, 0xFF, 0x41))
        elif op == 4 and len(b) < max_size:      # grow (duplicate a byte)
            b.insert(i, b[i])
        elif op == 5 and len(b) > 1:             # shrink
            del b[i]
    return bytes(b[:max_size])


def _splice(a: bytes, b: bytes, rng: random.Random, max_size: int) -> bytes:
    if not a or not b:
        return a or b
    cut_a = rng.randrange(len(a))
    cut_b = rng.randrange(len(b))
    return (a[:cut_a] + b[cut_b:])[:max_size]


def run_fuzz(
    engine,
    input_addr: int,
    input_size: int,
    run_begin: int,
    run_end: int = 0,
    seeds: list[bytes] | None = None,
    iterations: int = 1000,
    timeout_ms: int = 1000,
    wall_clock_s: float = 30.0,
    max_input: int | None = None,
    seed: int | None = None,
    max_crashes: int = 25,
) -> dict[str, Any]:
    """Run a coverage-guided fuzzing loop against `engine`.

    input_addr/input_size: where (and how big) the fuzzed input is written. The
      region must be mapped. The input is written before each run.
    run_begin/run_end: execution range for each run (run_end=0 => free run).
    seeds: initial corpus (bytes); defaults to a single zero-filled input.
    iterations / wall_clock_s: stop after this many runs or this much time.
    """
    rng = random.Random(seed)
    max_input = max_input or input_size
    mode, read_cov, clear_cov = _coverage_signal(engine)

    # Baseline captures the caller's setup (registers, mapped memory). Each run
    # is restored to it so inputs don't interfere with each other.
    baseline = engine.snapshot_save("fuzz-baseline")

    corpus: list[bytes] = [s for s in (seeds or []) if s] or [bytes(input_size)]
    total_cov: set = set()
    crashes: list[dict[str, Any]] = []
    crash_keys: set = set()
    executions = 0
    new_cov_hits = 0

    start = time.time()
    for _ in range(max(iterations, 1)):
        if time.time() - start > wall_clock_s:
            break
        base = rng.choice(corpus)
        if len(corpus) > 1 and rng.random() < 0.3:
            data = _splice(base, rng.choice(corpus), rng, max_input)
        else:
            data = _mutate(base, rng, max_input)

        engine.snapshot_restore(baseline)
        clear_cov()
        payload = data[:input_size].ljust(input_size, b"\x00")
        try:
            engine.memory_write(input_addr, payload)
        except Exception as e:
            return {"error": f"Could not write input at 0x{input_addr:x}: {e}. "
                             f"Map the region first."}
        try:
            result = engine.start(run_begin, run_end, timeout_ms=timeout_ms)
        except Exception as e:
            result = {"status": "error", "error": f"{type(e).__name__}: {e}"}
        executions += 1

        cov = read_cov()
        new = cov - total_cov
        if new:
            total_cov |= new
            corpus.append(data)
            new_cov_hits += 1

        status = str(result.get("status", "")).lower()
        if status in _CRASH_STATUSES or (status not in _OK_STATUSES and status):
            key = (status, str(result.get("error", ""))[:80])
            if key not in crash_keys and len(crashes) < max_crashes:
                crash_keys.add(key)
                crashes.append({
                    "input": data.hex(),
                    "status": status,
                    "error": result.get("error", ""),
                    "pc": result.get("pc", ""),
                })

    engine.snapshot_restore(baseline)
    return {
        "mode": mode,
        "executions": executions,
        "elapsed_s": round(time.time() - start, 2),
        "corpus_size": len(corpus),
        "coverage": len(total_cov),
        "new_coverage_inputs": new_cov_hits,
        "crashes": crashes,
        "unique_crashes": len(crashes),
    }
