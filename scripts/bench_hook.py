#!/usr/bin/env python3
"""Measure agentwitness hook latency by invoking it as a subprocess.

This is what Claude Code's hook system actually does: spawn a process,
pipe a JSON payload to its stdin, wait for exit. The measured time
covers everything the user feels — process spawn, Python startup,
module imports, keychain access, signing, and the writes to
events.jsonl / signatures.jsonl.

Defaults to a sandboxed environment (AGENTWITNESS_STATE_DIR and
AGENTWITNESS_CLAUDE_SETTINGS pointed at a tmpdir) so it does not
touch the real keychain or hook config. Pass --no-sandbox to measure
against the actual installed state.

Run:

    python scripts/bench_hook.py            # 30 iterations, sandbox
    python scripts/bench_hook.py -n 100     # 100 iterations
    python scripts/bench_hook.py --no-sandbox -n 50

Reports min, median, mean, p95, and max in milliseconds.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def _make_payload(session_id: str, kind: str = "PreToolUse") -> str:
    """A realistic-shaped hook payload for an Edit on a small file."""
    return json.dumps(
        {
            "session_id": session_id,
            "transcript_path": "/tmp/transcript",
            "cwd": "/tmp",
            "hook_event_name": kind,
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "/tmp/perf-target.txt",
                "old_string": "a",
                "new_string": "b",
            },
            "tool_use_id": "perf-test",
        }
    )


def _setup_sandbox(agentwitness_bin: str) -> tuple[Path, dict[str, str]]:
    """Create a tmpdir-backed sandbox state, run install into it.

    Returns (sandbox_dir, env) so the caller can clean up and reuse env.
    """
    sandbox = Path(tempfile.mkdtemp(prefix="aw-bench-"))
    env = os.environ.copy()
    env["AGENTWITNESS_STATE_DIR"] = str(sandbox / "state")
    env["AGENTWITNESS_CLAUDE_SETTINGS"] = str(sandbox / "settings.json")

    result = subprocess.run([agentwitness_bin, "install"], env=env, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(f"sandbox install failed (exit {result.returncode}):\n{result.stderr}\n")
        shutil.rmtree(sandbox, ignore_errors=True)
        sys.exit(1)
    return sandbox, env


def _measure(agentwitness_bin: str, env: dict[str, str], iterations: int) -> list[float]:
    """Run ``iterations`` hook invocations, return per-run wall-clock millis."""
    times_ms: list[float] = []
    for i in range(iterations):
        payload = _make_payload(f"bench-session-{i}")
        start = time.perf_counter()
        result = subprocess.run(
            [agentwitness_bin, "hook"],
            input=payload,
            env=env,
            capture_output=True,
            text=True,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        if result.returncode != 0:
            sys.stderr.write(
                f"hook failed at iteration {i} (exit {result.returncode}): {result.stderr}\n"
            )
            continue
        times_ms.append(elapsed_ms)
    return times_ms


def _report(times_ms: list[float], iterations_requested: int) -> None:
    if not times_ms:
        sys.stderr.write("No successful measurements.\n")
        sys.exit(1)
    sorted_ms = sorted(times_ms)
    n = len(sorted_ms)
    p95_idx = max(0, int(n * 0.95) - 1)
    print(f"agentwitness hook latency over {n} invocations ({iterations_requested} requested):")
    print(f"  min:    {sorted_ms[0]:7.1f} ms")
    print(f"  median: {statistics.median(sorted_ms):7.1f} ms")
    print(f"  mean:   {statistics.mean(sorted_ms):7.1f} ms")
    print(f"  p95:    {sorted_ms[p95_idx]:7.1f} ms")
    print(f"  max:    {sorted_ms[-1]:7.1f} ms")


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark agentwitness hook end-to-end latency.")
    parser.add_argument(
        "--iterations",
        "-n",
        type=int,
        default=30,
        help="Number of hook invocations to measure (default 30).",
    )
    parser.add_argument(
        "--no-sandbox",
        action="store_true",
        help="Use the real installed state instead of a tmpdir sandbox.",
    )
    args = parser.parse_args()

    agentwitness_bin = shutil.which("agentwitness")
    if agentwitness_bin is None:
        sys.stderr.write(
            "agentwitness not on PATH. Activate the environment that has it installed.\n"
        )
        sys.exit(1)

    sandbox: Path | None = None
    if args.no_sandbox:
        env = os.environ.copy()
    else:
        sandbox, env = _setup_sandbox(agentwitness_bin)

    try:
        times_ms = _measure(agentwitness_bin, env, args.iterations)
        _report(times_ms, args.iterations)
    finally:
        if sandbox is not None:
            shutil.rmtree(sandbox, ignore_errors=True)


if __name__ == "__main__":
    main()
