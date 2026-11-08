"""
sandbox.py — minimal capped execution for the floor build.

Honest scope (also stated in the README): on the deployed demo this
runner executes inside a per-task Docker container on the Vultr VM
(--memory / --cpus caps, empty env, destroyed after the task). This
stdlib fallback enforces the same contract in-process when Docker is
unavailable: empty environment, wall-clock timeout + kill, output
capped, and a run record (with the SHA-256 of the output) returned
for the ledger. It is an isolated-runner demo, not a claim of
verified containment.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
import time


def run_snippet(code: str, timeout: float = 5.0,
                max_output: int = 8192) -> dict:
    started = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, timeout=timeout,
            env={},  # secret hygiene: the sandbox sees NO credentials
        )
        output = (proc.stdout or "")[:max_output]
        status = "ok" if proc.returncode == 0 else "error"
        stderr = (proc.stderr or "")[:1024]
    except subprocess.TimeoutExpired:
        output, status, stderr = "", "timeout_killed", ""
    duration = round(time.time() - started, 3)
    return {
        "status": status,
        "output": output,
        "stderr": stderr,
        "duration_s": duration,
        "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
        "env_keys_seen": [],  # by construction: env={} above
    }
