"""
rt.runner — model-agnostic agent CLI runner.

Ported from sapper-v2's run_claude (MIT, (c) 2026 N1nEmAn; see /NOTICE). The
agent behind each role is swappable: set RT_AGENT_BIN to any CLI that reads a
prompt on stdin and prints a JSON envelope {"result": "..."} on stdout
(Claude Code, Codex, a local-model wrapper, etc.). On a self-hosted appliance
this usually points at a wrapper around a locally served model so no target
data leaves the box.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


class RunnerError(Exception):
    pass


def run_agent(
    prompt: str,
    *,
    model: str,
    timeout: int = 900,
    cwd: Path | None = None,
    append_system: str | None = None,
) -> dict:
    if timeout < 1:
        raise RunnerError("timeout must be >= 1s")
    if not model.strip():
        raise RunnerError("model cannot be empty")
    prefix = os.environ.get("RT_AGENT_BIN", "claude").split()
    argv = prefix + ["-p", "--output-format", "json", "--model", model]
    if append_system:
        argv += ["--append-system-prompt", append_system]
    engine = prefix[0]
    try:
        proc = subprocess.run(
            argv, input=prompt, capture_output=True, text=True,
            timeout=timeout, cwd=str(cwd) if cwd else None,
        )
    except FileNotFoundError:
        raise RunnerError(f"`{engine}` not on PATH; install it or set RT_AGENT_BIN")
    except subprocess.TimeoutExpired:
        raise RunnerError(f"{engine} timed out after {timeout}s")
    if proc.returncode != 0:
        raise RunnerError(f"{engine} exited {proc.returncode}: {proc.stderr.strip()[:500]}")
    try:
        envelope = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise RunnerError(f"{engine} did not return JSON. stdout[:300]={proc.stdout[:300]!r}")
    if not isinstance(envelope, dict) or not isinstance(envelope.get("result", ""), str):
        raise RunnerError("agent returned a malformed envelope")
    if envelope.get("is_error"):
        raise RunnerError(f"{engine} error: {str(envelope.get('result'))[:300]}")
    return envelope
