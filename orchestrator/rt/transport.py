"""
rt.transport — clients for the Go services (policy-gate, sandbox).

The orchestrator (Python) talks to the two Go services across the appliance's
internal network. The wire contract is proto/rt.proto; the transport here is
HTTP+JSON over stdlib urllib so the core stays dependency-free and runnable on
an air-gapped box.

Swapping to gRPC-on-the-wire is a localized change: generate stubs from
proto/rt.proto (`python -m grpc_tools.protoc ...`) and reimplement GateClient /
SandboxClient against the generated stubs. Nothing else in the orchestrator
imports the transport details — the Engine and scope code depend only on the
method signatures below, which mirror the proto service methods
(PolicyGate.Check, ToolRunner.Run).
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass


class TransportError(Exception):
    pass


def _post(url: str, body: dict, timeout: int = 30) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (internal URL)
            return json.loads(resp.read().decode())
    except urllib.error.URLError as exc:
        raise TransportError(f"POST {url} failed: {exc}") from exc


@dataclass
class Decision:
    target: str
    allowed: bool
    reason: str


class GateClient:
    """Client for PolicyGate.Check (proto/rt.proto)."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def check(self, target: str, engagement_id: str = "") -> Decision:
        d = _post(f"{self.base_url}/check",
                  {"engagement_id": engagement_id, "target": target})
        return Decision(d.get("target", target), bool(d.get("allowed")), d.get("reason", ""))


@dataclass
class ToolResult:
    exit_code: int
    stdout: str
    stderr: str
    err: str = ""


class SandboxClient:
    """Client for ToolRunner.Run (proto/rt.proto)."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def run(self, *, tool: str, target: str, tier: str, confirmed: bool,
            args: dict | None = None, timeout_seconds: int = 120) -> ToolResult:
        d = _post(f"{self.base_url}/run", {
            "tool": tool, "target": target, "tier": tier, "confirmed": confirmed,
            "args": args or {}, "timeout_seconds": timeout_seconds,
        }, timeout=timeout_seconds + 10)
        return ToolResult(int(d.get("exit_code", -1)), d.get("stdout", ""),
                          d.get("stderr", ""), d.get("err", ""))
