"""
rt.scope — the signed engagement scope (Rules of Engagement).

This is the single most important safety object in RT. It replaces sapper's
hard-wired CTF "arena" target with an explicit, signed description of exactly
what an engagement is authorized to touch:

    * allowed targets   — CIDR ranges and domains the client authorized
    * excluded targets  — assets explicitly carved out (prod DB, etc.)
    * time window       — when testing is permitted
    * rate limits       — caps to avoid DoS-ing the client

The Python side here is DEFENSE IN DEPTH — a fast local check the orchestrator
runs before it ever dispatches a task. The AUTHORITATIVE enforcement is the Go
policy-gate (/policy-gate), which both re-validates every tool call AND
physically blocks out-of-scope egress. A confused or jailbroken agent must be
unable to reach an excluded host even if this check is bypassed.

The scope is signed at engagement creation (operator signs the ROE). The
signature is what you show a client — and an insurer — to prove RT could not
have touched an out-of-scope asset. Signing/verification here is a stub
(sha256 digest); wire it to your real KMS/HSM before production.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path


class ScopeError(Exception):
    pass


@dataclass
class Scope:
    engagement_id: str
    allowed_cidrs: list[str] = field(default_factory=list)
    allowed_domains: list[str] = field(default_factory=list)
    excluded_cidrs: list[str] = field(default_factory=list)
    excluded_domains: list[str] = field(default_factory=list)
    window_start: str | None = None  # ISO8601
    window_end: str | None = None
    max_rps: int = 50
    signed_by: str | None = None
    signature: str | None = None  # digest over the canonical scope body

    # -- canonical body (everything except the signature) ------------------ #
    def _body(self) -> dict:
        d = asdict(self)
        d.pop("signature", None)
        return d

    def canonical(self) -> str:
        # Compact separators + sorted keys so this matches the Go policy-gate's
        # canonical form byte-for-byte (both sign/verify the same scope).
        return json.dumps(self._body(), sort_keys=True, ensure_ascii=False,
                          separators=(",", ":"))

    def sign(self, operator: str) -> "Scope":
        """Stub signer. Replace with KMS/HSM. Operator attests the ROE."""
        self.signed_by = operator
        self.signature = hashlib.sha256(self.canonical().encode()).hexdigest()
        return self

    def verify(self) -> bool:
        if not self.signature:
            return False
        return self.signature == hashlib.sha256(self.canonical().encode()).hexdigest()

    # -- the check --------------------------------------------------------- #
    def permits(self, target: str) -> bool:
        """True iff `target` (an IP, CIDR, host, or URL host) is in scope.

        Exclusions always win over inclusions.
        """
        host = _host_of(target)
        # IP / CIDR path
        ip = _as_ip(host)
        if ip is not None:
            for net in self.excluded_cidrs:
                if ip in ipaddress.ip_network(net, strict=False):
                    return False
            for net in self.allowed_cidrs:
                if ip in ipaddress.ip_network(net, strict=False):
                    return True
            return False
        # domain path
        h = host.lower().rstrip(".")
        for dom in self.excluded_domains:
            if _domain_match(h, dom):
                return False
        for dom in self.allowed_domains:
            if _domain_match(h, dom):
                return True
        return False

    def require(self, target: str) -> None:
        if not self.permits(target):
            raise ScopeError(f"target {target!r} is OUT OF SCOPE for {self.engagement_id}")

    # -- io ---------------------------------------------------------------- #
    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(**data)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(asdict(self), indent=2, ensure_ascii=False), encoding="utf-8"
        )


def _host_of(target: str) -> str:
    t = target.strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    t = t.rsplit("@", 1)[-1]
    if t.startswith("["):  # [ipv6]:port
        return t[1:].split("]", 1)[0]
    if t.count(":") == 1:  # host:port
        t = t.split(":", 1)[0]
    return t


def _as_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _domain_match(host: str, pattern: str) -> bool:
    pattern = pattern.lower().lstrip("*.").rstrip(".")
    return host == pattern or host.endswith("." + pattern)
