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
have touched an out-of-scope asset.

Signatures are Ed25519 (RFC 8032). The operator holds a 32-byte private seed
(`rt keygen`); the signature and the operator's public key are embedded in
scope.json. Verification is asymmetric — the policy-gate and any auditor verify
with the public key and can never forge a scope, and the gate additionally
checks that the signing key is in its provisioned trust store. There is NO
symmetric/checksum fallback: a scope without a valid Ed25519 signature does not
verify, so an attacker cannot strip the algorithm field to downgrade it. The
pure-Python signer (rt._ed25519) keeps the core dependency-free; swap the seed
file for a KMS/HSM-backed signer in production by replacing `Scope.sign`.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path

from . import _ed25519


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
    sig_alg: str | None = None       # "ed25519" once signed
    public_key: str | None = None    # operator Ed25519 public key, hex (32 bytes)
    signature: str | None = None     # Ed25519 signature over the canonical body, hex

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

    def sign(self, operator: str, seed: bytes | str) -> "Scope":
        """Operator attests the ROE with an Ed25519 seed (dev/default path).

        For production, hold the key in an HSM or behind a signing agent and use
        `sign_with` with a non-seed Signer — the verify path is identical.
        """
        from .signing import SeedSigner
        seed_b = seed if isinstance(seed, (bytes, bytearray)) else bytes.fromhex(seed.strip())
        if len(seed_b) != 32:
            raise ScopeError("signing seed must be 32 bytes (see `rt keygen`)")
        return self.sign_with(operator, SeedSigner(seed_b))

    def sign_with(self, operator: str, signer) -> "Scope":
        """Attest the ROE using any Ed25519 `Signer` (rt.signing).

        The signed body includes signed_by, sig_alg, and public_key, so none can
        be swapped without breaking the signature. The private key stays inside
        the signer (HSM/agent/token); this method only hands it the canonical
        bytes to sign.
        """
        pub = signer.public_key()
        if len(pub) != 32:
            raise ScopeError("signer public key must be 32 bytes (Ed25519)")
        self.signed_by = operator
        self.sig_alg = "ed25519"
        self.public_key = pub.hex()
        sig = signer.sign(self.canonical().encode())
        if len(sig) != 64:
            raise ScopeError("signer produced a non-Ed25519 signature")
        self.signature = sig.hex()
        if not self.verify():
            raise ScopeError("produced signature does not verify — signer/key mismatch")
        return self

    def verify(self, trusted: set[str] | None = None) -> bool:
        """True iff the Ed25519 signature is valid for the embedded public key.

        If `trusted` is given (a set of accepted public-key hex strings), the
        signing key must also be a member — this is the trust anchor the gate
        enforces. With no `trusted` set, only cryptographic authenticity is
        checked (fine on the operator's own box signing their own scope).
        """
        if self.sig_alg != "ed25519" or not self.signature or not self.public_key:
            return False
        if trusted is not None and self.public_key not in trusted:
            return False
        try:
            return _ed25519.verify(
                bytes.fromhex(self.public_key),
                self.canonical().encode(),
                bytes.fromhex(self.signature),
            )
        except ValueError:
            return False

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
