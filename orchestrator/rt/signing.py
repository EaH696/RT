"""
rt.signing — pluggable Ed25519 signers for the Rules of Engagement.

The scope signature is the liability spine: it attests that the operator
authorized exactly these targets. On a real engagement the operator's private
key must NOT be a plaintext file RT can read — it should live in an HSM or
behind a signing agent. This module puts the key material behind a `Signer`
interface so `Scope.sign` never holds it directly.

The algorithm is fixed: Ed25519 (RFC 8032). A signer only has to (a) expose the
32-byte raw public key and (b) return a 64-byte Ed25519 signature over a message
it is handed. The policy-gate's verify path is unchanged regardless of which
signer produced the signature.

Backends:

  * SeedSigner      — a 32-byte seed in memory (or a file). Pure-Python, no
                      dependencies; the dev/default path. NOT for production —
                      the key is readable.
  * ExternalSigner  — delegates to an operator-provided command that holds the
                      key (an HSM wrapper, a cloud-KMS/Azure Managed HSM shim, an
                      agent). RT passes the message and gets a signature back; it
                      never sees the private key. Hardware-agnostic.
  * PKCS11Signer    — a PKCS#11 token (YubiHSM2, Nitrokey, SoftHSM, …) via
                      CKM_EDDSA. The air-gap-appropriate hardware backend.
                      Requires `python-pkcs11`.

`make_signer(uri)` builds one from a URI:

    seed:/path/to/operator.key                      (or seed:<hex>)
    cmd:/usr/local/bin/rt-hsm-sign                   (+ optional args)
    pkcs11:module=/usr/lib/softhsm/libsofthsm2.so;token=rt;key=operator;pin=1234
"""
from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from typing import Protocol, runtime_checkable

from . import _ed25519


class SignerError(Exception):
    pass


@runtime_checkable
class Signer(Protocol):
    def public_key(self) -> bytes:
        """The 32-byte raw Ed25519 public key."""
        ...

    def sign(self, message: bytes) -> bytes:
        """A 64-byte Ed25519 signature over `message`."""
        ...


# --------------------------------------------------------------------------- #
# seed in memory / file (dev default)
# --------------------------------------------------------------------------- #

class SeedSigner:
    def __init__(self, seed: bytes):
        if len(seed) != 32:
            raise SignerError("seed must be 32 bytes")
        self._seed = seed

    @classmethod
    def from_file(cls, path: str | Path) -> "SeedSigner":
        text = Path(path).read_text(encoding="utf-8").strip()
        return cls(bytes.fromhex(text))

    def public_key(self) -> bytes:
        return _ed25519.public_key(self._seed)

    def sign(self, message: bytes) -> bytes:
        return _ed25519.sign(self._seed, message)


# --------------------------------------------------------------------------- #
# external signing command (HSM / KMS / agent wrapper)
# --------------------------------------------------------------------------- #

class ExternalSigner:
    """Delegate to an operator-provided command that holds the key.

    Contract (keeps the key out of RT, language-agnostic):
      * `<cmd> pubkey`            -> prints 64 hex chars (the raw public key)
      * `<cmd> sign`  (msg hex on stdin) -> prints 128 hex chars (the signature)

    RT self-checks every signature against the returned public key before
    trusting it, so a misconfigured or wrong-key signer fails loudly at signing
    time rather than producing a scope the gate will later reject.
    """

    def __init__(self, argv: list[str], *, timeout: int = 30):
        if not argv:
            raise SignerError("external signer command is empty")
        self._argv = argv
        self._timeout = timeout

    def _run(self, extra: list[str], stdin: str | None = None) -> str:
        try:
            proc = subprocess.run(
                self._argv + extra, input=stdin, capture_output=True, text=True,
                timeout=self._timeout,
            )
        except FileNotFoundError:
            raise SignerError(f"external signer not found: {self._argv[0]!r}")
        except subprocess.TimeoutExpired:
            raise SignerError(f"external signer timed out after {self._timeout}s")
        if proc.returncode != 0:
            raise SignerError(f"external signer failed ({proc.returncode}): "
                              f"{proc.stderr.strip()[:300]}")
        return proc.stdout.strip()

    def public_key(self) -> bytes:
        out = self._run(["pubkey"])
        try:
            pub = bytes.fromhex(out)
        except ValueError:
            raise SignerError("external signer `pubkey` did not return hex")
        if len(pub) != 32:
            raise SignerError(f"external signer public key is {len(pub)} bytes, want 32")
        return pub

    def sign(self, message: bytes) -> bytes:
        out = self._run(["sign"], stdin=message.hex())
        try:
            sig = bytes.fromhex(out)
        except ValueError:
            raise SignerError("external signer `sign` did not return hex")
        if len(sig) != 64:
            raise SignerError(f"external signer signature is {len(sig)} bytes, want 64")
        if not _ed25519.verify(self.public_key(), message, sig):
            raise SignerError("external signer returned a signature that does not "
                              "verify against its own public key — wrong key or buggy signer")
        return sig


# --------------------------------------------------------------------------- #
# PKCS#11 HSM (CKM_EDDSA)
# --------------------------------------------------------------------------- #

class PKCS11Signer:
    """Sign with an Ed25519 key resident in a PKCS#11 token.

    The private key never leaves the token. Requires `python-pkcs11`; the module
    is imported lazily so the orchestrator core stays dependency-free when this
    backend is not used. Provision the key in the token out of band (e.g.
    `pkcs11-tool --keypairgen --key-type EC:edwards25519 --label operator`).
    """

    def __init__(self, *, module: str, key_label: str,
                 token_label: str | None = None, pin: str | None = None):
        self._module = module
        self._key_label = key_label
        self._token_label = token_label
        self._pin = pin

    def _session(self):
        try:
            import pkcs11  # type: ignore
        except ImportError as e:
            raise SignerError(
                "PKCS#11 signer needs `python-pkcs11` installed "
                "(pip install python-pkcs11)"
            ) from e
        try:
            lib = pkcs11.lib(self._module)
            token = (lib.get_token(token_label=self._token_label)
                     if self._token_label else next(iter(lib.get_tokens())))
            return pkcs11, token.open(user_pin=self._pin)
        except Exception as e:  # pragma: no cover - needs a live token
            raise SignerError(f"PKCS#11 open failed: {e}") from e

    def public_key(self) -> bytes:  # pragma: no cover - needs a live token
        pkcs11, session = self._session()
        with session:
            key = session.get_key(label=self._key_label,
                                  object_class=pkcs11.ObjectClass.PUBLIC_KEY)
            # EC_POINT for an Edwards key is the 32-byte public key, DER-wrapped
            # as an OCTET STRING; strip the 2-byte tag/len prefix when present.
            raw = key[pkcs11.Attribute.EC_POINT]
            if len(raw) == 34 and raw[0] == 0x04:
                raw = raw[2:]
            if len(raw) != 32:
                raise SignerError(f"unexpected EC_POINT length {len(raw)}")
            return bytes(raw)

    def sign(self, message: bytes) -> bytes:  # pragma: no cover - needs a live token
        pkcs11, session = self._session()
        with session:
            key = session.get_key(label=self._key_label,
                                  object_class=pkcs11.ObjectClass.PRIVATE_KEY)
            sig = key.sign(message, mechanism=pkcs11.Mechanism.EDDSA)
            if len(sig) != 64:
                raise SignerError(f"PKCS#11 returned {len(sig)}-byte signature, want 64")
            return bytes(sig)


# --------------------------------------------------------------------------- #
# factory
# --------------------------------------------------------------------------- #

def make_signer(uri: str) -> Signer:
    scheme, _, rest = uri.partition(":")
    if not rest:
        raise SignerError(f"signer URI must be <scheme>:<spec> (got {uri!r})")
    if scheme == "seed":
        p = Path(rest)
        if p.exists():
            return SeedSigner.from_file(p)
        return SeedSigner(bytes.fromhex(rest.strip()))
    if scheme == "cmd":
        return ExternalSigner(shlex.split(rest))
    if scheme == "pkcs11":
        params = dict(kv.split("=", 1) for kv in rest.split(";") if "=" in kv)
        if "module" not in params or "key" not in params:
            raise SignerError("pkcs11 URI needs at least module=... and key=...")
        return PKCS11Signer(module=params["module"], key_label=params["key"],
                            token_label=params.get("token"), pin=params.get("pin"))
    raise SignerError(f"unknown signer scheme {scheme!r} (use seed:, cmd:, or pkcs11:)")
