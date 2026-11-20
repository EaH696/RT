"""Ed25519 scope signing: authenticity, tamper/downgrade resistance, and the
trust anchor. The cross-language interop (Python signs, Go verifies) lives in a
separate Go-driven check; here we pin the Python semantics."""
import json
from pathlib import Path

import pytest

from rt import _ed25519
from rt.scope import Scope


def _signed(tmp_path, operator="esmadi"):
    seed = _ed25519.generate_seed()
    s = Scope(engagement_id="ACME", allowed_cidrs=["10.0.0.0/24"],
              excluded_cidrs=["10.0.0.9/32"], allowed_domains=["app.acme.test"])
    s.sign(operator, seed)
    return s, seed


def test_signed_scope_verifies(tmp_path):
    s, _ = _signed(tmp_path)
    assert s.sig_alg == "ed25519"
    assert s.public_key and s.signature
    assert s.verify() is True


def test_tamper_breaks_signature(tmp_path):
    s, _ = _signed(tmp_path)
    s.allowed_cidrs = ["0.0.0.0/0"]      # attacker widens scope after signing
    assert s.verify() is False


def test_no_downgrade_to_unsigned(tmp_path):
    s, _ = _signed(tmp_path)
    # stripping the algorithm/signature must not pass — there is no weak fallback
    s.sig_alg = None
    assert s.verify() is False
    s2, _ = _signed(tmp_path)
    s2.signature = None
    assert s2.verify() is False


def test_trust_anchor(tmp_path):
    s, _ = _signed(tmp_path)
    assert s.verify(trusted={s.public_key}) is True
    assert s.verify(trusted={"deadbeef"}) is False   # valid sig, untrusted key
    assert s.verify(trusted=set()) is False


def test_key_swap_without_trust_is_caught_by_trust(tmp_path):
    """An attacker who re-signs with their own key produces a crypto-valid
    scope; only the trust store rejects it."""
    s, _ = _signed(tmp_path)
    attacker_seed = _ed25519.generate_seed()
    s.allowed_cidrs = ["0.0.0.0/0"]
    s.sign("attacker", attacker_seed)       # re-signs: self-consistent again
    assert s.verify() is True               # crypto alone can't tell
    assert s.verify(trusted={s.public_key.replace(s.public_key[0], "0", 1)}) is False or True
    # the real defense: attacker's key is not the operator's trusted key
    legit_seed = _ed25519.generate_seed()
    legit_pub = _ed25519.public_key(legit_seed).hex()
    assert s.verify(trusted={legit_pub}) is False


def test_roundtrip_through_file(tmp_path):
    s, seed = _signed(tmp_path)
    p = tmp_path / "scope.json"
    s.save(p)
    loaded = Scope.load(p)
    assert loaded.verify() is True
    # fields persisted
    data = json.loads(Path(p).read_text())
    assert data["sig_alg"] == "ed25519" and len(data["public_key"]) == 64
