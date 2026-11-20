"""Pluggable signer tests.

SeedSigner and ExternalSigner are exercised fully (the latter against a real
out-of-process fake HSM). PKCS11Signer is covered for its import guard and URI
parsing; a live-token integration test is skipped unless python-pkcs11 and a
configured token are present.
"""
import os
import stat
import textwrap
from pathlib import Path

import pytest

from rt import _ed25519
from rt.scope import Scope
from rt.signing import (
    SeedSigner, ExternalSigner, PKCS11Signer, make_signer, SignerError,
)


# -- a fake out-of-process HSM, implementing the ExternalSigner contract ----- #

FAKE_HSM = textwrap.dedent('''\
    #!/usr/bin/env python3
    import sys, hashlib
    # a deterministic test "HSM": holds a fixed seed, signs with vendored ed25519
    sys.path.insert(0, {rtpath!r})
    from rt import _ed25519
    SEED = bytes(range(32))
    if sys.argv[1] == "pubkey":
        print(_ed25519.public_key(SEED).hex())
    elif sys.argv[1] == "sign":
        msg = bytes.fromhex(sys.stdin.read().strip())
        print(_ed25519.sign(SEED, msg).hex())
    else:
        sys.exit(2)
''')

# a signer that returns a signature from the WRONG key (self-check must catch it)
BAD_HSM = textwrap.dedent('''\
    #!/usr/bin/env python3
    import sys
    sys.path.insert(0, {rtpath!r})
    from rt import _ed25519
    GOOD = bytes(range(32)); WRONG = bytes([9])*32
    if sys.argv[1] == "pubkey":
        print(_ed25519.public_key(GOOD).hex())        # advertises GOOD
    elif sys.argv[1] == "sign":
        msg = bytes.fromhex(sys.stdin.read().strip())
        print(_ed25519.sign(WRONG, msg).hex())        # but signs with WRONG
    else:
        sys.exit(2)
''')


def _script(tmp_path, name, body):
    rtpath = str(Path(__file__).resolve().parents[1])  # orchestrator/ on sys.path
    p = tmp_path / name
    p.write_text(body.format(rtpath=rtpath))
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return p


# -- SeedSigner -------------------------------------------------------------- #

def test_seed_signer_matches_primitive():
    seed = _ed25519.generate_seed()
    s = SeedSigner(seed)
    assert s.public_key() == _ed25519.public_key(seed)
    msg = b"roe"
    assert _ed25519.verify(s.public_key(), msg, s.sign(msg))


def test_seed_signer_from_file(tmp_path):
    seed = _ed25519.generate_seed()
    f = tmp_path / "op.key"; f.write_text(seed.hex() + "\n")
    assert SeedSigner.from_file(f).public_key() == _ed25519.public_key(seed)


# -- ExternalSigner (real subprocess) ---------------------------------------- #

def test_external_signer_signs_a_scope(tmp_path):
    hsm = _script(tmp_path, "hsm.py", FAKE_HSM)
    signer = ExternalSigner(["python3", str(hsm)])
    expected_pub = _ed25519.public_key(bytes(range(32))).hex()
    assert signer.public_key().hex() == expected_pub

    sc = Scope(engagement_id="ACME", allowed_cidrs=["10.0.0.0/24"])
    sc.sign_with("esmadi", signer)
    assert sc.verify() is True
    assert sc.public_key == expected_pub      # key came from the "HSM", not RT


def test_external_signer_rejects_wrong_key_signature(tmp_path):
    bad = _script(tmp_path, "bad.py", BAD_HSM)
    signer = ExternalSigner(["python3", str(bad)])
    with pytest.raises(SignerError, match="does not verify"):
        signer.sign(b"message")


def test_external_signer_missing_command():
    with pytest.raises(SignerError, match="not found"):
        ExternalSigner(["/nonexistent/hsm-binary"]).public_key()


# -- make_signer dispatch ---------------------------------------------------- #

def test_make_signer_dispatch(tmp_path):
    seed = _ed25519.generate_seed()
    f = tmp_path / "op.key"; f.write_text(seed.hex())
    assert isinstance(make_signer(f"seed:{f}"), SeedSigner)
    assert isinstance(make_signer("seed:" + seed.hex()), SeedSigner)
    assert isinstance(make_signer("cmd:/usr/bin/true arg"), ExternalSigner)
    assert isinstance(make_signer("pkcs11:module=/x.so;key=operator"), PKCS11Signer)
    with pytest.raises(SignerError):
        make_signer("bogus:whatever")
    with pytest.raises(SignerError):
        make_signer("pkcs11:token=only")   # missing module/key


# -- PKCS11Signer ------------------------------------------------------------ #

def test_pkcs11_import_guard_is_clear():
    """Without python-pkcs11, the backend fails with an actionable message
    rather than an opaque ImportError (the common appliance state until the
    operator installs it)."""
    pytest.importorskip  # noqa: keep pytest import meaningful
    try:
        import pkcs11  # noqa: F401
        pytest.skip("python-pkcs11 is installed; live-token test not run here")
    except ImportError:
        pass
    signer = PKCS11Signer(module="/usr/lib/softhsm/libsofthsm2.so", key_label="operator")
    with pytest.raises(SignerError, match="python-pkcs11"):
        signer.public_key()
