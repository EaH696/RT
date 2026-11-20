"""Tests for the hash-chained audit log and its tamper detection."""
import sqlite3

import pytest

from rt.audit import SQLiteAudit, open_audit, AuditError, GENESIS
from rt.store import Store


def _audit(tmp_path):
    return SQLiteAudit(str(tmp_path / "audit.db"))


def test_append_chains_and_verifies(tmp_path):
    a = _audit(tmp_path)
    e1 = a.append("engagement.init", actor="op", data={"engagement_id": "X"})
    e2 = a.append("finding.add", actor="recon", data={"id": "f001"})
    assert e1["seq"] == 1 and e1["prev_hash"] == GENESIS
    assert e2["seq"] == 2 and e2["prev_hash"] == e1["entry_hash"]
    ok, broken, reason = a.verify()
    assert ok and broken is None


def test_unknown_event_and_missing_actor_rejected(tmp_path):
    a = _audit(tmp_path)
    with pytest.raises(AuditError):
        a.append("not.a.real.event", actor="op")
    with pytest.raises(AuditError):
        a.append("finding.add", actor="  ")


def test_tamper_is_detected(tmp_path):
    a = _audit(tmp_path)
    a.append("engagement.init", actor="op", data={"engagement_id": "X"})
    a.append("task.create", actor="commander", data={"id": "t001", "tier": "exploit"})
    a.append("task.confirm", actor="op", data={"id": "t001"})
    # tamper: downgrade the exploit task's tier directly in the DB
    conn = sqlite3.connect(str(tmp_path / "audit.db"))
    conn.execute("UPDATE audit SET data = ? WHERE seq = 2",
                 ('{"id":"t001","tier":"recon"}',))
    conn.commit(); conn.close()
    ok, broken, reason = a.verify()
    assert not ok
    assert broken == 2
    assert "recompute" in reason


def test_deletion_breaks_chain(tmp_path):
    a = _audit(tmp_path)
    for i in range(3):
        a.append("finding.add", actor="recon", data={"id": f"f{i}"})
    conn = sqlite3.connect(str(tmp_path / "audit.db"))
    conn.execute("DELETE FROM audit WHERE seq = 2")
    conn.commit(); conn.close()
    ok, broken, reason = a.verify()
    assert not ok and broken == 2  # gap where seq 2 used to be


def test_open_audit_selects_backend(tmp_path):
    assert isinstance(open_audit(str(tmp_path / "a.db")), SQLiteAudit)
    from rt.audit import PostgresAudit
    assert isinstance(open_audit("postgres://u@h/db"), PostgresAudit)


def test_store_emits_audit_trail(tmp_path):
    """The store, given an audit sink, logs the gated-exploit lifecycle."""
    a = _audit(tmp_path)
    s = Store(tmp_path / ".rt", audit=a)
    s.init(engagement_id="T", objective="pwn", scope_ref="scope.json")
    f = s.add_finding("vuln", creator="recon", kind="vuln", target="10.0.0.5")
    t = s.add_task([f["id"]], "exploit it", creator="commander",
                   risk_tier="exploit", target="10.0.0.5")
    # blocked before confirmation
    with pytest.raises(Exception):
        s.claim_task(t["id"], worker="exploit")
    s.confirm_task(t["id"], operator="esmadi")
    s.claim_task(t["id"], worker="exploit")

    events = [e["event"] for e in a.entries()]
    assert events == [
        "engagement.init", "finding.add", "task.create",
        "task.blocked", "task.confirm", "task.dispatch",
    ]
    ok, _, _ = a.verify()
    assert ok
    # the confirming operator is captured in the trail
    confirm = next(e for e in a.entries() if e["event"] == "task.confirm")
    assert confirm["actor"] == "esmadi"
