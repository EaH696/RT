"""Hash-chained audit log: linkage, verification, and tamper/deletion detection."""
import sqlite3

from rt.audit import open_audit, GENESIS
from rt.store import Store
from rt.engine import Engine
import json


def test_chain_links_and_verifies(tmp_path):
    log = open_audit(str(tmp_path / "audit.sqlite"))
    e1 = log.record("esmadi", "engagement.init", engagement_id="E", objective="x")
    e2 = log.record("cmd", "task.create", engagement_id="E", target="10.0.0.5", task="t001")
    e3 = log.record("esmadi", "task.confirm", engagement_id="E", target="10.0.0.5", task="t001")

    assert e1.prev_hash == GENESIS
    assert e2.prev_hash == e1.entry_hash
    assert e3.prev_hash == e2.entry_hash
    ok, broken = log.verify()
    assert ok and broken is None


def test_detects_tampering(tmp_path):
    path = tmp_path / "audit.sqlite"
    log = open_audit(str(path))
    log.record("esmadi", "engagement.init", engagement_id="E")
    log.record("cmd", "task.create", engagement_id="E", target="10.0.0.5", task="t001")
    log.record("esmadi", "task.confirm", engagement_id="E", target="10.0.0.5", task="t001")
    log.close()

    # someone edits the approval out-of-band to point at a different target
    con = sqlite3.connect(path)
    con.execute("UPDATE audit SET target='10.9.9.9' WHERE seq=3")
    con.commit(); con.close()

    ok, broken = open_audit(str(path)).verify()
    assert ok is False and broken == 3


def test_detects_deletion(tmp_path):
    path = tmp_path / "audit.sqlite"
    log = open_audit(str(path))
    for i in range(1, 5):
        log.record("a", "finding.add", engagement_id="E", seq_note=str(i))
    log.close()

    con = sqlite3.connect(path)
    con.execute("DELETE FROM audit WHERE seq=2")  # remove an entry
    con.commit(); con.close()

    ok, broken = open_audit(str(path)).verify()
    assert ok is False and broken == 3  # seq gap detected at the next entry


def test_engine_records_to_audit(tmp_path):
    s = Store(tmp_path / ".rt")
    s.init(engagement_id="E", objective="x", scope_ref="scope.json")
    f = s.add_finding("host", creator="seed", kind="host", target="10.0.0.5")
    s.add_task([f["id"]], "enumerate", creator="cmd", risk_tier="enum", target="10.0.0.5")

    log = open_audit(str(tmp_path / "audit.sqlite"))

    def agent(_p):
        return {"result": json.dumps({"accepted": True, "data": {
            "kind": "service", "title": "ssh", "description": "22 open",
            "data": {"host": "10.0.0.5", "port": "22"}}})}

    Engine(s, agent, audit=log).run()
    actions = [e.action for e in log.entries()]
    assert "task.dispatch" in actions and "task.conclude" in actions
    ok, _ = log.verify()
    assert ok
