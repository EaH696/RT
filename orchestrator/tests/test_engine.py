"""The durable loop: auto-dispatch, pause at the operator gate, resume, and
crash-safe restart (a fresh Engine continues from the on-disk graph)."""
import json

from rt.store import Store, awaiting_confirmation
from rt.engine import Engine


def _init(tmp_path):
    s = Store(tmp_path / ".rt")
    s.init(engagement_id="T", objective="map and breach", scope_ref="scope.json")
    return s


def _agent(mapping):
    """Fake agent: returns a canned accepted finding per task description substring."""
    def fn(prompt: str) -> dict:
        for needle, data in mapping.items():
            if needle in prompt:
                return {"result": json.dumps({"accepted": True, "data": data})}
        return {"result": json.dumps({"accepted": True, "data": {
            "title": "done", "description": "generic", "kind": "note"}})}
    return fn


def test_recon_autoruns_and_concludes(tmp_path):
    s = _init(tmp_path)
    f = s.add_finding("host 10.0.0.5 up", creator="seed", kind="host", target="10.0.0.5")
    t = s.add_task([f["id"]], "enumerate services on 10.0.0.5", creator="cmd",
                   risk_tier="enum", target="10.0.0.5")
    eng = Engine(s, _agent({"enumerate services": {
        "title": "ssh found", "description": "22/tcp open ssh",
        "kind": "service", "data": {"host": "10.0.0.5", "port": "22"}}}))
    report = eng.run()
    assert report.concluded == 1
    assert report.stopped_reason == "frontier exhausted"
    assert s.get_task(t["id"])["to"] is not None          # concluded
    assert any(f["kind"] == "service" for f in s.list_findings())


def test_pause_at_gate_then_resume(tmp_path):
    s = _init(tmp_path)
    f = s.add_finding("vuln on 10.0.0.5", creator="seed", kind="vuln", target="10.0.0.5")
    gated = s.add_task([f["id"]], "exploit the rce", creator="cmd",
                       risk_tier="exploit", target="10.0.0.5")
    eng = Engine(s, _agent({"exploit the rce": {
        "title": "rce", "description": "popped a shell", "kind": "vuln",
        "data": {"host": "10.0.0.5", "severity": "critical", "status": "exploited"}}}))

    # 1. loop runs but the gated task does NOT execute — it pauses at the gate
    report = eng.run()
    assert report.concluded == 0
    assert report.stopped_reason == "awaiting operator confirmation"
    assert s.get_task(gated["id"])["to"] is None
    assert gated["id"] in {t["id"] for t in awaiting_confirmation(s)}

    # 2. operator confirms, then a BRAND-NEW Engine (simulating a restart)
    #    resumes and runs it — proving durability is in the graph, not memory
    s.confirm_task(gated["id"], operator="esmadi")
    eng2 = Engine(Store(tmp_path / ".rt"), eng.agent)
    report2 = eng2.run()
    assert report2.concluded == 1
    done = s.get_task(gated["id"])
    assert done["to"] is not None
    assert done["confirmed_by"] == "esmadi"


def test_rejection_concludes_as_note_no_infinite_loop(tmp_path):
    s = _init(tmp_path)
    f = s.add_finding("host up", creator="seed", kind="host", target="10.0.0.5")
    s.add_task([f["id"]], "enumerate", creator="cmd", risk_tier="enum", target="10.0.0.5")

    def rejecting(_prompt):
        return {"result": json.dumps({"accepted": False, "reason": "not reachable"})}

    report = Engine(s, rejecting).run(max_steps=10)
    # rejected task is concluded with a note, so the loop terminates cleanly
    assert report.stopped_reason == "frontier exhausted"
    assert report.steps[0].status == "rejected"
    assert any(f["kind"] == "note" and "rejected" in (f.get("title") or "")
               for f in s.list_findings())
