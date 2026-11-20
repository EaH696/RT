"""Operator console API: state, the approval queue, and confirming via HTTP."""
import json
import threading
import urllib.request

import pytest

from rt.store import Store
from rt.audit import open_audit
from rt.console import serve, build_state


@pytest.fixture
def engagement(tmp_path):
    s = Store(tmp_path / ".rt")
    s.init(engagement_id="C", objective="demo", scope_ref="scope.json")
    f = s.add_finding("vuln svc", creator="recon", kind="vuln", target="10.0.0.5",
                      data={"severity": "critical"})
    s.add_task([f["id"]], "exploit it", creator="cmd", risk_tier="exploit", target="10.0.0.5")
    open_audit(str(tmp_path / ".rt" / "audit.sqlite")).record("op", "engagement.init", engagement_id="C")
    return tmp_path / ".rt"


def test_build_state_queue(engagement):
    st = build_state(Store(engagement))
    assert st["engagement"]["id"] == "C"
    assert st["counts"]["vulns"] == 1
    assert len(st["queue"]) == 1 and st["queue"][0]["tier"] == "exploit"


def _server(store_dir):
    httpd = serve(str(store_dir), host="127.0.0.1", port=0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def _get(port, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}") as r:
        return json.loads(r.read())


def _post(port, path, body):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                 data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_console_confirm_flow(engagement):
    httpd, port = _server(engagement)
    try:
        st = _get(port, "/api/state")
        tid = st["queue"][0]["id"]
        assert st["counts"]["queue"] == 1

        # confirming requires an operator name
        code, d = _post(port, "/api/confirm", {"task_id": tid, "operator": ""})
        assert code == 400 and d["ok"] is False

        # valid confirm clears the queue and records to the audit log
        code, d = _post(port, "/api/confirm", {"task_id": tid, "operator": "esmadi"})
        assert code == 200 and d["ok"] is True
        assert _get(port, "/api/state")["counts"]["queue"] == 0

        audit = _get(port, "/api/audit")
        assert audit["verified"] is True
        assert any(e["action"] == "task.confirm" and e["actor"] == "esmadi"
                   for e in audit["entries"])
    finally:
        httpd.shutdown()


def test_console_serves_html(engagement):
    httpd, port = _server(engagement)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as r:
            html = r.read().decode()
        assert "RT Operator Console" in html and "Approval queue" in html
    finally:
        httpd.shutdown()
