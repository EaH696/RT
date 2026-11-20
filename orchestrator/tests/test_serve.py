"""Tests for the operator console API (rt.serve), driven in-process.

A real ThreadingHTTPServer is started on an ephemeral port so the handler,
routing, and the approve->confirm->audit path are exercised end to end.
"""
import json
import threading
import urllib.request
import urllib.error

import pytest

from http.server import ThreadingHTTPServer

from rt.store import Store
from rt.audit import SQLiteAudit
from rt.serve import make_handler


@pytest.fixture
def server(tmp_path):
    audit = SQLiteAudit(str(tmp_path / "audit.db"))
    s = Store(tmp_path / ".rt", audit=audit)
    s.init(engagement_id="ACME", objective="pwn", scope_ref="scope.json")
    f = s.add_finding("vuln", creator="recon", kind="vuln", target="10.0.0.5")
    s.add_task([f["id"]], "exploit it", creator="commander",
               risk_tier="exploit", target="10.0.0.5")  # t001, gated
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(s))
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}", s
    httpd.shutdown()


def _get(base, path):
    with urllib.request.urlopen(base + path, timeout=5) as r:
        return r.status, json.loads(r.read())


def _post(base, path, body):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_engagement_and_graph(server):
    base, _ = server
    code, eng = _get(base, "/api/engagement")
    assert code == 200
    assert eng["engagement_id"] == "ACME"
    assert eng["awaiting_confirmation"] == 1
    _, graph = _get(base, "/api/graph")
    assert any(t["id"] == "t001" for t in graph["tasks"])


def test_approvals_then_approve(server):
    base, store = server
    code, queue = _get(base, "/api/approvals")
    assert code == 200 and len(queue) == 1 and queue[0]["id"] == "t001"

    code, res = _post(base, "/api/approve", {"task_id": "t001", "operator": "esmadi"})
    assert code == 200 and res["confirmed"] == "t001" and res["confirmed_by"] == "esmadi"
    # queue now empty and the store reflects the confirmation
    _, queue2 = _get(base, "/api/approvals")
    assert queue2 == []
    assert store.get_task("t001")["confirmed_by"] == "esmadi"


def test_approve_validation_and_conflict(server):
    base, _ = server
    code, _ = _post(base, "/api/approve", {"task_id": "t001"})  # missing operator
    assert code == 400
    # confirm once ok, twice -> 409 from the store's rule
    assert _post(base, "/api/approve", {"task_id": "t001", "operator": "x"})[0] == 200
    assert _post(base, "/api/approve", {"task_id": "t001", "operator": "x"})[0] == 409


def test_audit_verify_endpoint(server):
    base, _ = server
    _post(base, "/api/approve", {"task_id": "t001", "operator": "esmadi"})
    code, res = _get(base, "/api/audit/verify")
    assert code == 200 and res["ok"] is True and res["entries"] >= 4
