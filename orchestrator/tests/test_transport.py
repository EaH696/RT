"""Transport + Engine↔gate wiring, exercised against a stdlib stub HTTP gate."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from rt.store import Store
from rt.engine import Engine
from rt.transport import GateClient, Decision


class _GateHandler(BaseHTTPRequestHandler):
    # allows only 10.0.0.5
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        target = body.get("target", "")
        allowed = target == "10.0.0.5"
        payload = json.dumps({"target": target, "allowed": allowed, "reason": "stub"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):  # quiet
        pass


@pytest.fixture
def gate_url():
    srv = HTTPServer(("127.0.0.1", 0), _GateHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_gate_client_allow_deny(gate_url):
    g = GateClient(gate_url)
    assert g.check("10.0.0.5").allowed is True
    d = g.check("10.9.9.9")
    assert d.allowed is False and d.reason == "stub"


def test_engine_blocks_out_of_scope_task(tmp_path, gate_url):
    s = Store(tmp_path / ".rt")
    s.init(engagement_id="T", objective="x", scope_ref="scope.json")
    f = s.add_finding("host", creator="seed", kind="host", target="10.9.9.9")
    t = s.add_task([f["id"]], "scan out-of-scope host", creator="cmd",
                   risk_tier="enum", target="10.9.9.9")

    called = {"agent": False}

    def agent(_prompt):
        called["agent"] = True
        return {"result": json.dumps({"accepted": True, "data": {"kind": "note",
                "title": "x", "description": "y"}})}

    report = Engine(s, agent, gate=GateClient(gate_url)).run()
    # the gate denied the target, so the agent was never invoked and the task
    # was concluded as an out-of-scope note
    assert called["agent"] is False
    assert report.steps[0].status == "blocked"
    assert s.get_task(t["id"])["to"] is not None
    assert any(x.get("title") == "out of scope" for x in s.list_findings())
