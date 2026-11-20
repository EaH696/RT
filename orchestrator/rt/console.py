"""
rt.console — the operator console server.

A stdlib HTTP server (no dependencies, runs on the air-gapped appliance) that
serves the operator UI and a small JSON API over the live engagement:

    GET  /                -> the console page (templates/console.html)
    GET  /api/state       -> engagement, findings, tasks, the approval queue
    POST /api/confirm     -> operator confirms a gated (exploit+) task
    GET  /api/audit       -> audit entries + chain-integrity status

All engagement logic stays in Python (store, audit, scope) — one source of
truth. The Go `gateway/` is the production edge (auth, TLS, multi-engagement);
on a single appliance the operator opens this directly. It binds to loopback by
default and has no auth, so keep it behind the gateway / an SSH tunnel in
production.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .store import Store, is_open, awaiting_confirmation
from .audit import open_audit

TEMPLATE = Path(__file__).parent / "templates" / "console.html"


def build_state(store: Store) -> dict:
    project = store.load_project()
    findings = [f for f in store.list_findings() if f["id"] != "objective"]
    tasks = store.list_tasks()
    queue = awaiting_confirmation(store)
    return {
        "engagement": {
            "id": project.get("engagement_id"),
            "objective": project.get("objective"),
            "status": project.get("status"),
            "scope_ref": project.get("scope_ref"),
        },
        "counts": {
            "findings": len(findings),
            "vulns": sum(1 for f in findings if f["kind"] == "vuln"),
            "open_tasks": sum(1 for t in tasks if is_open(t)),
            "queue": len(queue),
        },
        "findings": [
            {"id": f["id"], "kind": f["kind"], "title": f.get("title") or f["description"][:60],
             "target": f.get("target"), "severity": (f.get("data") or {}).get("severity")}
            for f in findings
        ],
        "tasks": [
            {"id": t["id"], "tier": t.get("risk_tier"), "target": t.get("target"),
             "title": t.get("title") or t["description"][:60], "status": t["status"],
             "open": is_open(t), "requires_confirmation": t.get("requires_confirmation"),
             "confirmed_by": t.get("confirmed_by")}
            for t in tasks
        ],
        "queue": [
            {"id": t["id"], "tier": t.get("risk_tier"), "target": t.get("target"),
             "title": t.get("title") or t["description"][:80], "description": t["description"]}
            for t in queue
        ],
    }


def _audit_summary(audit) -> dict:
    ok, broken = audit.verify()
    return {
        "verified": ok, "broken_at": broken,
        "entries": [
            {"seq": e.seq, "ts": e.ts, "actor": e.actor, "action": e.action,
             "target": e.target, "details": e.details}
            for e in audit.entries()
        ],
    }


class _Handler(BaseHTTPRequestHandler):
    store: Store = None       # set by serve()
    audit_dsn: str = None

    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            html = TEMPLATE.read_text(encoding="utf-8").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return
        if self.path == "/api/state":
            self._json(200, build_state(self.store))
            return
        if self.path == "/api/audit":
            audit = open_audit(self.audit_dsn)
            try:
                self._json(200, _audit_summary(audit))
            finally:
                audit.close()
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/api/confirm":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
            task_id = body["task_id"]
            operator = (body.get("operator") or "").strip()
            if not operator:
                raise ValueError("operator required")
            task = self.store.confirm_task(task_id, operator=operator)
            audit = open_audit(self.audit_dsn)
            try:
                audit.record(operator, "task.confirm",
                             engagement_id=self.store.load_project().get("engagement_id", ""),
                             target=task.get("target") or "", task=task["id"], tier=task["risk_tier"])
            finally:
                audit.close()
            self._json(200, {"ok": True, "task": task["id"], "confirmed_by": operator})
        except Exception as exc:
            self._json(400, {"ok": False, "error": str(exc)})

    def log_message(self, *_):
        pass


def serve(store_dir: str, audit_dsn: str | None = None,
          host: str = "127.0.0.1", port: int = 8900):
    store = Store(Path(store_dir))
    store.require()
    _Handler.store = store
    _Handler.audit_dsn = audit_dsn or str(Path(store_dir) / "audit.sqlite")
    httpd = ThreadingHTTPServer((host, port), _Handler)
    return httpd
