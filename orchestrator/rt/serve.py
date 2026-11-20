"""
rt.serve — the single-appliance operator console backend (stdlib HTTP).

A dependency-free JSON API over one engagement graph, so it runs on an
air-gapped appliance with nothing but Python. It exposes the engagement to the
operator UI and, critically, serves the **approval queue** for gated (exploit+)
tasks: the console lists what is awaiting confirmation and POSTs the operator's
approval, which is exactly `rt confirm` — and every approval is written to the
hash-chained audit log.

Endpoints:

    GET  /healthz            -> "ok"
    GET  /api/engagement     -> project (id, objective, scope_ref, status, counts)
    GET  /api/graph          -> {findings: [...], tasks: [...]}
    GET  /api/approvals      -> [ gated tasks awaiting confirmation ]
    POST /api/approve        -> {task_id, operator}  ->  confirm_task (+ audit)
    GET  /api/audit/verify   -> {ok, first_broken_seq, reason, entries}

This is the backend the Go `gateway/` fronts in production (auth, TLS,
multi-engagement). On its own it binds loopback by default — do NOT expose it
directly; put the gateway (or an authenticating reverse proxy) in front.

Safety: read endpoints never mutate. The only mutation is POST /api/approve,
which goes through store.confirm_task — so the store's own rules apply (only a
gated, unconcluded, not-yet-confirmed task can be approved, and the operator
must be named for the audit trail).
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .store import Store, awaiting_confirmation, RTError


def _project_summary(store: Store) -> dict:
    p = store.load_project()
    tasks = store.list_tasks()
    return {
        "engagement_id": p.get("engagement_id"),
        "objective": p.get("objective"),
        "scope_ref": p.get("scope_ref"),
        "status": p.get("status"),
        "findings": len(store.list_findings()),
        "tasks": len(tasks),
        "awaiting_confirmation": len(awaiting_confirmation(store)),
    }


def make_handler(store: Store):
    class Handler(BaseHTTPRequestHandler):
        server_version = "rt-serve/0.1"

        # -- helpers ------------------------------------------------------- #
        def _send(self, code: int, payload) -> None:
            body = (payload if isinstance(payload, (bytes, bytearray))
                    else json.dumps(payload).encode("utf-8"))
            self.send_response(code)
            ctype = "text/plain" if isinstance(payload, (bytes, bytearray)) else "application/json"
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # quiet by default; the gateway logs
            pass

        # -- routes -------------------------------------------------------- #
        def do_GET(self):
            try:
                if self.path == "/healthz":
                    return self._send(200, b"ok")
                if self.path == "/api/engagement":
                    return self._send(200, _project_summary(store))
                if self.path == "/api/graph":
                    return self._send(200, {"findings": store.list_findings(),
                                            "tasks": store.list_tasks()})
                if self.path == "/api/approvals":
                    return self._send(200, awaiting_confirmation(store))
                if self.path == "/api/audit/verify":
                    if store.audit is None:
                        return self._send(200, {"ok": None, "reason": "no audit sink configured"})
                    ok, broken, reason = store.audit.verify()
                    return self._send(200, {"ok": ok, "first_broken_seq": broken,
                                            "reason": reason,
                                            "entries": len(store.audit.entries())})
                return self._send(404, {"error": "not found"})
            except Exception as e:  # never leak a stack trace to the console
                return self._send(500, {"error": str(e)})

        def do_POST(self):
            if self.path != "/api/approve":
                return self._send(404, {"error": "not found"})
            try:
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length) if length else b"{}"
                body = json.loads(raw or b"{}")
            except (ValueError, json.JSONDecodeError):
                return self._send(400, {"error": "invalid JSON body"})
            task_id = str(body.get("task_id", "")).strip()
            operator = str(body.get("operator", "")).strip()
            if not task_id or not operator:
                return self._send(400, {"error": "task_id and operator are required"})
            try:
                task = store.confirm_task(task_id, operator=operator)
            except RTError as e:
                return self._send(409, {"error": str(e)})
            return self._send(200, {"confirmed": task["id"],
                                    "confirmed_by": task["confirmed_by"]})

    return Handler


def serve(store: Store, host: str = "127.0.0.1", port: int = 8070) -> None:
    store.require()
    httpd = ThreadingHTTPServer((host, port), make_handler(store))
    print(f"rt serve: console API on http://{host}:{port}  "
          f"(engagement {store.load_project().get('engagement_id')})")
    print("  put the gateway or an authenticating proxy in front — do not expose directly")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nrt serve: shutting down")
        httpd.shutdown()
