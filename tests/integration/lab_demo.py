#!/usr/bin/env python3
"""
RT lab demo — a full engagement against a multi-vuln local target.

Like run_engagement.py but the target exposes several realistic issues, so the
report shows varied findings across severities — a better showcase than the
single-finding e2e. Everything is real RT (policy-gate, sandbox, egress proxy,
durable loop, operator gate, audit); only the LLM agent is scripted, and it
makes REAL curl tool calls through the sandbox.

Run: python tests/integration/lab_demo.py
"""
import json
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

RT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RT_ROOT / "orchestrator"))

from rt.store import Store, awaiting_confirmation          # noqa: E402
from rt.scope import Scope                                 # noqa: E402
from rt.engine import Engine                               # noqa: E402
from rt.audit import open_audit                            # noqa: E402
from rt.transport import GateClient, SandboxClient         # noqa: E402
from rt import findings as findings_mod                    # noqa: E402

GATE, SBX, EGRESS, PORT = 8700, 8710, 8720, 9000
TARGET = f"127.0.0.1:{PORT}"
BIN = RT_ROOT / "bin"

# --- a deliberately vulnerable "lab" web app ------------------------------- #
PAGES = {
    "/.env": ("text/plain",
              "APP_ENV=production\nDB_HOST=10.0.0.5\nDB_USER=root\nDB_PASSWORD=S3cr3tP@ss!\nJWT_SECRET=hunter2hunter2\n"),
    "/.git/config": ("text/plain",
                      "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://github.com/acme/secret-app.git\n"),
    "/backup.sql": ("text/plain",
                    "-- MySQL dump\nINSERT INTO users VALUES (1,'admin','$2y$10$abcd...');\n"),
    "/robots.txt": ("text/plain", "User-agent: *\nDisallow: /admin\nDisallow: /backup.sql\n"),
    "/admin": ("text/html", "<html><title>Admin</title><form>login</form></html>"),
}

class Lab(BaseHTTPRequestHandler):
    server_version = "nginx/1.18.0"
    def _send(self, code, ctype, body):
        b = body.encode()
        self.send_response(code)
        self.send_header("Server", "nginx/1.18.0")
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/search":  # reflected XSS
            q = ""
            if "?" in self.path:
                q = self.path.split("q=", 1)[1] if "q=" in self.path else ""
            from urllib.parse import unquote
            self._send(200, "text/html", f"<html>results for {unquote(q)}</html>")
            return
        if path in PAGES:
            ctype, body = PAGES[path]
            self._send(200, ctype, body)
            return
        if path == "/":
            self._send(200, "text/html", "<html><title>ACME App</title><body>home</body></html>")
            return
        self._send(404, "text/html", "<html>not found</html>")
    def log_message(self, *_):
        pass


def wait_port(port, timeout=8):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.3):
                return
        except OSError:
            time.sleep(0.15)
    raise RuntimeError(f"port {port} never came up")


def banner(m): print(f"\n{'='*72}\n{m}\n{'='*72}")


# --- scripted agent: real tool calls, classifies what it finds ------------- #
def make_agent(sandbox):
    def probe(target, path, tier, confirmed):
        return sandbox.run(tool="httpget", target=target, tier=tier,
                           confirmed=confirmed, args={"path": path} if path else {})

    def agent(prompt):
        target = re.search(r"target=([^\s)]+)", prompt).group(1)
        tier = re.search(r"tier=(\w+)", prompt).group(1)
        confirmed = tier in ("exploit", "post", "destructive")
        pm = re.search(r"PATH=(\S+)", prompt)
        path = pm.group(1) if pm else ""

        # exploit task: dump the secret file
        if "dump" in prompt.lower():
            r = probe(target, path, tier, confirmed)
            body = r.stdout.split("\r\n\r\n", 1)[-1] if r.stdout else r.err
            return {"result": json.dumps({"accepted": True, "data": {
                "kind": "loot", "title": f"dumped {path}",
                "description": f"retrieved {path} from {target}",
                "data": {"host": target, "path": path}, "doc": body[:300]}})}

        r = probe(target, path, tier, confirmed)
        out = r.stdout or r.err
        status = out.splitlines()[0] if out else "no response"
        body = out.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in out else ""
        is200 = "200" in status

        def vuln(title, sev, name, desc):
            return {"result": json.dumps({"accepted": True, "data": {
                "kind": "vuln", "title": title,
                "description": desc,
                "data": {"host": target, "severity": sev, "name": name, "status": "confirmed"},
                "doc": status}})}

        if path == "/.env" and is200 and "PASSWORD" in body:
            return vuln("exposed .env with DB credentials", "critical", "secrets exposure",
                        "Application .env is world-readable, leaking DB and JWT secrets")
        if path == "/.git/config" and is200 and "[core]" in body:
            return vuln("exposed .git/config", "high", "source disclosure",
                        "/.git/config is world-readable (source code disclosure)")
        if path == "/backup.sql" and is200 and "INSERT INTO" in body:
            return vuln("exposed database backup", "high", "data exposure",
                        "/backup.sql is downloadable, leaking user table + password hashes")
        if path == "/admin" and is200:
            return vuln("admin login exposed", "medium", "access control",
                        "/admin login is reachable without network restriction")
        if path.startswith("/search") and "<script>" in body.lower():
            return vuln("reflected XSS in search", "medium", "xss",
                        "q parameter reflected unencoded in the response")
        # nothing notable
        return {"result": json.dumps({"accepted": True, "data": {
            "kind": "note", "title": f"probed {path or '/'}",
            "description": f"{status}; nothing notable", "data": {"host": target}}})}
    return agent


def main():
    work = Path("/tmp/rt_lab"); shutil.rmtree(work, ignore_errors=True); work.mkdir(parents=True)
    store_dir = work / ".rt"; scope_path = work / "scope.json"

    httpd = HTTPServer(("127.0.0.1", PORT), Lab)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    Scope(engagement_id="LAB-2026", allowed_cidrs=["127.0.0.0/8"]).sign("esmadi").save(scope_path)

    procs = []
    try:
        procs.append(subprocess.Popen([str(BIN/"rt-policy-gate"), "-scope", str(scope_path), "-addr", f"127.0.0.1:{GATE}"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        procs.append(subprocess.Popen([str(BIN/"rt-sandbox"), "-addr", f"127.0.0.1:{SBX}", "-egress-addr", f"127.0.0.1:{EGRESS}", "-gate", f"http://127.0.0.1:{GATE}"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        for p in (GATE, SBX, EGRESS, PORT):
            wait_port(p)

        gate = GateClient(f"http://127.0.0.1:{GATE}")
        sandbox = SandboxClient(f"http://127.0.0.1:{SBX}")
        store_dir.mkdir(parents=True, exist_ok=True)
        audit = open_audit(str(store_dir / "audit.sqlite"))

        banner("1. ENGAGEMENT SETUP (scope 127.0.0.0/8, signed)")
        store = Store(store_dir)
        store.init(engagement_id="LAB-2026", objective="assess the ACME web app", scope_ref=str(scope_path))
        audit.record("operator", "engagement.init", engagement_id="LAB-2026")
        host = store.add_finding("web app host", creator="operator", kind="host", target=TARGET)
        checks = ["/.git/config", "/.env", "/backup.sql", "/admin", "/search?q=<script>alert(1)</script>"]
        for pth in checks:
            store.add_task([host["id"]], f"probe PATH={pth} for exposure", creator="commander",
                           risk_tier="enum", target=TARGET, title=f"probe {pth}")
        print(f"   seeded host + {len(checks)} recon tasks")

        engine = Engine(store, make_agent(sandbox), gate=gate, audit=audit)

        banner("2. RECON — real curl probes through the sandbox + egress proxy")
        engine.run()
        for f in store.list_findings():
            if f["kind"] == "vuln":
                print(f"   [{(f['data'].get('severity','?')).upper():8}] {f['title']}")

        banner("3. COMMANDER escalates the CRITICAL finding (gated exploit)")
        crit = next(f for f in store.list_findings()
                    if f["kind"] == "vuln" and f["data"].get("severity") == "critical")
        ex = store.add_task([crit["id"]], "dump PATH=/.env (exfil secrets, proof)", creator="commander",
                            risk_tier="exploit", target=TARGET, title="dump /.env")
        audit.record("commander", "task.create", engagement_id="LAB-2026", target=TARGET, task=ex["id"], tier="exploit")
        print(f"   created {ex['id']} [exploit] from {crit['id']} — needs confirmation")

        banner("4. GATE: loop pauses for operator approval")
        engine.run()
        print(f"   awaiting confirmation: {[t['id'] for t in awaiting_confirmation(store)]}")

        banner("5. OPERATOR CONFIRMS (audited human approval)")
        store.confirm_task(ex["id"], operator="esmadi")
        audit.record("esmadi", "task.confirm", engagement_id="LAB-2026", target=TARGET, task=ex["id"], tier="exploit")
        print("   t00x confirmed by esmadi")

        banner("6. EXPLOIT RESUMES — dumps /.env through the sandbox")
        engine.run()
        loot = next((f for f in store.list_findings() if f["kind"] == "loot"), None)
        if loot:
            print(f"   {loot['title']}:")
            for line in loot["doc"].splitlines()[:5]:
                print(f"     {line}")

        banner("7. OUT-OF-SCOPE EGRESS REFUSED")
        oos = sandbox.run(tool="httpget", target="10.9.9.9", tier="recon", confirmed=False)
        print(f"   httpget 10.9.9.9 -> {oos.err}")

        banner("8. REPORT + AUDIT")
        print(findings_mod.render_markdown(store))
        ok, broken = audit.verify()
        print(f"\n   AUDIT CHAIN: {'VERIFIED' if ok else f'BROKEN@{broken}'} ({len(audit.entries())} entries)")
        return 0 if ok else 1
    finally:
        for p in procs:
            p.terminate()
        httpd.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
