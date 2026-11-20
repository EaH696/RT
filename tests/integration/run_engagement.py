#!/usr/bin/env python3
"""
RT end-to-end functioning test.

Stands up the REAL stack — policy-gate + sandbox (with the egress proxy) as
compiled Go binaries, and a local "victim" web service — then drives a complete
engagement through the orchestrator:

    seed host  ->  recon (real curl via the sandbox+egress)  ->  finds an
    exposed /.git/config  ->  commander opens an exploit task  ->  it PAUSES at
    the operator gate  ->  operator confirms  ->  exploit dumps the file  ->
    report + tamper-evident audit log.

Also shows the egress proxy refusing an out-of-scope target.

The only stand-in is the LLM agent (no model CLI here): a scripted agent that
makes REAL tool calls through the real sandbox. Everything else is the actual
system. Run: python tests/integration/run_engagement.py
"""
import json
import re
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HERE = Path(__file__).resolve()
RT_ROOT = HERE.parents[2]
sys.path.insert(0, str(RT_ROOT / "orchestrator"))

from rt.store import Store, frontier, awaiting_confirmation      # noqa: E402
from rt.scope import Scope                                        # noqa: E402
from rt.engine import Engine                                      # noqa: E402
from rt.audit import open_audit                                   # noqa: E402
from rt.transport import GateClient, SandboxClient                # noqa: E402
from rt import findings as findings_mod                           # noqa: E402

GATE_ADDR, SBX_ADDR, EGRESS_ADDR, TARGET_PORT = 8700, 8710, 8720, 9000
TARGET = f"127.0.0.1:{TARGET_PORT}"  # host:port — scope checks the host, tool hits the port
BIN = RT_ROOT / "bin"


# --- the victim service: a web app leaking its .git/config ----------------- #
GIT_CONFIG = "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://github.com/acme/secret-app.git\n"

class Victim(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/.git/config"):
            body = GIT_CONFIG.encode()
            self.send_response(200); self.send_header("Server", "nginx/1.18.0")
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body)
            return
        body = b"<html><title>ACME Internal</title><body>login</body></html>"
        self.send_response(200); self.send_header("Server", "nginx/1.18.0")
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def wait_port(port, timeout=8):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.3):
                return True
        except OSError:
            time.sleep(0.15)
    raise RuntimeError(f"port {port} never came up")


def banner(msg):
    print(f"\n{'='*70}\n{msg}\n{'='*70}")


# --- scripted agent: makes REAL tool calls through the sandbox ------------- #
def make_agent(sandbox: SandboxClient):
    def probe(target, tier, confirmed, path=""):
        args = {"path": path} if path else {}
        return sandbox.run(tool="httpget", target=target, tier=tier,
                           confirmed=confirmed, args=args)

    def agent(prompt: str) -> dict:
        target = re.search(r"target=([^\s)]+)", prompt).group(1)
        tier = re.search(r"tier=(\w+)", prompt).group(1)
        confirmed = tier in ("exploit", "post", "destructive")

        if "dump" in prompt.lower() or ".git" in prompt.lower():
            # exploit task: pull the exposed file through the sandbox
            res = probe(target, tier, confirmed, path=".git/config")
            got = res.stdout or res.err
            data = {"kind": "loot", "title": "dumped /.git/config",
                    "description": f"retrieved /.git/config from {target}",
                    "data": {"host": target, "path": "/.git/config"},
                    "doc": got[:400]}
            return {"result": json.dumps({"accepted": True, "data": data})}

        # recon task: fingerprint root, then check for the .git leak
        root = probe(target, tier, confirmed)
        status = (root.stdout or root.err).splitlines()[0] if (root.stdout or root.err) else "no response"
        server = "unknown"
        for line in root.stdout.splitlines():
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
        git = probe(target, tier, confirmed, path=".git/config")
        git_status = git.stdout.splitlines()[0] if git.stdout else ""
        if "200" in git_status and "[core]" in git.stdout:
            data = {"kind": "vuln", "title": "exposed .git/config",
                    "description": f"{server}: /.git/config is world-readable (source disclosure)",
                    "data": {"host": target, "port": str(TARGET_PORT), "severity": "high",
                             "name": "exposed .git/config", "status": "confirmed"},
                    "doc": git.stdout.split("\r\n\r\n")[0][:200]}
        else:
            data = {"kind": "service", "title": f"http {server}",
                    "description": f"{status}; server={server}",
                    "data": {"host": target, "port": str(TARGET_PORT), "product": server}}
        return {"result": json.dumps({"accepted": True, "data": data})}

    return agent


def main() -> int:
    work = Path("/tmp/rt_e2e")
    import shutil
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    store_dir = work / ".rt"
    scope_path = work / "scope.json"
    audit_dsn = str(store_dir / "audit.sqlite")

    # victim service (in-process thread)
    httpd = HTTPServer(("127.0.0.1", TARGET_PORT), Victim)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    # signed scope: the whole loopback range is authorized for this engagement
    Scope(engagement_id="ACME-2026", allowed_cidrs=["127.0.0.0/8"]).sign("esmadi").save(scope_path)

    procs = []
    try:
        procs.append(subprocess.Popen(
            [str(BIN / "rt-policy-gate"), "-scope", str(scope_path), "-addr", f"127.0.0.1:{GATE_ADDR}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        procs.append(subprocess.Popen(
            [str(BIN / "rt-sandbox"), "-addr", f"127.0.0.1:{SBX_ADDR}",
             "-egress-addr", f"127.0.0.1:{EGRESS_ADDR}", "-gate", f"http://127.0.0.1:{GATE_ADDR}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        for p in (GATE_ADDR, SBX_ADDR, EGRESS_ADDR, TARGET_PORT):
            wait_port(p)

        gate = GateClient(f"http://127.0.0.1:{GATE_ADDR}")
        sandbox = SandboxClient(f"http://127.0.0.1:{SBX_ADDR}")
        store_dir.mkdir(parents=True, exist_ok=True)
        audit = open_audit(audit_dsn)

        banner("1. SET UP ENGAGEMENT (signed scope: 127.0.0.0/8)")
        store = Store(store_dir)
        store.init(engagement_id="ACME-2026", objective="find and prove web exposures",
                   scope_ref=str(scope_path))
        audit.record("operator", "engagement.init", engagement_id="ACME-2026")
        host = store.add_finding("web host up", creator="operator", kind="host", target=TARGET)
        store.add_task([host["id"]], "HTTP recon of the web service", creator="commander",
                       risk_tier="enum", target=TARGET)
        print(f"   seeded {host['id']} (host), opened recon task on 127.0.0.1")

        engine = Engine(store, make_agent(sandbox), gate=gate, audit=audit)

        banner("2. RECON — real curl through the sandbox + egress proxy")
        rep = engine.run()
        for f in store.list_findings():
            if f["id"] != "objective":
                print(f"   {f['id']} [{f['kind']}] {f.get('title')}")
        print(f"   -> {rep.concluded} task(s) concluded; {rep.stopped_reason}")

        banner("3. COMMANDER opens an EXPLOIT task from the vuln (gated)")
        vuln = next(f for f in store.list_findings() if f["kind"] == "vuln")
        ex = store.add_task([vuln["id"]], "dump the exposed /.git/config", creator="commander",
                            risk_tier="exploit", target=TARGET)
        audit.record("commander", "task.create", engagement_id="ACME-2026",
                     target=TARGET, task=ex["id"], tier="exploit")
        print(f"   created {ex['id']} [exploit] — requires_confirmation={ex['requires_confirmation']}")

        banner("4. LOOP PAUSES AT THE OPERATOR GATE")
        rep = engine.run()
        q = awaiting_confirmation(store)
        print(f"   engine stopped: {rep.stopped_reason}")
        print(f"   approval queue: {[t['id'] for t in q]}  (agent did NOT run the exploit)")

        banner("5. OPERATOR CONFIRMS — the human gate (audited)")
        store.confirm_task(ex["id"], operator="esmadi")
        audit.record("esmadi", "task.confirm", engagement_id="ACME-2026",
                     target=TARGET, task=ex["id"], tier="exploit")
        print(f"   {ex['id']} confirmed by esmadi")

        banner("6. EXPLOIT RESUMES — dumps the file through the sandbox")
        rep = engine.run()
        loot = next((f for f in store.list_findings() if f["kind"] == "loot"), None)
        print(f"   {rep.concluded} task concluded; loot: {loot and loot['title']}")
        if loot and loot.get("doc"):
            print("   --- retrieved content (first lines) ---")
            for line in loot["doc"].split("\r\n\r\n")[-1].splitlines()[:4]:
                print(f"     {line}")

        banner("7. OUT-OF-SCOPE EGRESS IS PHYSICALLY REFUSED")
        d = gate.check("10.9.9.9")
        print(f"   gate.check(10.9.9.9): allowed={d.allowed} ({d.reason})")
        oos = sandbox.run(tool="httpget", target="10.9.9.9", tier="recon", confirmed=False)
        print(f"   sandbox httpget 10.9.9.9 -> {oos.err or oos.stdout[:60]}")

        banner("8. CLIENT DELIVERABLES")
        print(findings_mod.render_markdown(store))
        ok, broken = audit.verify()
        print(f"\n   AUDIT CHAIN: {'VERIFIED ✓' if ok else f'BROKEN at {broken}'}  "
              f"({len(audit.entries())} entries)")
        print("   actions:", " -> ".join(e.action for e in audit.entries()))

        return 0 if ok else 1
    finally:
        for p in procs:
            p.terminate()
        httpd.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
