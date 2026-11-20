"""
rt — the engagement CLI. The agents and the operator share the graph through it.

    rt init --engagement ACME-2026 --objective "..." --scope scope.json
    rt scope new  --engagement ACME-2026 --allow 10.0.0.0/24 --allow app.acme.test
    rt scope sign --operator esmadi
    rt status | rt graph | rt frontier | rt queue
    rt finding "ssh open" -k service --target 10.0.0.5 -d port=22
    rt task --from f001 "exploit CVE-X" --tier exploit --target 10.0.0.5
    rt confirm t003 --operator esmadi      # operator approves a gated task
    rt report > report.md

Adapted from sapper-v2's CLI (MIT, (c) 2026 N1nEmAn; see /NOTICE).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import findings as findings_mod
from . import knowledge
from .scope import Scope, ScopeError
from .store import RTError, Store, frontier, awaiting_confirmation, is_open


def _store(args) -> Store:
    from .audit import open_audit
    dsn = getattr(args, "audit", None) or str(Path(args.store) / "audit.db")
    return Store(Path(args.store), audit=open_audit(dsn))


def _kv(pairs: list[str] | None) -> dict:
    out = {}
    for p in pairs or []:
        if "=" in p:
            k, v = p.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def cmd_init(args) -> int:
    scope_path = Path(args.scope)
    if not scope_path.exists():
        raise RTError(f"scope file {scope_path} not found — create it with `rt scope new` first")
    scope = Scope.load(scope_path)
    if not scope.verify():
        raise RTError("scope signature invalid or missing — sign it with `rt scope sign`")
    _store(args).init(
        engagement_id=args.engagement, objective=args.objective, scope_ref=str(scope_path),
    )
    print(f"initialized engagement {args.engagement} (scope signed by {scope.signed_by})")
    return 0


def cmd_keygen(args) -> int:
    import os
    from . import _ed25519
    seed = _ed25519.generate_seed()
    pub = _ed25519.public_key(seed)
    key_path = Path(f"{args.out}.key")
    pub_path = Path(f"{args.out}.pub")
    if key_path.exists() and not args.force:
        raise RTError(f"{key_path} exists — refusing to overwrite (use --force)")
    key_path.write_text(seed.hex() + "\n", encoding="utf-8")
    os.chmod(key_path, 0o600)
    pub_path.write_text(pub.hex() + "\n", encoding="utf-8")
    print(f"wrote private seed  {key_path} (mode 0600 — keep it secret)")
    print(f"wrote public key    {pub_path}")
    print(f"public key: {pub.hex()}")
    return 0


def cmd_scope(args) -> int:
    path = Path(args.file)
    if args.scope_cmd == "new":
        scope = Scope(
            engagement_id=args.engagement,
            allowed_cidrs=[a for a in (args.allow or []) if "/" in a or _looks_ip(a)],
            allowed_domains=[a for a in (args.allow or []) if not ("/" in a or _looks_ip(a))],
            excluded_cidrs=[e for e in (args.exclude or []) if "/" in e or _looks_ip(e)],
            excluded_domains=[e for e in (args.exclude or []) if not ("/" in e or _looks_ip(e))],
        )
        scope.save(path)
        print(f"wrote unsigned scope to {path} — review it, then `rt scope sign`")
    elif args.scope_cmd == "sign":
        key_path = Path(args.key)
        if not key_path.exists():
            raise RTError(f"signing key {key_path} not found — generate one with `rt keygen`")
        seed = key_path.read_text(encoding="utf-8").strip()
        scope = Scope.load(path)
        scope.sign(args.operator, seed)
        scope.save(path)
        print(f"scope signed by {args.operator} (ed25519)")
        print(f"  public key: {scope.public_key}")
        print(f"  provision this key in the policy-gate trust store (`-trust`) before use")
    elif args.scope_cmd == "check":
        scope = Scope.load(path)
        ok = scope.permits(args.target)
        print(f"{args.target}: {'IN SCOPE' if ok else 'OUT OF SCOPE'}")
        return 0 if ok else 2
    return 0


def _looks_ip(s: str) -> bool:
    return all(p.isdigit() for p in s.split(".")[:1]) and s[0].isdigit()


def cmd_status(args) -> int:
    s = _store(args); s.require()
    p = s.load_project()
    print(f"engagement : {p['engagement_id']}  ({p['status']})")
    print(f"objective  : {p['objective']}")
    print(f"findings   : {len(s.list_findings())}")
    tasks = s.list_tasks()
    print(f"tasks      : {len(tasks)} ({sum(1 for t in tasks if is_open(t))} open)")
    q = awaiting_confirmation(s)
    if q:
        print(f"\n⚠  {len(q)} task(s) awaiting operator confirmation (`rt queue`)")
    return 0


def cmd_graph(args) -> int:
    s = _store(args); s.require()
    from .prompts import _graph_yaml
    print(_graph_yaml(s))
    return 0


def cmd_frontier(args) -> int:
    s = _store(args); s.require()
    for t in frontier(s):
        print(f"{t['id']}  [{t['risk_tier']}]  {t.get('target') or '-'}  "
              f"{t.get('title') or t['description'][:60]}")
    return 0


def cmd_queue(args) -> int:
    s = _store(args); s.require()
    q = awaiting_confirmation(s)
    if not q:
        print("approval queue empty")
        return 0
    print("TASKS AWAITING OPERATOR CONFIRMATION:\n")
    for t in q:
        print(f"{t['id']}  [{t['risk_tier']}]  target={t.get('target')}")
        print(f"    {t['description']}")
        print(f"    confirm with: rt confirm {t['id']} --operator <you>\n")
    return 0


def cmd_finding(args) -> int:
    s = _store(args); s.require()
    f = s.add_finding(args.description, creator=args.worker, kind=args.kind,
                      data=_kv(args.data), target=args.target, title=args.title,
                      doc=args.doc, source_task=getattr(args, "from_task", None))
    print(f"recorded {f['id']} ({f['kind']})")
    return 0


def cmd_task(args) -> int:
    s = _store(args); s.require()
    t = s.add_task(args.from_ids, args.description, creator=args.worker,
                   risk_tier=args.tier, target=args.target, title=args.title, doc=args.doc)
    note = "  ⚠ NEEDS OPERATOR CONFIRMATION" if t["requires_confirmation"] else ""
    print(f"created {t['id']} [{t['risk_tier']}]{note}")
    return 0


def cmd_confirm(args) -> int:
    s = _store(args); s.require()
    t = s.confirm_task(args.task_id, operator=args.operator)
    print(f"{t['id']} confirmed by {t['confirmed_by']} — now claimable")
    return 0


def cmd_run(args) -> int:
    s = _store(args); s.require()
    from .engine import Engine
    p = s.load_project()
    scope = Scope.load(p["scope_ref"])
    if not scope.verify():
        raise RTError("engagement scope signature invalid — re-sign before running")
    engine = Engine(s, scope, model=args.model, timeout=args.timeout)
    history = engine.run(max_rounds=args.max_rounds)
    created = sum(len(r.created) for r in history)
    dispatched = sum(len(r.dispatched) for r in history)
    print(f"ran {len(history)} round(s): {created} task(s) created, "
          f"{dispatched} dispatched")
    pending = awaiting_confirmation(s)
    if pending:
        print(f"\n⚠  {len(pending)} task(s) awaiting operator confirmation — "
              f"`rt queue` to review, `rt confirm <id>` to approve, then `rt run` again")
    return 0


def cmd_report(args) -> int:
    s = _store(args); s.require()
    print(findings_mod.render_markdown(s))
    return 0


def cmd_serve(args) -> int:
    s = _store(args); s.require()
    from .serve import serve
    serve(s, host=args.host, port=args.port)
    return 0


def cmd_audit(args) -> int:
    from .audit import open_audit
    dsn = getattr(args, "audit", None) or str(Path(args.store) / "audit.db")
    audit = open_audit(dsn)
    if args.audit_cmd == "verify":
        ok, broken, reason = audit.verify()
        if ok:
            print(f"audit chain OK ({len(audit.entries())} entries)")
            return 0
        print(f"AUDIT CHAIN BROKEN at seq {broken}: {reason}", file=sys.stderr)
        return 2
    # log
    for e in audit.entries():
        print(f"{e['seq']:>4}  {e['ts']}  {e['actor']:<12}  {e['event']:<16}  "
              f"{e['data']}")
    return 0


def cmd_kb(args) -> int:
    hits = knowledge.search(args.query, tag=args.tag)
    for e in hits:
        print(f"{e['id']}  [{','.join(e.get('tags', []))}]  {e['title']}")
        print(f"    {e['description']}")
    if not hits:
        print("(no matching knowledge-base entries)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rt", description="RT agentic pentest orchestrator")
    p.add_argument("--store", default=".rt", help="engagement graph directory")
    p.add_argument("--audit", default=None,
                   help="audit log DSN: a sqlite path (default <store>/audit.db) "
                        "or a postgres:// URL")
    sub = p.add_subparsers(dest="cmd", required=True)

    kg = sub.add_parser("keygen", help="generate an operator Ed25519 signing key")
    kg.add_argument("--out", default="operator", help="output prefix (<out>.key, <out>.pub)")
    kg.add_argument("--force", action="store_true")
    kg.set_defaults(func=cmd_keygen)

    i = sub.add_parser("init"); i.add_argument("--engagement", required=True)
    i.add_argument("--objective", required=True); i.add_argument("--scope", required=True)
    i.set_defaults(func=cmd_init)

    sc = sub.add_parser("scope"); scs = sc.add_subparsers(dest="scope_cmd", required=True)
    scn = scs.add_parser("new"); scn.add_argument("--engagement", required=True)
    scn.add_argument("--allow", action="append"); scn.add_argument("--exclude", action="append")
    scn.add_argument("--file", default="scope.json")
    scsign = scs.add_parser("sign"); scsign.add_argument("--operator", required=True)
    scsign.add_argument("--key", required=True, help="operator Ed25519 seed file (`rt keygen`)")
    scsign.add_argument("--file", default="scope.json")
    scchk = scs.add_parser("check"); scchk.add_argument("target")
    scchk.add_argument("--file", default="scope.json")
    sc.set_defaults(func=cmd_scope)

    for name, fn in (("status", cmd_status), ("graph", cmd_graph),
                     ("frontier", cmd_frontier), ("queue", cmd_queue), ("report", cmd_report)):
        sp = sub.add_parser(name); sp.set_defaults(func=fn)

    f = sub.add_parser("finding"); f.add_argument("description")
    f.add_argument("-k", "--kind", default="note"); f.add_argument("--target")
    f.add_argument("-d", "--data", action="append"); f.add_argument("--title")
    f.add_argument("--doc"); f.add_argument("--from-task", dest="from_task")
    f.add_argument("--worker", default="operator"); f.set_defaults(func=cmd_finding)

    t = sub.add_parser("task"); t.add_argument("description")
    t.add_argument("--from", dest="from_ids", action="append", required=True)
    t.add_argument("--tier", default="recon"); t.add_argument("--target")
    t.add_argument("--title"); t.add_argument("--doc")
    t.add_argument("--worker", default="commander"); t.set_defaults(func=cmd_task)

    c = sub.add_parser("confirm"); c.add_argument("task_id")
    c.add_argument("--operator", required=True); c.set_defaults(func=cmd_confirm)

    r = sub.add_parser("run", help="drive the commander/executor loop")
    r.add_argument("--model", required=True, help="agent model (passed to RT_AGENT_BIN)")
    r.add_argument("--max-rounds", dest="max_rounds", type=int, default=20)
    r.add_argument("--timeout", type=int, default=900, help="per-agent timeout (s)")
    r.set_defaults(func=cmd_run)

    k = sub.add_parser("kb"); k.add_argument("query"); k.add_argument("-t", "--tag")
    k.set_defaults(func=cmd_kb)

    sv = sub.add_parser("serve", help="run the operator console API (single appliance)")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8070)
    sv.set_defaults(func=cmd_serve)

    a = sub.add_parser("audit", help="the hash-chained evidence trail")
    asub = a.add_subparsers(dest="audit_cmd", required=True)
    asub.add_parser("verify", help="walk the chain; report the first break")
    asub.add_parser("log", help="print the audit log")
    a.set_defaults(func=cmd_audit)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (RTError, ScopeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
