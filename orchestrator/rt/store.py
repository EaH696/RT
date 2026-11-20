"""
rt.store — the engagement graph: the shared memory every RT agent reads and writes.

Ported and adapted from sapper-v2's fact/intent graph (MIT, (c) 2026 N1nEmAn;
see /NOTICE). RT renames the two node types to its own domain:

    Finding  (was "fact")   — a confirmed piece of knowledge about the target:
                              a host, service, vuln, credential, or loot item.
                              This is the attack graph.
    Task     (was "intent") — a planned unit of offensive work. A hyper-edge:
                              it consumes one or more Findings (`from`) and,
                              when concluded, produces a new Finding (`to`).

Two RT-specific rules layered on top of the ported mechanics:

  * Every Task carries a `risk_tier` (recon|enum|analysis|exploit|post|destructive).
    Anything at `exploit` or above sets `requires_confirmation=True` and cannot
    be claimed by a worker until a human operator confirms it. This is RT's
    semi-autonomous, gated-exploitation model — enforced in the store, not in a
    prompt.
  * Findings and Tasks carry the target they concern; the orchestrator checks
    every target against the engagement scope (see rt.scope) before dispatch.
    The store is defense-in-depth memory, not the enforcement point — the Go
    policy-gate is — but it refuses to persist work with no target on an
    exploit-tier task.

Storage: one JSON file per node under <root>/findings and <root>/tasks, guarded
by an fcntl lock, written atomically. No database required on the appliance.
"""
from __future__ import annotations

import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

OBJECTIVE_ID = "objective"
LOCK_NAME = ".rt.lock"
_UNSET = object()

RISK_TIERS = ("recon", "enum", "analysis", "exploit", "post", "destructive")
GATED_TIERS = ("exploit", "post", "destructive")  # require operator confirmation

FINDING_KINDS = ("host", "service", "vuln", "cred", "loot", "note")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class RTError(Exception):
    """User-facing error; message is printed, exit code 1."""


def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _read_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


class Store:
    """Filesystem-backed engagement graph. One file per node, fcntl-locked."""

    def __init__(self, root: Path, audit=None):
        self.root = Path(root)
        self.findings_dir = self.root / "findings"
        self.tasks_dir = self.root / "tasks"
        self.project_file = self.root / "engagement.json"
        self.lock_file = self.root / LOCK_NAME
        # Optional rt.audit.AuditStore. When set, every graph mutation is
        # appended to the hash-chained evidence trail. None = no logging
        # (unit tests, ephemeral use).
        self.audit = audit

    def _emit(self, event: str, *, actor: str, data: dict) -> None:
        if self.audit is None:
            return
        try:
            self.audit.append(event, actor=actor, data=data)
        except Exception:
            # The audit log must never crash the engagement loop. A broken sink
            # is surfaced by `rt audit verify`, not by a failed finding write.
            pass

    # -- existence ---------------------------------------------------------- #
    def exists(self) -> bool:
        return self.project_file.exists()

    def require(self) -> None:
        if not self.exists():
            raise RTError(
                f"no engagement graph here ({self.root}). run `rt init` first, "
                f"or pass --store <path>."
            )

    # -- locking ------------------------------------------------------------ #
    @contextmanager
    def locked(self):
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)
        fh = open(self.lock_file, "a+")
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            fh.close()

    # -- init --------------------------------------------------------------- #
    def init(self, *, engagement_id: str, objective: str, scope_ref: str) -> None:
        objective = objective.strip()
        if not objective:
            raise RTError("objective cannot be empty")
        with self.locked():
            if self.exists():
                raise RTError(f"engagement graph already exists at {self.root}")
            for d in (self.root, self.findings_dir, self.tasks_dir):
                d.mkdir(parents=True, exist_ok=True)
            project = {
                "id": "engagement",
                "engagement_id": engagement_id.strip(),
                "objective": objective,
                "scope_ref": scope_ref.strip(),  # path to signed scope (rt.scope)
                "status": "active",
                "created_at": now_iso(),
                "counters": {"finding": 0, "task": 0},
            }
            _atomic_write_json(self.project_file, project)
            objective_finding = {
                "id": OBJECTIVE_ID,
                "title": "objective",
                "description": objective,
                "kind": "note",
                "data": {},
                "target": None,
                "created_at": now_iso(),
                "creator": "system",
                "source_task": None,
            }
            _atomic_write_json(self.findings_dir / f"{OBJECTIVE_ID}.json", objective_finding)
        self._emit("engagement.init", actor="operator",
                   data={"engagement_id": engagement_id.strip(), "objective": objective})

    # -- project ------------------------------------------------------------ #
    def load_project(self) -> dict:
        project = _read_json(self.project_file)
        project.setdefault("counters", {"finding": 0, "task": 0})
        return project

    def save_project(self, project: dict) -> None:
        _atomic_write_json(self.project_file, project)

    def _next_id(self, kind: str, prefix: str) -> str:
        """Must be called inside locked(). Counter is a hint; skip occupied ids."""
        project = self.load_project()
        n = project["counters"].get(kind, 0) + 1
        directory = {"finding": self.findings_dir, "task": self.tasks_dir}[kind]
        while (directory / f"{prefix}{n:03d}.json").exists():
            n += 1
        project["counters"][kind] = n
        self.save_project(project)
        return f"{prefix}{n:03d}"

    # -- findings ----------------------------------------------------------- #
    def list_findings(self) -> list[dict]:
        if not self.findings_dir.exists():
            return []
        return sorted(
            (_read_json(p) for p in self.findings_dir.glob("*.json")),
            key=lambda f: f["id"],
        )

    def get_finding(self, fid: str) -> dict:
        p = self.findings_dir / f"{fid}.json"
        if not p.exists():
            raise RTError(f"finding {fid} not found")
        return _read_json(p)

    def add_finding(
        self,
        description: str,
        creator: str,
        *,
        kind: str = "note",
        data: dict | None = None,
        target: str | None = None,
        title: str | None = None,
        doc: str | None = None,
        source_task: str | None = None,
    ) -> dict:
        if not description.strip():
            raise RTError("finding description cannot be empty")
        if kind not in FINDING_KINDS:
            raise RTError(f"finding kind must be one of {FINDING_KINDS}")
        with self.locked():
            source = None
            if source_task is not None:
                source = self.get_task(source_task)
                if source["to"] is not None:
                    raise RTError(f"task {source_task} already concluded")
            fid = self._next_id("finding", "f")
            finding = {
                "id": fid,
                "title": (title.strip() if title else None),
                "description": description.strip(),
                "doc": (doc.strip() if doc else None),
                "kind": kind,
                "data": data or {},
                "target": target,
                "created_at": now_iso(),
                "creator": creator,
                "source_task": source_task,
            }
            _atomic_write_json(self.findings_dir / f"{fid}.json", finding)
            if source is not None:
                source["to"] = fid
                source["status"] = "done"
                source["concluded_at"] = now_iso()
                source["worker"] = creator or source.get("worker")
                self.save_task(source)
        self._emit("finding.add", actor=creator or "unknown",
                   data={"id": fid, "kind": kind, "target": target})
        if source_task is not None:
            self._emit("task.conclude", actor=creator or "unknown",
                       data={"task": source_task, "to": fid})
        return finding

    # -- tasks -------------------------------------------------------------- #
    def list_tasks(self) -> list[dict]:
        if not self.tasks_dir.exists():
            return []
        return sorted(
            (_read_json(p) for p in self.tasks_dir.glob("*.json")),
            key=lambda t: t["id"],
        )

    def get_task(self, tid: str) -> dict:
        p = self.tasks_dir / f"{tid}.json"
        if not p.exists():
            raise RTError(f"task {tid} not found")
        return _read_json(p)

    def add_task(
        self,
        from_ids: list[str],
        description: str,
        creator: str,
        *,
        risk_tier: str = "recon",
        target: str | None = None,
        title: str | None = None,
        doc: str | None = None,
    ) -> dict:
        if not description.strip():
            raise RTError("task description cannot be empty")
        if risk_tier not in RISK_TIERS:
            raise RTError(f"risk_tier must be one of {RISK_TIERS}")
        from_ids = list(dict.fromkeys(from_ids))
        if not from_ids:
            raise RTError("task must consume at least one finding (`from`)")
        # Gated tiers must name the target they act on — so the policy-gate and
        # the operator both know exactly what will be touched before approval.
        if risk_tier in GATED_TIERS and not (target and target.strip()):
            raise RTError(f"{risk_tier}-tier task must specify a --target")
        with self.locked():
            existing = {f["id"] for f in self.list_findings()}
            for fid in from_ids:
                if fid not in existing:
                    raise RTError(f"from finding {fid} does not exist")
            requires_confirmation = risk_tier in GATED_TIERS
            tid = self._next_id("task", "t")
            task = {
                "id": tid,
                "title": (title.strip() if title else None),
                "from": from_ids,
                "to": None,
                "description": description.strip(),
                "doc": (doc.strip() if doc else None),
                "risk_tier": risk_tier,
                "target": target,
                "creator": creator,
                "status": "open",
                "worker": None,
                "requires_confirmation": requires_confirmation,
                "confirmed_at": None,
                "confirmed_by": None,
                "created_at": now_iso(),
                "concluded_at": None,
            }
            _atomic_write_json(self.tasks_dir / f"{tid}.json", task)
        self._emit("task.create", actor=creator or "commander",
                   data={"id": tid, "tier": risk_tier, "target": target,
                         "requires_confirmation": requires_confirmation})
        return task

    def save_task(self, task: dict) -> None:
        _atomic_write_json(self.tasks_dir / f"{task['id']}.json", task)

    def claim_task(self, tid: str, worker: str) -> dict:
        with self.locked():
            task = self.get_task(tid)
            if task["to"] is not None:
                raise RTError(f"task {tid} already concluded")
            if task.get("requires_confirmation") and not task.get("confirmed_at"):
                self._emit("task.blocked", actor=worker,
                           data={"id": tid, "tier": task["risk_tier"],
                                 "reason": "unconfirmed gated task"})
                raise RTError(
                    f"task {tid} is {task['risk_tier']}-tier and needs operator "
                    f"confirmation before it can be claimed (`rt confirm {tid}`)"
                )
            owner = task.get("worker")
            if owner and owner != worker:
                raise RTError(f"task {tid} already claimed by {owner}")
            task["worker"] = worker
            task["status"] = "claimed"
            self.save_task(task)
        self._emit("task.dispatch", actor=worker,
                   data={"id": tid, "tier": task.get("risk_tier"), "target": task.get("target")})
        return task

    def confirm_task(self, tid: str, operator: str) -> dict:
        """Operator approval for a gated (exploit+) task. The HITL checkpoint."""
        with self.locked():
            task = self.get_task(tid)
            if task["to"] is not None:
                raise RTError(f"task {tid} already concluded")
            if not task["requires_confirmation"]:
                raise RTError(f"task {tid} ({task['risk_tier']}) needs no confirmation")
            if task["confirmed_at"]:
                raise RTError(f"task {tid} already confirmed by {task.get('confirmed_by')}")
            if not operator.strip():
                raise RTError("confirming operator must be identified (audit trail)")
            task["confirmed_at"] = now_iso()
            task["confirmed_by"] = operator.strip()
            self.save_task(task)
        self._emit("task.confirm", actor=operator.strip(),
                   data={"id": tid, "tier": task.get("risk_tier"), "target": task.get("target")})
        return task


# --------------------------------------------------------------------------- #
# graph helpers
# --------------------------------------------------------------------------- #
def is_open(task: dict) -> bool:
    return task["to"] is None


def is_ready(task: dict, finding_ids: set[str] | None = None) -> bool:
    """Can this task be worked right now?"""
    if not is_open(task):
        return False
    if finding_ids is not None and not set(task.get("from", ())).issubset(finding_ids):
        return False
    if task.get("requires_confirmation") and not task.get("confirmed_at"):
        return False
    return True


def frontier(store: Store) -> list[dict]:
    """Tasks that are ready to dispatch, claimed ones first."""
    finding_ids = {f["id"] for f in store.list_findings()}
    ready = [t for t in store.list_tasks() if is_ready(t, finding_ids)]
    ready.sort(key=lambda t: (t["status"] != "claimed", t["created_at"]))
    return ready


def awaiting_confirmation(store: Store) -> list[dict]:
    """Gated tasks sitting in the operator's approval queue."""
    return [
        t for t in store.list_tasks()
        if is_open(t) and t.get("requires_confirmation") and not t.get("confirmed_at")
    ]
