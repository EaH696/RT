"""
rt.audit — the tamper-evident engagement audit log.

Every action that matters in a pentest engagement — the operator approving an
exploit, an agent dispatching a tool, the policy-gate denying a target — is
appended here as an immutable, hash-chained record. Each entry carries the hash
of the previous one, so removing, reordering, or altering any entry breaks the
chain and `verify()` pinpoints where. The chain needs no secret key: a client or
auditor can verify it independently. This is RT's evidence trail and liability
shield.

Persistence is pluggable behind AuditStore:
  * SQLiteAuditStore — stdlib (sqlite3). The default; also the appliance's
    embedded mode and what the tests use.
  * PostgresAuditStore — production persistence via psycopg (same schema/SQL).
    Not exercised in environments without psycopg + a Postgres server; selected
    by a postgres:// DSN.

open_audit(dsn) picks the backend from the DSN.
"""
from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

GENESIS = "0" * 64


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _entry_hash(seq: int, ts: str, actor: str, action: str,
                engagement_id: str, target: str, details: dict, prev_hash: str) -> str:
    body = json.dumps(
        {"seq": seq, "ts": ts, "actor": actor, "action": action,
         "engagement_id": engagement_id, "target": target, "details": details},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    return hashlib.sha256((prev_hash + body).encode()).hexdigest()


@dataclass
class AuditEntry:
    seq: int
    ts: str
    actor: str
    action: str
    engagement_id: str
    target: str
    details: dict
    prev_hash: str
    entry_hash: str

    def recompute(self) -> str:
        return _entry_hash(self.seq, self.ts, self.actor, self.action,
                           self.engagement_id, self.target, self.details, self.prev_hash)


# --------------------------------------------------------------------------- #
# storage backends
# --------------------------------------------------------------------------- #
class AuditStore(ABC):
    @abstractmethod
    def append_row(self, row: dict) -> None: ...
    @abstractmethod
    def last_row(self) -> dict | None: ...
    @abstractmethod
    def iter_rows(self): ...
    def close(self) -> None: ...


_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY,
  ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  engagement_id TEXT NOT NULL, target TEXT NOT NULL,
  details TEXT NOT NULL, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL
);
"""


class SQLiteAuditStore(AuditStore):
    def __init__(self, path: str):
        import sqlite3
        self._conn = sqlite3.connect(path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(_SQLITE_SCHEMA)
        self._conn.commit()

    def append_row(self, row: dict) -> None:
        self._conn.execute(
            "INSERT INTO audit (seq, ts, actor, action, engagement_id, target, "
            "details, prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?,?,?)",
            (row["seq"], row["ts"], row["actor"], row["action"], row["engagement_id"],
             row["target"], json.dumps(row["details"], sort_keys=True, ensure_ascii=False),
             row["prev_hash"], row["entry_hash"]),
        )
        self._conn.commit()

    def last_row(self) -> dict | None:
        cur = self._conn.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT 1")
        r = cur.fetchone()
        return _row_to_dict(r) if r else None

    def iter_rows(self):
        for r in self._conn.execute("SELECT * FROM audit ORDER BY seq ASC"):
            yield _row_to_dict(r)

    def close(self) -> None:
        self._conn.close()


def _row_to_dict(r) -> dict:
    d = dict(r)
    d["details"] = json.loads(d["details"])
    return d


class PostgresAuditStore(AuditStore):
    """Production backend. Requires psycopg and a reachable Postgres server; not
    exercised in environments lacking them. Schema/SQL mirror the SQLite store.

    Note on concurrency: with multiple agent writers, wrap seq allocation +
    insert in a transaction (SELECT max(seq) ... FOR UPDATE, or a dedicated
    sequence table) so the chain stays linear. Left as the single statement
    here for clarity.
    """

    _SCHEMA = _SQLITE_SCHEMA  # identical DDL is valid Postgres

    def __init__(self, dsn: str):
        import psycopg  # lazy: only needed for the postgres:// path
        self._conn = psycopg.connect(dsn)
        with self._conn.cursor() as cur:
            cur.execute(self._SCHEMA)
        self._conn.commit()

    def append_row(self, row: dict) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO audit (seq, ts, actor, action, engagement_id, target, "
                "details, prev_hash, entry_hash) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (row["seq"], row["ts"], row["actor"], row["action"], row["engagement_id"],
                 row["target"], json.dumps(row["details"], sort_keys=True, ensure_ascii=False),
                 row["prev_hash"], row["entry_hash"]),
            )
        self._conn.commit()

    def last_row(self) -> dict | None:
        with self._conn.cursor() as cur:
            cur.execute("SELECT seq, ts, actor, action, engagement_id, target, "
                        "details, prev_hash, entry_hash FROM audit ORDER BY seq DESC LIMIT 1")
            r = cur.fetchone()
        return _pg_row(r) if r else None

    def iter_rows(self):
        with self._conn.cursor() as cur:
            cur.execute("SELECT seq, ts, actor, action, engagement_id, target, "
                        "details, prev_hash, entry_hash FROM audit ORDER BY seq ASC")
            for r in cur.fetchall():
                yield _pg_row(r)

    def close(self) -> None:
        self._conn.close()


def _pg_row(r) -> dict:
    keys = ["seq", "ts", "actor", "action", "engagement_id", "target",
            "details", "prev_hash", "entry_hash"]
    d = dict(zip(keys, r))
    if isinstance(d["details"], str):
        d["details"] = json.loads(d["details"])
    return d


# --------------------------------------------------------------------------- #
# the log
# --------------------------------------------------------------------------- #
class AuditLog:
    def __init__(self, store: AuditStore):
        self.store = store

    def record(self, actor: str, action: str, *, engagement_id: str = "",
               target: str = "", **details) -> AuditEntry:
        last = self.store.last_row()
        seq = (last["seq"] + 1) if last else 1
        prev_hash = last["entry_hash"] if last else GENESIS
        ts = _now()
        details = {k: v for k, v in details.items() if v is not None}
        eh = _entry_hash(seq, ts, actor, action, engagement_id, target, details, prev_hash)
        row = {"seq": seq, "ts": ts, "actor": actor, "action": action,
               "engagement_id": engagement_id, "target": target, "details": details,
               "prev_hash": prev_hash, "entry_hash": eh}
        self.store.append_row(row)
        return AuditEntry(**row)

    def entries(self) -> list[AuditEntry]:
        return [AuditEntry(**r) for r in self.store.iter_rows()]

    def verify(self) -> tuple[bool, int | None]:
        """Walk the chain. Returns (ok, first_broken_seq). ok=True means every
        entry hashes correctly and links to its predecessor."""
        prev = GENESIS
        expect_seq = 1
        for e in self.entries():
            if e.seq != expect_seq:
                return False, e.seq
            if e.prev_hash != prev:
                return False, e.seq
            if e.recompute() != e.entry_hash:
                return False, e.seq
            prev = e.entry_hash
            expect_seq += 1
        return True, None

    def export_jsonl(self) -> str:
        return "\n".join(json.dumps(asdict(e), ensure_ascii=False) for e in self.entries())

    def export_markdown(self) -> str:
        lines = ["# Engagement Audit Log", ""]
        ok, broken = self.verify()
        lines.append(f"**Chain integrity:** {'VERIFIED ✓' if ok else f'BROKEN at seq {broken} ✗'}")
        lines.append("")
        lines.append("| seq | time (UTC) | actor | action | target | details |")
        lines.append("|----|----|----|----|----|----|")
        for e in self.entries():
            det = ", ".join(f"{k}={v}" for k, v in e.details.items())
            lines.append(f"| {e.seq} | {e.ts} | {e.actor} | {e.action} | {e.target or '-'} | {det} |")
        return "\n".join(lines)

    def close(self) -> None:
        self.store.close()


def open_audit(dsn: str) -> AuditLog:
    """Open an audit log from a DSN:
       sqlite:///path/to/audit.sqlite   (or a bare filesystem path, or ':memory:')
       postgres://user:pass@host/db     (also postgresql://)
    """
    if dsn.startswith(("postgres://", "postgresql://")):
        return AuditLog(PostgresAuditStore(dsn))
    if dsn.startswith("sqlite:///"):
        dsn = dsn[len("sqlite://"):]  # leave one leading slash -> absolute path
    elif dsn.startswith("sqlite://"):
        dsn = dsn[len("sqlite://"):]
    return AuditLog(SQLiteAuditStore(dsn))
