"""
rt.audit — the append-only, hash-chained evidence trail.

Every engagement action is recorded as an immutable entry whose hash chains to
the previous one:

    entry_hash = sha256(prev_hash + canonical(body))

where ``body = {seq, ts, actor, event, data}`` and ``canonical`` is sorted-key,
compact-separator JSON (byte-identical to the form rt.scope and the Go services
use). Any edit, deletion, or reorder breaks the chain; ``verify()`` walks it and
reports the first broken sequence number. No secret key is needed — a client or
an auditor verifies it independently. This is RT's VAPT liability shield.

Persistence is pluggable behind a DB-API 2.0 connection:

    * SQLiteAudit  — stdlib ``sqlite3``; the default, and the embedded appliance
                     backend. One file, no server.
    * PostgresAudit — ``psycopg`` (same schema, same chain logic) for production.

``open_audit(dsn)`` selects: a ``postgres://`` DSN → Postgres, anything else is
treated as a SQLite file path. The file/table is created lazily on first append
or verify, so attaching an audit sink to a read-only command costs nothing.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

GENESIS = "0" * 64

# Canonical engagement events (see RT-architecture.md "Audit log").
EVENTS = (
    "engagement.init",
    "finding.add",
    "task.create",
    "task.confirm",
    "task.dispatch",
    "task.blocked",
    "task.conclude",
)


class AuditError(Exception):
    pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical(body: dict) -> str:
    return json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _entry_hash(prev_hash: str, body: dict) -> str:
    return hashlib.sha256((prev_hash + _canonical(body)).encode("utf-8")).hexdigest()


class AuditStore:
    """Chain logic over a DB-API 2.0 connection. Backends supply the connection
    and the parameter placeholder (``?`` for sqlite, ``%s`` for psycopg)."""

    _ddl = (
        "CREATE TABLE IF NOT EXISTS audit ("
        "  seq INTEGER PRIMARY KEY,"
        "  ts TEXT NOT NULL,"
        "  actor TEXT NOT NULL,"
        "  event TEXT NOT NULL,"
        "  data TEXT NOT NULL,"
        "  prev_hash TEXT NOT NULL,"
        "  entry_hash TEXT NOT NULL"
        ")"
    )

    def __init__(self):
        self._ready = False

    # -- backend hooks (overridden) ---------------------------------------- #
    def _connect(self):  # pragma: no cover - overridden
        raise NotImplementedError

    @property
    def _ph(self) -> str:  # parameter placeholder
        return "?"

    # -- schema ------------------------------------------------------------ #
    def _ensure(self, conn) -> None:
        if not self._ready:
            conn.execute(self._ddl)
            self._ready = True

    # -- append ------------------------------------------------------------ #
    def append(self, event: str, *, actor: str, data: dict | None = None) -> dict:
        if event not in EVENTS:
            raise AuditError(f"unknown audit event {event!r}; expected one of {EVENTS}")
        if not actor or not str(actor).strip():
            raise AuditError(f"audit event {event!r} needs an actor (who did it)")
        data = data or {}
        conn = self._connect()
        try:
            self._ensure(conn)
            cur = conn.cursor()
            cur.execute("SELECT seq, entry_hash FROM audit ORDER BY seq DESC LIMIT 1")
            row = cur.fetchone()
            prev_seq, prev_hash = (row[0], row[1]) if row else (0, GENESIS)
            seq = prev_seq + 1
            body = {"seq": seq, "ts": _now_iso(), "actor": str(actor).strip(),
                    "event": event, "data": data}
            eh = _entry_hash(prev_hash, body)
            ph = self._ph
            cur.execute(
                f"INSERT INTO audit (seq, ts, actor, event, data, prev_hash, entry_hash) "
                f"VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})",
                (seq, body["ts"], body["actor"], event, _canonical(data), prev_hash, eh),
            )
            conn.commit()
            return {**body, "prev_hash": prev_hash, "entry_hash": eh}
        finally:
            conn.close()

    # -- read -------------------------------------------------------------- #
    def entries(self) -> list[dict]:
        conn = self._connect()
        try:
            self._ensure(conn)
            cur = conn.cursor()
            cur.execute("SELECT seq, ts, actor, event, data, prev_hash, entry_hash "
                        "FROM audit ORDER BY seq ASC")
            out = []
            for seq, ts, actor, event, data, prev_hash, entry_hash in cur.fetchall():
                out.append({"seq": seq, "ts": ts, "actor": actor, "event": event,
                            "data": json.loads(data), "prev_hash": prev_hash,
                            "entry_hash": entry_hash})
            return out
        finally:
            conn.close()

    # -- verify ------------------------------------------------------------ #
    def verify(self) -> tuple[bool, int | None, str | None]:
        """Walk the chain. Returns (ok, first_broken_seq, reason).

        A break is any of: a gap in the sequence, a prev_hash that does not
        match the prior entry's hash, or an entry_hash that does not recompute
        from the stored body — i.e. any edit, deletion, or reorder.
        """
        prev_hash = GENESIS
        expected_seq = 1
        for e in self.entries():
            if e["seq"] != expected_seq:
                return False, expected_seq, f"sequence gap: expected {expected_seq}, found {e['seq']}"
            if e["prev_hash"] != prev_hash:
                return False, e["seq"], "prev_hash does not match the prior entry"
            body = {"seq": e["seq"], "ts": e["ts"], "actor": e["actor"],
                    "event": e["event"], "data": e["data"]}
            if _entry_hash(prev_hash, body) != e["entry_hash"]:
                return False, e["seq"], "entry_hash does not recompute (entry was altered)"
            prev_hash = e["entry_hash"]
            expected_seq += 1
        return True, None, None


class SQLiteAudit(AuditStore):
    def __init__(self, path: str):
        super().__init__()
        self.path = path

    def _connect(self):
        import sqlite3
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("BEGIN IMMEDIATE")  # serialize appends; one appliance, low volume
        return conn


class PostgresAudit(AuditStore):
    """Same schema and chain logic over psycopg. Untested without a live PG;
    the SQLite path is the tested reference implementation."""
    def __init__(self, dsn: str):
        super().__init__()
        self.dsn = dsn

    @property
    def _ph(self) -> str:
        return "%s"

    def _connect(self):
        try:
            import psycopg  # type: ignore
        except ImportError as e:  # pragma: no cover
            raise AuditError("Postgres audit backend needs `psycopg` installed") from e
        return psycopg.connect(self.dsn, autocommit=False)


def open_audit(dsn: str) -> AuditStore:
    """Open an audit store. ``postgres://`` or ``postgresql://`` DSN → Postgres;
    anything else is a SQLite file path (the appliance default)."""
    if dsn.startswith("postgres://") or dsn.startswith("postgresql://"):
        return PostgresAudit(dsn)
    return SQLiteAudit(dsn)
