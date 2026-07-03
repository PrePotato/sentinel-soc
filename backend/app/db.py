"""PostgreSQL event log (via asyncpg).

Persists every generated alert as a searchable security event. Entirely
optional: if DATABASE_URL is unset or the database is unreachable, every
function is a safe no-op and the app runs from in-memory state — matching the
rest of the platform's graceful-degradation design.
"""
from __future__ import annotations

from typing import Any

from .config import settings
from .schemas import Alert, EventRecord

_pool: Any = None

_CREATE = """
CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL PRIMARY KEY,
    event_ts    BIGINT      NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    type        TEXT        NOT NULL,
    severity    TEXT        NOT NULL,
    message     TEXT        NOT NULL,
    action      TEXT,
    technique   TEXT,
    source      TEXT,
    src_mac     TEXT
);
CREATE INDEX IF NOT EXISTS events_created_idx ON events (created_at DESC);
CREATE INDEX IF NOT EXISTS events_severity_idx ON events (severity);
"""


async def init() -> None:
    """Create the connection pool and ensure the schema exists."""
    global _pool
    if not settings.database_url:
        return
    try:
        import asyncpg

        # statement_cache_size=0 keeps us compatible with transaction-mode
        # poolers (e.g. Supabase / PgBouncer), which don't support prepared
        # statement caching.
        _pool = await asyncpg.create_pool(
            settings.database_url, min_size=1, max_size=5, command_timeout=10, statement_cache_size=0
        )
        async with _pool.acquire() as con:
            await con.execute(_CREATE)
    except Exception:
        _pool = None  # DB unavailable → degrade to in-memory only


async def close() -> None:
    global _pool
    if _pool is not None:
        try:
            await _pool.close()
        finally:
            _pool = None


def available() -> bool:
    return _pool is not None


async def log_event(a: Alert) -> None:
    if _pool is None:
        return
    try:
        async with _pool.acquire() as con:
            await con.execute(
                """INSERT INTO events (event_ts, type, severity, message, action, technique, source, src_mac)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8)""",
                a.ts, a.type, a.severity, a.message, a.action, a.technique, a.source, a.srcMac,
            )
    except Exception:
        pass


async def recent_events(limit: int = 100, q: str | None = None, severity: str | None = None) -> list[EventRecord]:
    """Searchable event log — most recent first."""
    if _pool is None:
        return []
    try:
        where, args = [], []
        if q:
            args.append(f"%{q}%")
            where.append(f"(message ILIKE ${len(args)} OR type ILIKE ${len(args)} OR source ILIKE ${len(args)} OR technique ILIKE ${len(args)})")
        if severity:
            args.append(severity)
            where.append(f"severity = ${len(args)}")
        args.append(max(1, min(500, limit)))
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        sql = f"SELECT id, event_ts, type, severity, message, action, technique, source, src_mac FROM events {clause} ORDER BY id DESC LIMIT ${len(args)}"
        async with _pool.acquire() as con:
            rows = await con.fetch(sql, *args)
        return [
            EventRecord(
                id=r["id"], ts=r["event_ts"], type=r["type"], severity=r["severity"],
                message=r["message"], action=r["action"], technique=r["technique"],
                source=r["source"], srcMac=r["src_mac"],
            )
            for r in rows
        ]
    except Exception:
        return []
