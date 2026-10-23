"""Configuration, database access and small shared helpers."""
from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

BASE_DIR = Path(__file__).resolve().parent.parent
MIGRATIONS_DIR = BASE_DIR / "migrations"

log = logging.getLogger("huntforge")

SEVERITIES = ["informational", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


class Settings:
    """Environment-based configuration, read lazily so tests can override it."""

    @property
    def db_path(self) -> str:
        return os.environ.get("HUNTFORGE_DB_PATH", str(BASE_DIR / "data" / "huntforge.db"))

    @property
    def cors_origins(self) -> list[str]:
        raw = os.environ.get("HUNTFORGE_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
        return [o.strip() for o in raw.split(",") if o.strip()]

    @property
    def max_upload_bytes(self) -> int:
        return int(float(os.environ.get("HUNTFORGE_MAX_UPLOAD_MB", "10")) * 1024 * 1024)

    @property
    def max_events_per_upload(self) -> int:
        return int(os.environ.get("HUNTFORGE_MAX_EVENTS", "100000"))

    @property
    def rate_limit_per_minute(self) -> int:
        return int(os.environ.get("HUNTFORGE_RATE_LIMIT", "600"))

    @property
    def log_level(self) -> str:
        return os.environ.get("HUNTFORGE_LOG_LEVEL", "INFO")


settings = Settings()


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect() -> sqlite3.Connection:
    path = settings.db_path
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def migrate() -> list[str]:
    """Apply numbered SQL migrations that have not yet been recorded."""
    conn = connect()
    applied: list[str] = []
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)")
        done = {r["name"] for r in conn.execute("SELECT name FROM schema_migrations")}
        for f in sorted(MIGRATIONS_DIR.glob("*.sql")):
            if f.name in done:
                continue
            conn.executescript(f.read_text(encoding="utf-8"))
            conn.execute("INSERT INTO schema_migrations VALUES (?, ?)", (f.name, now_iso()))
            conn.commit()
            applied.append(f.name)
    finally:
        conn.close()
    return applied


def get_db() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


def record_activity(conn: sqlite3.Connection, action: str, target_type: str | None = None,
                    target_id: str | None = None, detail: str | None = None) -> None:
    conn.execute(
        "INSERT INTO activity (ts, action, target_type, target_id, detail) VALUES (?,?,?,?,?)",
        (now_iso(), action, target_type, target_id, detail),
    )


def jloads(v, default=None):
    if v is None:
        return default
    try:
        return json.loads(v)
    except (TypeError, ValueError):
        return default
