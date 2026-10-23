"""Vercel serverless entrypoint: serves the FastAPI backend from the same project as the SPA.

Serverless limitation: SQLite lives in /tmp, which is ephemeral and per-instance. Data resets on
cold starts. Use a persistent host (see render.yaml) for durable cases.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
os.environ.setdefault("HUNTFORGE_DB_PATH", "/tmp/huntforge.db")

from app.core import migrate  # noqa: E402
from app.main import app  # noqa: E402,F401

migrate()  # lifespan events are not guaranteed in serverless; migrations are idempotent


def _seed_demo() -> None:
    """Every cold-started instance has its own empty /tmp database. Seed the deterministic synthetic
    sample so all instances serve identical data (same events, same detection IDs)."""
    from app.core import connect
    from app.detections import engine
    from app.ingest import ingest_bytes
    from app.sample import generator

    conn = connect()
    try:
        if conn.execute("SELECT COUNT(*) FROM ingestions").fetchone()[0] == 0:
            res = ingest_bytes(conn, "huntforge-sample.jsonl (SYNTHETIC)", generator.to_jsonl(), is_sample=True)
            engine.run_all(conn, res["id"])
    finally:
        conn.close()


if os.environ.get("HUNTFORGE_DEMO_SEED", "1") == "1":
    _seed_demo()
