from __future__ import annotations

import csv
import io
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from ..core import get_db, now_iso
from ..search import LIST_COLS, SORTABLE, build_where, event_dict

router = APIRouter(prefix="/api/events", tags=["events"])


def _filters(q: str | None = None, severity: str | None = None, event_type: str | None = None,
             outcome: str | None = None, username: str | None = None, hostname: str | None = None,
             src_ip: str | None = None, dst_ip: str | None = None, source: str | None = None,
             since: str | None = None, until: str | None = None, ingestion_id: int | None = None):
    return dict(q=q, severity=severity, event_type=event_type, outcome=outcome, username=username,
                hostname=hostname, src_ip=src_ip, dst_ip=dst_ip, source=source, since=since, until=until,
                ingestion_id=ingestion_id)


@router.get("")
def list_events(f: dict = Depends(_filters), sort: str = "ts", order: str = Query("desc", pattern="^(asc|desc)$"),
                page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db: sqlite3.Connection = Depends(get_db)):
    if sort not in SORTABLE:
        raise HTTPException(400, f"Cannot sort by {sort}. Allowed: {', '.join(sorted(SORTABLE))}")
    where, args = build_where(**f)
    total = db.execute(f"SELECT COUNT(*) FROM events WHERE {where}", args).fetchone()[0]
    rows = db.execute(f"SELECT {LIST_COLS} FROM events WHERE {where} ORDER BY {sort} {order}, id {order} LIMIT ? OFFSET ?",
                      args + [page_size, (page - 1) * page_size]).fetchall()
    return {"items": [event_dict(r) for r in rows], "total": total, "page": page, "page_size": page_size,
            "pages": max(1, -(-total // page_size))}


@router.get("/facets")
def facets(db: sqlite3.Connection = Depends(get_db)):
    out = {}
    for col in ("event_type", "outcome", "severity", "source", "hostname", "username", "country"):
        out[col] = [r[0] for r in db.execute(f"SELECT {col} FROM events WHERE {col} IS NOT NULL GROUP BY {col} ORDER BY COUNT(*) DESC LIMIT 100")]
    return out


def _csv_safe(v):
    """Neutralise spreadsheet formula injection from untrusted log content."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


@router.get("/export")
def export_events(f: dict = Depends(_filters), sort: str = "ts", order: str = "asc", db: sqlite3.Connection = Depends(get_db)):
    if sort not in SORTABLE or order not in ("asc", "desc"):
        raise HTTPException(400, "Invalid sort")
    where, args = build_where(**f)
    rows = db.execute(f"SELECT {LIST_COLS} FROM events WHERE {where} ORDER BY {sort} {order}, id LIMIT 50000", args).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = [c.strip() for c in LIST_COLS.split(",")]
    w.writerow(cols)
    for r in rows:
        w.writerow([_csv_safe(r[c]) for c in cols])
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="huntforge-events.csv"'})


@router.get("/{event_id}")
def get_event(event_id: int, db: sqlite3.Connection = Depends(get_db)):
    r = db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
    if not r:
        raise HTTPException(404, "Event not found")
    d = event_dict(r, with_raw=True)
    d["detections"] = [dict(x) for x in db.execute(
        "SELECT d.id, d.title, d.severity, d.status FROM detections d, json_each(d.event_ids) j WHERE j.value = ?", (event_id,))]
    return d


class SavedSearchIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    query: str = Field(min_length=1, max_length=2000)


@router.get("/saved/searches")
def list_saved(db: sqlite3.Connection = Depends(get_db)):
    return [dict(r) for r in db.execute("SELECT * FROM saved_searches ORDER BY id DESC")]


@router.post("/saved/searches", status_code=201)
def save_search(body: SavedSearchIn, db: sqlite3.Connection = Depends(get_db)):
    from ..query import compile_query
    compile_query(body.query)  # validate before storing
    cur = db.execute("INSERT INTO saved_searches (name, query, created_at) VALUES (?,?,?)", (body.name, body.query, now_iso()))
    db.commit()
    return {"id": cur.lastrowid, **body.model_dump()}


@router.delete("/saved/searches/{sid}", status_code=204)
def delete_saved(sid: int, db: sqlite3.Connection = Depends(get_db)):
    db.execute("DELETE FROM saved_searches WHERE id=?", (sid,))
    db.commit()
