from __future__ import annotations

import sqlite3
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ..core import get_db, jloads, now_iso, record_activity
from ..detections import engine
from ..detections.rules import BY_ID
from ..search import event_dict

router = APIRouter(prefix="/api/detections", tags=["detections"])

STATUSES = ["open", "investigating", "false_positive", "benign", "resolved"]
SORTS = {"ts": "ts", "severity": "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END",
         "confidence": "confidence", "rule": "rule_id", "status": "status"}


def det_dict(r, full=False) -> dict:
    d = dict(r)
    d["event_ids"] = jloads(d["event_ids"], [])
    d["event_count"] = len(d["event_ids"])
    d["evidence"] = jloads(d["evidence"], {})
    d.pop("dedupe_key", None)
    rule = BY_ID.get(d["rule_id"])
    d["rule_name"] = rule.name if rule else d["rule_id"]
    d["technique"] = rule.technique if rule else None
    return d


@router.get("")
def list_detections(status: str | None = None, severity: str | None = None, rule_id: str | None = None,
                    entity: str | None = None, q: str | None = None, ingestion_id: int | None = None,
                    since: str | None = None, until: str | None = None,
                    sort: str = "ts", order: str = Query("desc", pattern="^(asc|desc)$"),
                    page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100),
                    db: sqlite3.Connection = Depends(get_db)):
    if sort not in SORTS:
        raise HTTPException(400, "Invalid sort")
    cl, args = [], []
    for col, v in (("status", status), ("severity", severity), ("rule_id", rule_id), ("entity_value", entity), ("ingestion_id", ingestion_id)):
        if v not in (None, ""):
            cl.append(f"{col} = ?")
            args.append(v)
    if q:
        cl.append("(title LIKE ? ESCAPE '\\' OR entity_value LIKE ? ESCAPE '\\' OR id LIKE ? ESCAPE '\\')")
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        args += [like] * 3
    if since:
        cl.append("ts >= ?"); args.append(since)
    if until:
        cl.append("ts <= ?"); args.append(until)
    where = " AND ".join(cl) or "1=1"
    total = db.execute(f"SELECT COUNT(*) FROM detections WHERE {where}", args).fetchone()[0]
    rows = db.execute(f"SELECT * FROM detections WHERE {where} ORDER BY {SORTS[sort]} {order}, id LIMIT ? OFFSET ?",
                      args + [page_size, (page - 1) * page_size]).fetchall()
    # Grouping: how many findings share the same rule + entity (alert grouping aid)
    items = []
    for r in rows:
        d = det_dict(r)
        d["group_size"] = db.execute("SELECT COUNT(*) FROM detections WHERE rule_id=? AND entity_value=?", (r["rule_id"], r["entity_value"])).fetchone()[0]
        items.append(d)
    return {"items": items, "total": total, "page": page, "page_size": page_size, "pages": max(1, -(-total // page_size))}


@router.post("/run")
def run_detections(ingestion_id: int | None = None, db: sqlite3.Connection = Depends(get_db)):
    return engine.run_all(db, ingestion_id)


@router.get("/{det_id}")
def get_detection(det_id: str, db: sqlite3.Connection = Depends(get_db)):
    r = db.execute("SELECT * FROM detections WHERE id=?", (det_id,)).fetchone()
    if not r:
        raise HTTPException(404, "Detection not found")
    d = det_dict(r)
    ids = d["event_ids"]
    events = []
    if ids:
        q = ",".join("?" * len(ids))
        events = [event_dict(e, with_raw=True) for e in db.execute(f"SELECT * FROM events WHERE id IN ({q}) ORDER BY ts, id", ids)]
    rule = BY_ID.get(d["rule_id"])
    d["events"] = events
    d["recommended_steps"] = rule.steps if rule else []
    d["false_positive_risks"] = rule.false_positives if rule else None
    d["limitations"] = rule.limitations if rule else None
    d["note"] = "A detection is a suspicious pattern, not a confirmed attack. Validate against the evidence before concluding."
    return d


class StatusIn(BaseModel):
    status: Literal["open", "investigating", "false_positive", "benign", "resolved"]


@router.patch("/{det_id}")
def update_status(det_id: str, body: StatusIn, db: sqlite3.Connection = Depends(get_db)):
    cur = db.execute("UPDATE detections SET status=?, updated_at=? WHERE id=?", (body.status, now_iso(), det_id))
    if cur.rowcount == 0:
        raise HTTPException(404, "Detection not found")
    record_activity(db, "detection_status", "detection", det_id, body.status)
    db.commit()
    return {"id": det_id, "status": body.status}
