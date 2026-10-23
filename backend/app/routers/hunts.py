from __future__ import annotations

import json
import sqlite3
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..core import get_db, jloads, now_iso, record_activity
from ..search import LIST_COLS, build_where, event_dict
from .cases import (add_detection_to_case, add_event_to_case, event_snapshot, next_id)

router = APIRouter(prefix="/api/hunts", tags=["hunts"])


class HuntCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    hypothesis: str = Field("", max_length=5000)
    query: str = Field("", max_length=2000)
    detection_id: str | None = None


class HuntUpdate(BaseModel):
    title: str | None = Field(None, min_length=1, max_length=200)
    hypothesis: str | None = Field(None, max_length=5000)
    query: str | None = Field(None, max_length=2000)
    status: Literal["open", "in_progress", "concluded"] | None = None
    conclusion: str | None = Field(None, max_length=20000)


class HuntItemIn(BaseModel):
    kind: Literal["note", "finding", "alternative", "evidence"]
    body: str = Field("", max_length=10000)
    event_id: int | None = None


def progress(h: dict, items: list[dict]) -> list[dict]:
    kinds = {i["kind"] for i in items}
    return [
        {"step": "Hypothesis defined", "done": bool(h["hypothesis"].strip())},
        {"step": "Search defined", "done": bool(h["query"].strip())},
        {"step": "Evidence saved", "done": "evidence" in kinds},
        {"step": "Findings or notes recorded", "done": bool(kinds & {"note", "finding"})},
        {"step": "Alternative explanations considered", "done": "alternative" in kinds},
        {"step": "Conclusion written", "done": bool(h["conclusion"].strip())},
    ]


def hunt_full(db, hid: str) -> dict:
    r = db.execute("SELECT * FROM hunts WHERE id=?", (hid,)).fetchone()
    if not r:
        raise HTTPException(404, "Hunt not found")
    h = dict(r)
    items = []
    for it in db.execute("SELECT * FROM hunt_items WHERE hunt_id=? ORDER BY id", (hid,)):
        x = dict(it)
        x["snapshot"] = jloads(x["snapshot"])
        items.append(x)
    h["items"] = items
    h["progress"] = progress(h, items)
    return h


@router.get("")
def list_hunts(db: sqlite3.Connection = Depends(get_db)):
    out = []
    for r in db.execute("SELECT * FROM hunts ORDER BY updated_at DESC, id DESC"):
        h = dict(r)
        its = [dict(i) for i in db.execute("SELECT kind FROM hunt_items WHERE hunt_id=?", (r["id"],))]
        pr = progress(h, its)
        h["progress_done"], h["progress_total"] = sum(p["done"] for p in pr), len(pr)
        out.append(h)
    return {"items": out, "total": len(out)}


@router.post("", status_code=201)
def create_hunt(body: HuntCreate, db: sqlite3.Connection = Depends(get_db)):
    from ..query import compile_query
    query, hyp, title = body.query, body.hypothesis, body.title
    if body.detection_id:
        d = db.execute("SELECT * FROM detections WHERE id=?", (body.detection_id,)).fetchone()
        if not d:
            raise HTTPException(404, "Detection not found")
        if not query and d["entity_value"]:
            ev = d["entity_value"]
            query = f'"{ev}"' if d["entity_type"] != "ip" else f'src_ip = "{ev}" OR dst_ip = "{ev}"'
        if not hyp:
            hyp = f"Is the activity flagged by {d['id']} ({d['title']}) malicious, and what else did {d['entity_value']} do?"
    compile_query(query)
    hid = next_id(db, "hunts", "HUNT")
    ts = now_iso()
    db.execute("INSERT INTO hunts (id, title, hypothesis, query, detection_id, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
               (hid, title, hyp, query, body.detection_id, ts, ts))
    if body.detection_id:
        db.execute("UPDATE detections SET status=CASE WHEN status='open' THEN 'investigating' ELSE status END, updated_at=? WHERE id=?", (ts, body.detection_id))
    record_activity(db, "hunt_created", "hunt", hid, title)
    db.commit()
    return hunt_full(db, hid)


@router.get("/{hid}")
def get_hunt(hid: str, db: sqlite3.Connection = Depends(get_db)):
    return hunt_full(db, hid)


@router.patch("/{hid}")
def update_hunt(hid: str, body: HuntUpdate, db: sqlite3.Connection = Depends(get_db)):
    from ..query import compile_query
    fields = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
    hunt_full(db, hid)
    if "query" in fields:
        compile_query(fields["query"])
    if fields:
        db.execute(f"UPDATE hunts SET {', '.join(f'{k}=?' for k in fields)}, updated_at=? WHERE id=?", [*fields.values(), now_iso(), hid])
        record_activity(db, "hunt_updated", "hunt", hid, ", ".join(fields))
        db.commit()
    return hunt_full(db, hid)


@router.post("/{hid}/items", status_code=201)
def add_item(hid: str, body: HuntItemIn, db: sqlite3.Connection = Depends(get_db)):
    hunt_full(db, hid)
    snap = None
    if body.kind == "evidence":
        if body.event_id is None:
            raise HTTPException(422, "event_id required for evidence")
        snap = event_snapshot(db, body.event_id)
        if not snap:
            raise HTTPException(404, "Event not found")
        if db.execute("SELECT 1 FROM hunt_items WHERE hunt_id=? AND kind='evidence' AND ref=?", (hid, str(body.event_id))).fetchone():
            return hunt_full(db, hid)
    elif not body.body.strip():
        raise HTTPException(422, "Text cannot be empty")
    db.execute("INSERT INTO hunt_items (hunt_id, kind, ref, body, snapshot, created_at) VALUES (?,?,?,?,?,?)",
               (hid, body.kind, str(body.event_id) if snap else None, body.body, json.dumps(snap) if snap else None, now_iso()))
    db.execute("UPDATE hunts SET status=CASE WHEN status='open' THEN 'in_progress' ELSE status END, updated_at=? WHERE id=?", (now_iso(), hid))
    record_activity(db, f"hunt_{body.kind}_added", "hunt", hid)
    db.commit()
    return hunt_full(db, hid)


@router.delete("/{hid}/items/{item_id}", status_code=204)
def delete_item(hid: str, item_id: int, db: sqlite3.Connection = Depends(get_db)):
    db.execute("DELETE FROM hunt_items WHERE id=? AND hunt_id=?", (item_id, hid))
    db.commit()


@router.post("/{hid}/case", status_code=201)
def promote_to_case(hid: str, db: sqlite3.Connection = Depends(get_db)):
    """Create a case from a hunt (or return the existing linked case), copying evidence and notes."""
    h = hunt_full(db, hid)
    if h["case_id"]:
        return {"case_id": h["case_id"], "created": False}
    cid = next_id(db, "cases", "CASE")
    ts = now_iso()
    db.execute("INSERT INTO cases (id, title, description, severity, findings, conclusion, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
               (cid, h["title"], f"Hypothesis: {h['hypothesis']}", "medium",
                "\n".join(f"- {i['body']}" for i in h["items"] if i["kind"] == "finding"), h["conclusion"], ts, ts))
    if h["detection_id"]:
        sev = db.execute("SELECT severity FROM detections WHERE id=?", (h["detection_id"],)).fetchone()
        if sev:
            db.execute("UPDATE cases SET severity=? WHERE id=?", (sev["severity"], cid))
        add_detection_to_case(db, cid, h["detection_id"])
    for i in h["items"]:
        if i["kind"] == "evidence":
            add_event_to_case(db, cid, int(i["ref"]), i["body"])
        else:
            label = {"note": "Hunt note", "finding": "Hunt finding", "alternative": "Alternative explanation"}[i["kind"]]
            db.execute("INSERT INTO case_items (case_id, kind, body, created_at) VALUES (?,?,?,?)", (cid, "note", f"[{label}] {i['body']}", ts))
    db.execute("UPDATE hunts SET case_id=?, updated_at=? WHERE id=?", (cid, ts, hid))
    record_activity(db, "case_created", "case", cid, f"from {hid}")
    db.commit()
    return {"case_id": cid, "created": True}


@router.get("/{hid}/events")
def hunt_events(hid: str, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db: sqlite3.Connection = Depends(get_db)):
    h = hunt_full(db, hid)
    where, args = build_where(q=h["query"] or None)
    total = db.execute(f"SELECT COUNT(*) FROM events WHERE {where}", args).fetchone()[0]
    rows = db.execute(f"SELECT {LIST_COLS} FROM events WHERE {where} ORDER BY ts, id LIMIT ? OFFSET ?", args + [page_size, (page - 1) * page_size]).fetchall()
    return {"items": [event_dict(r) for r in rows], "total": total, "page": page, "page_size": page_size}


@router.delete("/{hid}", status_code=204)
def delete_hunt(hid: str, db: sqlite3.Connection = Depends(get_db)):
    db.execute("DELETE FROM hunts WHERE id=?", (hid,))
    db.commit()
