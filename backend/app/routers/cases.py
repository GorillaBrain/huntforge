from __future__ import annotations

import json
import sqlite3
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..core import get_db, jloads, now_iso, record_activity
from ..search import event_dict

router = APIRouter(prefix="/api/cases", tags=["cases"])

Sev = Literal["informational", "low", "medium", "high", "critical"]
Status = Literal["open", "in_progress", "closed"]


def next_id(db: sqlite3.Connection, table: str, prefix: str) -> str:
    n = 0
    for r in db.execute(f"SELECT id FROM {table}"):
        try:
            n = max(n, int(r["id"].split("-")[1]))
        except (IndexError, ValueError):
            pass
    return f"{prefix}-{n + 1:04d}"


def event_snapshot(db, event_id: int) -> dict | None:
    r = db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
    return event_dict(r, with_raw=True) if r else None


def detection_snapshot(db, det_id: str) -> dict | None:
    r = db.execute("SELECT * FROM detections WHERE id=?", (det_id,)).fetchone()
    if not r:
        return None
    return {k: (jloads(r[k], r[k]) if k in ("evidence", "event_ids") else r[k]) for k in
            ("id", "rule_id", "severity", "confidence", "ts", "entity_type", "entity_value", "title", "explanation", "evidence", "event_ids", "status")}


def add_detection_to_case(db, case_id: str, det_id: str) -> None:
    snap = detection_snapshot(db, det_id)
    if not snap:
        raise HTTPException(404, f"Detection {det_id} not found")
    if db.execute("SELECT 1 FROM case_items WHERE case_id=? AND kind='detection' AND ref=?", (case_id, det_id)).fetchone():
        return
    db.execute("INSERT INTO case_items (case_id, kind, ref, body, snapshot, created_at) VALUES (?,?,?,?,?,?)",
               (case_id, "detection", det_id, snap["title"], json.dumps(snap), now_iso()))
    db.execute("UPDATE detections SET case_id=?, status=CASE WHEN status='open' THEN 'investigating' ELSE status END, updated_at=? WHERE id=?",
               (case_id, now_iso(), det_id))
    for eid in snap["event_ids"]:
        add_event_to_case(db, case_id, eid, "Supporting event for " + det_id)


def add_event_to_case(db, case_id: str, event_id: int, note: str = "") -> bool:
    if db.execute("SELECT 1 FROM case_items WHERE case_id=? AND kind='evidence' AND ref=?", (case_id, str(event_id))).fetchone():
        return False
    snap = event_snapshot(db, event_id)
    if not snap:
        raise HTTPException(404, f"Event {event_id} not found")
    db.execute("INSERT INTO case_items (case_id, kind, ref, body, snapshot, created_at) VALUES (?,?,?,?,?,?)",
               (case_id, "evidence", str(event_id), note, json.dumps(snap), now_iso()))
    return True


class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field("", max_length=5000)
    severity: Sev = "medium"
    assignee: str | None = Field(None, max_length=100)
    detection_id: str | None = None
    event_ids: list[int] = Field(default_factory=list, max_length=500)


class CaseUpdate(BaseModel):
    title: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = Field(None, max_length=5000)
    severity: Sev | None = None
    status: Status | None = None
    assignee: str | None = Field(None, max_length=100)
    findings: str | None = Field(None, max_length=20000)
    conclusion: str | None = Field(None, max_length=20000)
    uncertainty: str | None = Field(None, max_length=20000)
    recommendations: str | None = Field(None, max_length=20000)


class ItemIn(BaseModel):
    kind: Literal["note", "evidence", "detection"]
    body: str = Field("", max_length=10000)
    event_id: int | None = None
    detection_id: str | None = None


def case_dict(db, r) -> dict:
    d = dict(r)
    d["item_counts"] = {k: n for k, n in db.execute("SELECT kind, COUNT(*) FROM case_items WHERE case_id=? GROUP BY kind", (r["id"],))}
    return d


@router.get("")
def list_cases(status: str | None = None, severity: str | None = None, db: sqlite3.Connection = Depends(get_db)):
    cl, args = [], []
    if status:
        cl.append("status=?"); args.append(status)
    if severity:
        cl.append("severity=?"); args.append(severity)
    rows = db.execute(f"SELECT * FROM cases WHERE {' AND '.join(cl) or '1=1'} ORDER BY updated_at DESC, id DESC", args).fetchall()
    return {"items": [case_dict(db, r) for r in rows], "total": len(rows)}


@router.post("", status_code=201)
def create_case(body: CaseCreate, db: sqlite3.Connection = Depends(get_db)):
    cid = next_id(db, "cases", "CASE")
    ts = now_iso()
    db.execute("INSERT INTO cases (id, title, description, severity, assignee, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
               (cid, body.title, body.description, body.severity, body.assignee, ts, ts))
    if body.detection_id:
        add_detection_to_case(db, cid, body.detection_id)
    for eid in body.event_ids:
        add_event_to_case(db, cid, eid)
    record_activity(db, "case_created", "case", cid, body.title)
    db.commit()
    return get_case(cid, db)


@router.get("/{case_id}")
def get_case(case_id: str, db: sqlite3.Connection = Depends(get_db)):
    r = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not r:
        raise HTTPException(404, "Case not found")
    d = case_dict(db, r)
    items = []
    for it in db.execute("SELECT * FROM case_items WHERE case_id=? ORDER BY id", (case_id,)):
        x = dict(it)
        x["snapshot"] = jloads(x["snapshot"])
        items.append(x)
    d["items"] = items
    d["hunts"] = [dict(h) for h in db.execute("SELECT id, title, status FROM hunts WHERE case_id=?", (case_id,))]
    # Timeline: evidence events in event-time order, interleaved with analyst actions in action-time order.
    d["timeline"] = sorted(
        [{"ts": i["snapshot"]["ts"], "type": "event", "ref": f"EVT-{i['ref']}", "summary": _summ(i["snapshot"]), "note": i["body"]}
         for i in items if i["kind"] == "evidence" and i["snapshot"]], key=lambda t: t["ts"])
    return d


def _summ(e: dict) -> str:
    bits = [e.get("event_type"), e.get("outcome"), e.get("username"), e.get("hostname"), e.get("src_ip"),
            (f"-> {e['dst_ip']}:{e['dst_port']}" if e.get("dst_ip") else None), e.get("command_line") or e.get("message")]
    return " ".join(str(b) for b in bits if b)[:300]


@router.patch("/{case_id}")
def update_case(case_id: str, body: CaseUpdate, db: sqlite3.Connection = Depends(get_db)):
    fields = body.model_dump(exclude_unset=True)
    if "title" in fields and fields["title"] is None:
        fields.pop("title")
    if not db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
        raise HTTPException(404, "Case not found")
    if fields:
        sets = ", ".join(f"{k}=?" for k in fields)
        db.execute(f"UPDATE cases SET {sets}, updated_at=? WHERE id=?", [*fields.values(), now_iso(), case_id])
        record_activity(db, "case_updated", "case", case_id, ", ".join(fields))
        db.commit()
    return get_case(case_id, db)


@router.post("/{case_id}/items", status_code=201)
def add_item(case_id: str, body: ItemIn, db: sqlite3.Connection = Depends(get_db)):
    if not db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
        raise HTTPException(404, "Case not found")
    if body.kind == "note":
        if not body.body.strip():
            raise HTTPException(422, "Note cannot be empty")
        db.execute("INSERT INTO case_items (case_id, kind, body, created_at) VALUES (?,?,?,?)", (case_id, "note", body.body, now_iso()))
    elif body.kind == "evidence":
        if body.event_id is None:
            raise HTTPException(422, "event_id required")
        add_event_to_case(db, case_id, body.event_id, body.body)
    else:
        if not body.detection_id:
            raise HTTPException(422, "detection_id required")
        add_detection_to_case(db, case_id, body.detection_id)
    db.execute("UPDATE cases SET updated_at=? WHERE id=?", (now_iso(), case_id))
    record_activity(db, f"case_{body.kind}_added", "case", case_id)
    db.commit()
    return get_case(case_id, db)


@router.delete("/{case_id}/items/{item_id}", status_code=204)
def delete_item(case_id: str, item_id: int, db: sqlite3.Connection = Depends(get_db)):
    db.execute("DELETE FROM case_items WHERE id=? AND case_id=?", (item_id, case_id))
    db.commit()


@router.delete("/{case_id}", status_code=204)
def delete_case(case_id: str, db: sqlite3.Connection = Depends(get_db)):
    db.execute("UPDATE detections SET case_id=NULL WHERE case_id=?", (case_id,))
    db.execute("UPDATE hunts SET case_id=NULL WHERE case_id=?", (case_id,))
    db.execute("DELETE FROM cases WHERE id=?", (case_id,))
    record_activity(db, "case_deleted", "case", case_id)
    db.commit()
