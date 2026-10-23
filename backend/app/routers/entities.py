from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query

from ..core import get_db
from ..search import LIST_COLS, build_where, event_dict

router = APIRouter(prefix="/api", tags=["entities"])

# entity type -> columns holding that kind of value
ENTITY_COLS = {"ip": ["src_ip", "dst_ip"], "user": ["username"], "host": ["hostname"],
               "domain": ["domain"], "process": ["process_name"]}


def _entity_where(etype: str, value: str):
    cols = ENTITY_COLS[etype]
    return "(" + " OR ".join(f"{c} = ? COLLATE NOCASE" for c in cols) + ")", [value] * len(cols)


@router.get("/entities")
def search_entities(type: str = Query("ip", pattern="^(ip|user|host|domain|process)$"), q: str = "",
                    limit: int = Query(50, ge=1, le=200), db: sqlite3.Connection = Depends(get_db)):
    like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    parts = [f"SELECT {c} AS v FROM events WHERE {c} IS NOT NULL AND {c} LIKE ? ESCAPE '\\'" for c in ENTITY_COLS[type]]
    sql = f"SELECT v, COUNT(*) AS events, (SELECT MAX(ts) FROM events) AS _x FROM ({' UNION ALL '.join(parts)}) GROUP BY v ORDER BY events DESC LIMIT ?"
    rows = db.execute(sql, [like] * len(parts) + [limit]).fetchall()
    return {"type": type, "items": [{"value": r["v"], "events": r["events"]} for r in rows]}


@router.get("/entities/{etype}/{value:path}")
def get_entity(etype: str, value: str, db: sqlite3.Connection = Depends(get_db)):
    if etype not in ENTITY_COLS:
        raise HTTPException(404, "Unknown entity type")
    where, args = _entity_where(etype, value)
    stats = db.execute(f"SELECT COUNT(*) n, MIN(ts) first, MAX(ts) last FROM events WHERE {where}", args).fetchone()
    if stats["n"] == 0:
        raise HTTPException(404, "No observed activity for this entity")
    by_type = [dict(r) for r in db.execute(f"SELECT event_type, outcome, COUNT(*) n FROM events WHERE {where} GROUP BY event_type, outcome ORDER BY n DESC", args)]
    recent = [event_dict(r) for r in db.execute(f"SELECT {LIST_COLS} FROM events WHERE {where} ORDER BY ts DESC, id DESC LIMIT 25", args)]
    related = {}
    for rtype, cols in ENTITY_COLS.items():
        if rtype == etype:
            continue
        agg = []
        for c in cols:
            agg += [(r["v"], r["n"]) for r in db.execute(
                f"SELECT {c} v, COUNT(*) n FROM events WHERE {where} AND {c} IS NOT NULL GROUP BY {c} ORDER BY n DESC LIMIT 10", args)]
        merged: dict[str, int] = {}
        for v, n in agg:
            if v.lower() != value.lower():
                merged[v] = merged.get(v, 0) + n
        related[rtype] = [{"value": v, "events": n} for v, n in sorted(merged.items(), key=lambda kv: -kv[1])[:10]]
    ev_sql = f"SELECT id FROM events WHERE {where}"
    dets = [dict(r) for r in db.execute(
        f"""SELECT DISTINCT d.id, d.title, d.severity, d.confidence, d.status, d.ts, d.rule_id FROM detections d
            WHERE (d.entity_type = ? AND d.entity_value = ? COLLATE NOCASE)
               OR EXISTS (SELECT 1 FROM json_each(d.event_ids) j WHERE j.value IN ({ev_sql}))
            ORDER BY d.ts DESC LIMIT 50""", [etype, value, *args])]
    cases = [dict(r) for r in db.execute(
        f"""SELECT DISTINCT c.id, c.title, c.status, c.severity FROM cases c WHERE c.id IN (
              SELECT case_id FROM detections WHERE id IN ({','.join('?' * len(dets)) or "''"})
              UNION SELECT case_id FROM case_items WHERE kind='evidence' AND CAST(ref AS INTEGER) IN ({ev_sql}))""",
        [d["id"] for d in dets] + args)]
    return {"type": etype, "value": value,
            "observed": {"event_count": stats["n"], "first_seen": stats["first"], "last_seen": stats["last"],
                         "activity": by_type, "recent_events": recent, "related": related},
            "detections": dets, "cases": cases,
            "external_intelligence": {"providers": [], "note": "No external threat-intelligence provider is configured. "
                                      "The absence of reputation data does not indicate this entity is safe."}}


@router.get("/graph")
def graph(q: str | None = None, ingestion_id: int | None = None, limit: int = Query(500, ge=1, le=2000),
          db: sqlite3.Connection = Depends(get_db)):
    """Entity relationship graph built only from observed co-occurrence in matching events."""
    where, args = build_where(q=q, ingestion_id=ingestion_id)
    rows = db.execute(f"SELECT {LIST_COLS} FROM events WHERE {where} ORDER BY ts LIMIT ?", args + [limit]).fetchall()
    nodes: dict[str, dict] = {}
    edges: dict[tuple, dict] = {}

    def node(t, v):
        k = f"{t}:{v}"
        n = nodes.setdefault(k, {"id": k, "type": t, "value": v, "count": 0})
        n["count"] += 1
        return k

    def edge(a, b, label, eid):
        k = (a, b, label)
        e = edges.setdefault(k, {"source": a, "target": b, "label": label, "count": 0, "event_ids": []})
        e["count"] += 1
        if len(e["event_ids"]) < 20:
            e["event_ids"].append(eid)

    for r in rows:
        ip, user, host, dst, dom, proc = r["src_ip"], r["username"], r["hostname"], r["dst_ip"], r["domain"], r["process_name"]
        ni = node("ip", ip) if ip else None
        nu = node("user", user) if user else None
        nh = node("host", host) if host else None
        if ni and nu and r["event_type"] == "authentication":
            edge(ni, nu, "auth " + (r["outcome"] or ""), r["id"])
        if nu and nh:
            edge(nu, nh, r["event_type"] or "activity", r["id"])
        elif ni and nh:
            edge(ni, nh, r["event_type"] or "activity", r["id"])
        if nh and dst:
            edge(nh, node("ip", dst), f"connect :{r['dst_port']}" if r["dst_port"] else "connect", r["id"])
        if nh and dom:
            edge(nh, node("domain", dom), "dns", r["id"])
        if nh and proc:
            edge(nh, node("process", proc), "process", r["id"])
    return {"nodes": list(nodes.values()), "edges": list(edges.values()), "event_count": len(rows), "truncated": len(rows) >= limit}
