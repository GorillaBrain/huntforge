from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends

from ..core import get_db
from ..search import LIST_COLS, event_dict

router = APIRouter(prefix="/api", tags=["overview"])


@router.get("/health")
def health(db: sqlite3.Connection = Depends(get_db)):
    db.execute("SELECT 1").fetchone()
    return {"status": "ok", "database": "ok"}


@router.get("/overview")
def overview(since: str | None = None, until: str | None = None, severity: str | None = None,
             source: str | None = None, category: str | None = None, ingestion_id: int | None = None,
             db: sqlite3.Connection = Depends(get_db)):
    ev_cl, ev_args = ["1=1"], []
    if since: ev_cl.append("ts >= ?"); ev_args.append(since)
    if until: ev_cl.append("ts <= ?"); ev_args.append(until)
    if source: ev_cl.append("source = ?"); ev_args.append(source)
    if ingestion_id is not None: ev_cl.append("ingestion_id = ?"); ev_args.append(ingestion_id)
    ev_where = " AND ".join(ev_cl)
    d_cl, d_args = ["1=1"], []
    if since: d_cl.append("ts >= ?"); d_args.append(since)
    if until: d_cl.append("ts <= ?"); d_args.append(until)
    if severity: d_cl.append("severity = ?"); d_args.append(severity)
    if category: d_cl.append("rule_id = ?"); d_args.append(category)
    if ingestion_id is not None: d_cl.append("ingestion_id = ?"); d_args.append(ingestion_id)
    d_where = " AND ".join(d_cl)
    q1 = lambda sql, a=(): db.execute(sql, list(a)).fetchone()[0]

    total_events = q1("SELECT COUNT(*) FROM events")
    span = db.execute(f"SELECT MIN(ts) a, MAX(ts) b FROM events WHERE {ev_where}", ev_args).fetchone()
    # bucket by hour if the span is under 3 days, else by day
    from datetime import datetime
    fmt = "%Y-%m-%dT%H:00:00Z"
    if span["a"]:
        a, b = (datetime.strptime(x, "%Y-%m-%dT%H:%M:%SZ") for x in (span["a"], span["b"]))
        if (b - a).days >= 3:
            fmt = "%Y-%m-%dT00:00:00Z"
    sqlfmt = "%Y-%m-%dT%H:00:00Z" if fmt.endswith("%H:00:00Z") else "%Y-%m-%dT00:00:00Z"

    def top(col, where=ev_where, args=ev_args, extra=""):
        return [{"value": r["v"], "count": r["n"]} for r in db.execute(
            f"SELECT {col} v, COUNT(*) n FROM events WHERE {where} AND {col} IS NOT NULL {extra} GROUP BY {col} ORDER BY n DESC LIMIT 8", args)]

    ingestions = [dict(r) for r in db.execute("SELECT id, filename, format, is_sample, stored_records, failed_records, created_at FROM ingestions ORDER BY id DESC LIMIT 5")]
    for i in ingestions:
        i["is_sample"] = bool(i["is_sample"])
    return {
        "has_data": total_events > 0,
        "data_range": {"min": q1("SELECT MIN(ts) FROM events"), "max": q1("SELECT MAX(ts) FROM events")},
        "totals": {
            "events_ingested": total_events,
            "events_in_period": q1(f"SELECT COUNT(*) FROM events WHERE {ev_where}", ev_args),
            "active_investigations": q1("SELECT (SELECT COUNT(*) FROM cases WHERE status != 'closed') + (SELECT COUNT(*) FROM hunts WHERE status != 'concluded')"),
            "open_detections": q1(f"SELECT COUNT(*) FROM detections WHERE status IN ('open','investigating') AND {d_where}", d_args),
            "high_critical": q1(f"SELECT COUNT(*) FROM detections WHERE severity IN ('high','critical') AND status IN ('open','investigating') AND {d_where}", d_args),
            "total_detections": q1(f"SELECT COUNT(*) FROM detections WHERE {d_where}", d_args),
        },
        "detections_over_time": [dict(r) for r in db.execute(
            f"SELECT strftime('{sqlfmt}', ts) bucket, severity, COUNT(*) n FROM detections WHERE {d_where} GROUP BY bucket, severity ORDER BY bucket", d_args)],
        "events_over_time": [dict(r) for r in db.execute(
            f"SELECT strftime('{sqlfmt}', ts) bucket, COUNT(*) n FROM events WHERE {ev_where} GROUP BY bucket ORDER BY bucket", ev_args)],
        "top_detection_types": [dict(r) for r in db.execute(
            f"SELECT rule_id, COUNT(*) n FROM detections WHERE {d_where} GROUP BY rule_id ORDER BY n DESC LIMIT 8", d_args)],
        "top_source_ips": top("src_ip"),
        "top_users": top("username"),
        "top_hosts": top("hostname"),
        "recent_events": [event_dict(r) for r in db.execute(
            f"SELECT {LIST_COLS} FROM events WHERE {ev_where} ORDER BY ts DESC, id DESC LIMIT 8", ev_args)],
        "recent_activity": [dict(r) for r in db.execute("SELECT * FROM activity ORDER BY id DESC LIMIT 10")],
        "ingestions": ingestions,
        "sources": [r[0] for r in db.execute("SELECT DISTINCT source FROM events WHERE source IS NOT NULL ORDER BY source")],
        "failed_records_total": q1("SELECT COALESCE(SUM(failed_records),0) FROM ingestions"),
    }
