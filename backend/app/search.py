"""Shared event search: structured filters + HQL, always parameterised."""
from __future__ import annotations

from .query import compile_query

SORTABLE = {"ts", "event_type", "severity", "username", "hostname", "src_ip", "dst_ip", "source", "outcome", "id"}
EXACT_FILTERS = ["event_type", "outcome", "severity", "username", "hostname", "src_ip", "dst_ip", "source", "country", "domain"]
LIST_COLS = ("id, ingestion_id, ts, source, event_type, outcome, severity, src_ip, dst_ip, dst_port, username, hostname, "
             "process_name, parent_process, command_line, domain, bytes_out, country, message")


def build_where(q=None, since=None, until=None, ingestion_id=None, **filters) -> tuple[str, list]:
    clauses, args = [], []
    if q:
        sql, a = compile_query(q)
        clauses.append(sql)
        args += a
    for k in EXACT_FILTERS:
        v = filters.get(k)
        if v not in (None, ""):
            clauses.append(f"{k} = ? COLLATE NOCASE")
            args.append(v)
    if since:
        clauses.append("ts >= ?")
        args.append(since)
    if until:
        clauses.append("ts <= ?")
        args.append(until)
    if ingestion_id is not None:
        clauses.append("ingestion_id = ?")
        args.append(ingestion_id)
    return (" AND ".join(clauses) or "1=1"), args


def event_dict(r, with_raw=False) -> dict:
    d = {k: r[k] for k in r.keys() if k != "raw"}
    d["ref"] = f"EVT-{r['id']}"
    if with_raw:
        d["raw"] = r["raw"]
    return d
