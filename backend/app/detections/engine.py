"""Run rules, persist findings idempotently (deduplicated by rule + grouping key)."""
from __future__ import annotations

import hashlib
import json
import sqlite3

from ..core import now_iso, record_activity, jloads
from .rules import CATALOG, Finding, RuleDef


def rule_state(conn: sqlite3.Connection, rule: RuleDef) -> dict:
    row = conn.execute("SELECT enabled, params FROM rules WHERE id=?", (rule.id,)).fetchone()
    params = dict(rule.params)
    if row:
        params.update(jloads(row["params"], {}))
    return {"enabled": bool(row["enabled"]) if row else True, "params": params}


def detection_id(rule_id: str, key: str, ing: int | None) -> str:
    h = hashlib.sha256(f"{rule_id}|{key}|{ing}".encode()).hexdigest()[:8].upper()
    return f"DET-{h}"


def execute(conn: sqlite3.Connection, rule: RuleDef, ing: int | None, params: dict | None = None) -> list[Finding]:
    p = params if params is not None else rule_state(conn, rule)["params"]
    findings = rule.fn(conn, p, ing)
    findings.sort(key=lambda f: (f.ts, f.key))
    return findings


def finding_row(f: Finding, ing: int | None) -> dict:
    return {"id": detection_id(f.rule_id, f.key, ing), "rule_id": f.rule_id, "severity": f.severity,
            "confidence": f.confidence, "ts": f.ts, "entity_type": f.entity_type, "entity_value": f.entity_value,
            "title": f.title, "explanation": f.explanation, "evidence": f.evidence, "event_ids": f.event_ids}


def run_all(conn: sqlite3.Connection, ing: int | None = None, rule_ids: list[str] | None = None) -> dict:
    """Run enabled rules. Detection runs are scoped per ingestion (dataset); ing=None runs every dataset."""
    if ing is None:
        total = {"created": 0, "refreshed": 0, "per_rule": {}}
        for r in conn.execute("SELECT id FROM ingestions ORDER BY id").fetchall():
            res = run_all(conn, r["id"], rule_ids)
            total["created"] += res["created"]
            total["refreshed"] += res["refreshed"]
            for k, v in res["per_rule"].items():
                total["per_rule"][k] = total["per_rule"].get(k, 0) + v
        return total
    created = updated = 0
    per_rule: dict[str, int] = {}
    for rule in CATALOG:
        if rule_ids and rule.id not in rule_ids:
            continue
        if not rule_state(conn, rule)["enabled"]:
            per_rule[rule.id] = 0
            continue
        fs = execute(conn, rule, ing)
        per_rule[rule.id] = len(fs)
        for f in fs:
            r = finding_row(f, ing)
            exists = conn.execute("SELECT 1 FROM detections WHERE dedupe_key=?", (f"{f.rule_id}|{f.key}|{ing}",)).fetchone()
            ts = now_iso()
            if exists:
                # Refresh facts but keep analyst-controlled status and case link.
                conn.execute("UPDATE detections SET severity=?, confidence=?, ts=?, title=?, explanation=?, evidence=?, event_ids=?, updated_at=? WHERE dedupe_key=?",
                             (r["severity"], r["confidence"], r["ts"], r["title"], r["explanation"], json.dumps(r["evidence"]),
                              json.dumps(r["event_ids"]), ts, f"{f.rule_id}|{f.key}|{ing}"))
                updated += 1
            else:
                conn.execute("INSERT INTO detections (id, dedupe_key, rule_id, ingestion_id, severity, confidence, ts, entity_type, entity_value,"
                             " title, explanation, evidence, event_ids, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'open',?,?)",
                             (r["id"], f"{f.rule_id}|{f.key}|{ing}", r["rule_id"], ing, r["severity"], r["confidence"], r["ts"],
                              r["entity_type"], r["entity_value"], r["title"], r["explanation"], json.dumps(r["evidence"]),
                              json.dumps(r["event_ids"]), ts, ts))
                created += 1
    record_activity(conn, "detections_run", "ingestion", str(ing) if ing else "all", f"{created} new, {updated} refreshed")
    conn.commit()
    return {"created": created, "refreshed": updated, "per_rule": per_rule}
