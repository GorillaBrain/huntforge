from __future__ import annotations

import json
import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..core import get_db, record_activity
from ..detections import engine
from ..detections.rules import BY_ID, CATALOG
from ..sample import generator

router = APIRouter(prefix="/api/rules", tags=["rules"])


def rule_dict(conn, r) -> dict:
    st = engine.rule_state(conn, r)
    n = conn.execute("SELECT COUNT(*) FROM detections WHERE rule_id=?", (r.id,)).fetchone()[0]
    return {"id": r.id, "name": r.name, "description": r.description, "technique": r.technique, "severity": r.severity,
            "logic": r.logic, "data_sources": r.data_sources, "false_positives": r.false_positives,
            "limitations": r.limitations, "recommended_steps": r.steps, "default_params": r.params,
            "params": st["params"], "enabled": st["enabled"], "detection_count": n}


@router.get("")
def list_rules(db: sqlite3.Connection = Depends(get_db)):
    return [rule_dict(db, r) for r in CATALOG]


@router.get("/{rule_id}")
def get_rule(rule_id: str, db: sqlite3.Connection = Depends(get_db)):
    r = BY_ID.get(rule_id)
    if not r:
        raise HTTPException(404, "Rule not found")
    return rule_dict(db, r)


class RuleUpdate(BaseModel):
    enabled: bool | None = None
    params: dict | None = None


def _validate_params(rule, params: dict) -> dict:
    out = {}
    for k, v in params.items():
        if k not in rule.params:
            raise HTTPException(422, f"Unknown parameter '{k}'. Allowed: {', '.join(rule.params) or 'none'}")
        d = rule.params[k]
        if isinstance(d, list):
            if not isinstance(v, list) or len(v) > 100 or not all(isinstance(x, type(d[0])) for x in v):
                raise HTTPException(422, f"Parameter '{k}' must be a list of {type(d[0]).__name__}")
        elif isinstance(d, (int, float)) and not isinstance(d, bool):
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0 or v > 10**10:
                raise HTTPException(422, f"Parameter '{k}' must be a positive number")
        out[k] = v
    return out


@router.patch("/{rule_id}")
def update_rule(rule_id: str, body: RuleUpdate, db: sqlite3.Connection = Depends(get_db)):
    r = BY_ID.get(rule_id)
    if not r:
        raise HTTPException(404, "Rule not found")
    st = engine.rule_state(db, r)
    enabled = st["enabled"] if body.enabled is None else body.enabled
    params = st["params"]
    if body.params is not None:
        params = {**params, **_validate_params(r, body.params)}
    db.execute("INSERT INTO rules (id, enabled, params) VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled, params=excluded.params",
               (rule_id, int(enabled), json.dumps(params)))
    record_activity(db, "rule_updated", "rule", rule_id, f"enabled={enabled}")
    db.commit()
    return rule_dict(db, r)


@router.post("/{rule_id}/run")
def run_rule(rule_id: str, ingestion_id: int | None = None, persist: bool = False, db: sqlite3.Connection = Depends(get_db)):
    """Run a rule against one dataset (or all). Dry-run by default: returns matches without storing them."""
    r = BY_ID.get(rule_id)
    if not r:
        raise HTTPException(404, "Rule not found")
    ids = [ingestion_id] if ingestion_id is not None else [x["id"] for x in db.execute("SELECT id FROM ingestions")]
    matches = []
    for ing in ids:
        for f in engine.execute(db, r, ing):
            row = engine.finding_row(f, ing)
            row["ingestion_id"] = ing
            matches.append(row)
    if persist:
        engine.run_all(db, ingestion_id, [rule_id])
    return {"rule_id": rule_id, "match_count": len(matches), "matches": matches, "persisted": persist}


@router.get("/{rule_id}/test")
def test_rule(rule_id: str, db: sqlite3.Connection = Depends(get_db)):
    """Compare a rule's output on the sample dataset with the documented expectations."""
    r = BY_ID.get(rule_id)
    if not r:
        raise HTTPException(404, "Rule not found")
    ing = db.execute("SELECT id FROM ingestions WHERE is_sample=1").fetchone()
    if not ing:
        return {"rule_id": rule_id, "available": False, "message": "Load the sample dataset to run the rule test."}
    found = {f.entity_value for f in engine.execute(db, r, ing["id"])}
    expected = [e["entity_value"] for e in generator.EXPECTED if e["rule_id"] == rule_id]
    absent = [e["entity_value"] for e in generator.EXPECTED_ABSENT if e["rule_id"] == rule_id]
    checks = [{"description": f"Detects {v}", "passed": v in found} for v in expected]
    checks += [{"description": f"Does not flag {v} (negative control)", "passed": v not in found} for v in absent]
    return {"rule_id": rule_id, "available": True, "passed": all(c["passed"] for c in checks),
            "checks": checks, "entities_found": sorted(found)}
