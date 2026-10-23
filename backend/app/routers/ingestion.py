from __future__ import annotations

import json
import sqlite3

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import Response

from ..core import get_db, record_activity, settings
from ..detections import engine
from ..ingest import DuplicateIngestion, ParseError, SUPPORTED_FORMATS, ingest_bytes
from ..sample import generator

router = APIRouter(prefix="/api/ingestion", tags=["ingestion"])

TABLES_TO_WIPE = ["activity", "saved_searches", "hunt_items", "hunts", "case_items", "cases", "detections", "events", "ingestions", "rules"]


def _ing_dict(r):
    d = dict(r)
    d["errors"] = json.loads(d["errors"] or "[]")
    d["is_sample"] = bool(d["is_sample"])
    return d


@router.get("")
def list_ingestions(db: sqlite3.Connection = Depends(get_db)):
    return {"items": [_ing_dict(r) for r in db.execute("SELECT * FROM ingestions ORDER BY id DESC")],
            "supported_formats": SUPPORTED_FORMATS, "max_upload_mb": settings.max_upload_bytes // (1024 * 1024)}


@router.post("/upload", status_code=201)
async def upload(file: UploadFile = File(...), run_detections: bool = True, db: sqlite3.Connection = Depends(get_db)):
    data = await file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(413, f"File exceeds the {settings.max_upload_bytes // (1024 * 1024)} MB limit")
    try:
        res = ingest_bytes(db, (file.filename or "upload").split("/")[-1].split("\\")[-1], data)
    except DuplicateIngestion as d:
        raise HTTPException(409, f"This exact file was already ingested (ingestion #{d.ingestion_id}).")
    except ParseError as e:
        raise HTTPException(422, str(e))
    if run_detections:
        res["detections"] = engine.run_all(db, res["id"])
    return res


@router.post("/sample", status_code=201)
def load_sample(db: sqlite3.Connection = Depends(get_db)):
    """Load the clearly-labelled SYNTHETIC sample dataset and run detections on it."""
    try:
        res = ingest_bytes(db, "huntforge-sample.jsonl (SYNTHETIC)", generator.to_jsonl(), is_sample=True)
    except DuplicateIngestion as d:
        raise HTTPException(409, f"Sample dataset is already loaded (ingestion #{d.ingestion_id}).")
    res["detections"] = engine.run_all(db, res["id"])
    return res


@router.get("/sample/download")
def download_sample():
    return Response(generator.to_jsonl(), media_type="application/x-ndjson",
                    headers={"Content-Disposition": 'attachment; filename="huntforge-sample.jsonl"'})


@router.delete("/{ingestion_id}", status_code=204)
def delete_ingestion(ingestion_id: int, db: sqlite3.Connection = Depends(get_db)):
    if not db.execute("SELECT 1 FROM ingestions WHERE id=?", (ingestion_id,)).fetchone():
        raise HTTPException(404, "Ingestion not found")
    # Detections linked to a case are kept as case evidence snapshots; the live rows go with the data.
    db.execute("DELETE FROM ingestions WHERE id=?", (ingestion_id,))
    record_activity(db, "ingestion_deleted", "ingestion", str(ingestion_id))
    db.commit()


@router.post("/reset")
def reset(confirm: str = "", db: sqlite3.Connection = Depends(get_db)):
    """Wipe all data (demo reset). Requires ?confirm=RESET."""
    if confirm != "RESET":
        raise HTTPException(400, "Pass confirm=RESET to wipe all data")
    for t in TABLES_TO_WIPE:
        db.execute(f"DELETE FROM {t}")
    db.commit()
    return {"status": "reset"}
