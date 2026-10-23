"""HuntForge API application."""
from __future__ import annotations

import json
import logging
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .core import log, migrate, settings
from .ingest import ParseError
from .query import QueryError
from .routers import cases, detections, entities, events, hunts, ingestion, overview, reports, rules


class JsonFormatter(logging.Formatter):
    def format(self, record):
        d = {"ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"), "level": record.levelname, "msg": record.getMessage()}
        for k in ("method", "path", "status", "ms"):
            if hasattr(record, k):
                d[k] = getattr(record, k)
        if record.exc_info:
            d["exc"] = self.formatException(record.exc_info)
        return json.dumps(d)


def setup_logging():
    h = logging.StreamHandler()
    h.setFormatter(JsonFormatter())
    log.handlers[:] = [h]
    log.setLevel(settings.log_level)
    log.propagate = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    applied = migrate()
    log.info(f"database ready; migrations applied: {applied or 'none'}")
    yield


app = FastAPI(title="HuntForge API", version="2.0.0", lifespan=lifespan,
              description="Threat hunting and investigation workbench API. Interactive docs at /docs.")

app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["GET", "POST", "PATCH", "DELETE"],
                   allow_headers=["Content-Type"], allow_credentials=False)

_hits: dict[str, deque] = defaultdict(deque)


@app.middleware("http")
async def guard(request: Request, call_next):
    start = time.time()
    # Basic in-memory per-client rate limit; use an upstream proxy for real deployments.
    client = request.client.host if request.client else "unknown"
    q = _hits[client]
    now = time.time()
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= settings.rate_limit_per_minute:
        return JSONResponse({"detail": "Rate limit exceeded. Try again shortly."}, status_code=429)
    q.append(now)
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > settings.max_upload_bytes + 1_000_000:
        return JSONResponse({"detail": "Request body too large"}, status_code=413)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    log.info("request", extra={"method": request.method, "path": request.url.path, "status": response.status_code,
                               "ms": int((time.time() - start) * 1000)})
    return response


@app.exception_handler(QueryError)
async def query_error(_, exc: QueryError):
    return JSONResponse({"detail": f"Invalid query: {exc}"}, status_code=400)


@app.exception_handler(ParseError)
async def parse_error(_, exc: ParseError):
    return JSONResponse({"detail": str(exc)}, status_code=422)


@app.exception_handler(Exception)
async def unhandled(_, exc: Exception):
    log.exception("unhandled error")
    return JSONResponse({"detail": "Internal server error"}, status_code=500)


for r in (overview, events, ingestion, detections, rules, hunts, cases, entities, reports):
    app.include_router(r.router)
