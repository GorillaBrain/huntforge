"""Log parsing and normalisation. Missing fields remain NULL; nothing is fabricated."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone

from .core import now_iso, settings, record_activity

SUPPORTED_FORMATS = ["jsonl", "json", "syslog-auth"]

ALIASES = {
    "ts": ["timestamp", "@timestamp", "time", "ts", "datetime", "eventtime"],
    "source": ["source", "event_source", "log_source", "sourcetype", "provider"],
    "event_type": ["event_type", "eventtype", "event.action", "action", "type", "category"],
    "outcome": ["outcome", "result", "status", "event.outcome"],
    "severity": ["severity", "level", "priority"],
    "src_ip": ["src_ip", "source_ip", "srcip", "src", "client_ip", "ip", "source.ip", "ipaddress"],
    "dst_ip": ["dst_ip", "dest_ip", "destination_ip", "dstip", "dst", "destination.ip"],
    "dst_port": ["dst_port", "dest_port", "destination_port", "dstport", "port", "destination.port"],
    "username": ["username", "user", "user_name", "account", "user.name", "targetusername"],
    "hostname": ["hostname", "host", "computer", "host.name", "computername", "device"],
    "process_name": ["process_name", "process", "image", "process.name", "new_process_name"],
    "parent_process": ["parent_process", "parent_image", "parent", "process.parent.name", "parentprocessname"],
    "command_line": ["command_line", "commandline", "cmdline", "process.command_line", "command"],
    "domain": ["domain", "dns_query", "query", "dns.question.name", "url_domain"],
    "bytes_out": ["bytes_out", "bytes_sent", "sentbytes", "network.bytes", "bytes"],
    "country": ["country", "geo_country", "src_country", "source.geo.country_iso_code"],
    "message": ["message", "msg", "description"],
}

EVENT_TYPE_MAP = {
    "login": "authentication", "logon": "authentication", "auth": "authentication",
    "authentication": "authentication", "process_creation": "process_create", "process": "process_create",
    "process_create": "process_create", "network": "network_connection", "connection": "network_connection",
    "network_connection": "network_connection", "dns": "dns_query", "dns_query": "dns_query",
    "user_created": "account_created", "account_created": "account_created",
    "group_add": "group_member_added", "group_member_added": "group_member_added",
    "persistence": "persistence", "scheduled_task_created": "persistence", "service_installed": "persistence",
}
OUTCOME_MAP = {
    "failure": "failure", "failed": "failure", "fail": "failure", "denied": "failure", "error": "failure",
    "success": "success", "succeeded": "success", "ok": "success", "allowed": "success", "accepted": "success",
}
SEV_MAP = {"info": "informational", "informational": "informational", "low": "low", "medium": "medium",
           "warning": "medium", "high": "high", "critical": "critical", "error": "high"}

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$")


class ParseError(ValueError):
    pass


def _get(d: dict, keys: list[str]):
    lower = {k.lower(): v for k, v in d.items() if isinstance(k, str)}
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
        v = lower.get(k.lower())
        if v not in (None, ""):
            return v
        # nested dotted path e.g. event.action
        if "." in k:
            cur = d
            for part in k.split("."):
                cur = cur.get(part) if isinstance(cur, dict) else None
            if cur not in (None, ""):
                return cur
    return None


def _clip(v, n=2000):
    if v is None:
        return None
    return str(v)[:n]


def parse_ts(v) -> str:
    if v is None:
        raise ParseError("missing timestamp")
    if isinstance(v, (int, float)) or (isinstance(v, str) and re.fullmatch(r"\d{9,13}(\.\d+)?", v)):
        n = float(v)
        if n > 1e11:
            n /= 1000
        return datetime.fromtimestamp(n, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    s = str(v).strip().replace(" ", "T", 1) if re.match(r"\d{4}-\d{2}-\d{2} ", str(v).strip()) else str(v).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        raise ParseError(f"unparseable timestamp {str(v)[:40]!r}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _valid_ip(v):
    if v is None:
        return None
    s = str(v).strip()
    if IP_RE.match(s) and len(s) <= 45:
        if "." in s and any(int(p) > 255 for p in s.split(".") if p.isdigit()):
            return None
        return s
    return None


def _int(v):
    try:
        return int(float(v)) if v is not None else None
    except (TypeError, ValueError):
        return None


def normalize(rec: dict) -> dict:
    """Map an arbitrary dict into the normalised event schema. Raises ParseError if unusable."""
    if not isinstance(rec, dict):
        raise ParseError("record is not an object")
    out = {k: _get(rec, a) for k, a in ALIASES.items()}
    out["ts"] = parse_ts(out["ts"])
    et = out["event_type"]
    if et is not None:
        et = EVENT_TYPE_MAP.get(str(et).lower(), str(et).lower())[:64]
    out["event_type"] = et
    oc = out["outcome"]
    out["outcome"] = OUTCOME_MAP.get(str(oc).lower(), str(oc).lower()[:32]) if oc is not None else None
    sv = out["severity"]
    out["severity"] = SEV_MAP.get(str(sv).lower()) if sv is not None else None
    out["src_ip"] = _valid_ip(out["src_ip"])
    out["dst_ip"] = _valid_ip(out["dst_ip"])
    out["dst_port"] = _int(out["dst_port"])
    out["bytes_out"] = _int(out["bytes_out"])
    for k in ("source", "username", "hostname", "process_name", "parent_process", "domain", "country"):
        out[k] = _clip(out[k], 256)
    if out["domain"]:
        out["domain"] = out["domain"].lower()
    out["command_line"] = _clip(out["command_line"], 4000)
    out["message"] = _clip(out["message"], 2000)
    out["raw"] = json.dumps(rec, default=str, ensure_ascii=False)[:20000]
    return out


SSH_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<res>Failed|Accepted)\s+(?P<method>\S+)\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)
MONTHS = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}


def parse_syslog_line(line: str, year: int) -> dict:
    m = SSH_RE.match(line)
    if not m:
        raise ParseError("line is not a recognised sshd authentication entry")
    ts = datetime(year, MONTHS[m["mon"]], int(m["day"]), *map(int, m["time"].split(":")), tzinfo=timezone.utc)
    return {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "source": "sshd", "event_type": "authentication",
        "outcome": "failure" if m["res"] == "Failed" else "success", "src_ip": m["ip"], "username": m["user"],
        "hostname": m["host"], "message": line[:500],
    }


def detect_format(filename: str, text: str) -> str:
    stripped = text.lstrip()
    if stripped.startswith("["):
        return "json"
    first = next((l for l in text.splitlines() if l.strip()), "")
    if first.startswith("{"):
        return "jsonl"
    if SSH_RE.match(first):
        return "syslog-auth"
    raise ParseError("Unsupported or unrecognised format. Supported: " + ", ".join(SUPPORTED_FORMATS))


def parse_records(text: str, fmt: str):
    """Yield (index, dict|None, error|None)."""
    if fmt == "json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise ParseError(f"Malformed JSON: {e.msg} (line {e.lineno})")
        if not isinstance(data, list):
            raise ParseError("JSON file must contain an array of event objects")
        for i, r in enumerate(data):
            yield i, r, None
    elif fmt == "jsonl":
        for i, line in enumerate(text.splitlines()):
            if not line.strip():
                continue
            try:
                yield i, json.loads(line), None
            except json.JSONDecodeError as e:
                yield i, None, f"line {i + 1}: malformed JSON ({e.msg})"
    elif fmt == "syslog-auth":
        year = datetime.now(timezone.utc).year
        for i, line in enumerate(text.splitlines()):
            if not line.strip():
                continue
            try:
                yield i, parse_syslog_line(line, year), None
            except ParseError as e:
                yield i, None, f"line {i + 1}: {e}"
    else:
        raise ParseError("Unsupported format")


COLS = ["ingestion_id", "ts", "source", "event_type", "outcome", "severity", "src_ip", "dst_ip", "dst_port",
        "username", "hostname", "process_name", "parent_process", "command_line", "domain", "bytes_out",
        "country", "message", "raw"]


class DuplicateIngestion(Exception):
    def __init__(self, ingestion_id: int):
        self.ingestion_id = ingestion_id


def ingest_bytes(conn: sqlite3.Connection, filename: str, data: bytes, is_sample: bool = False,
                 fmt: str | None = None) -> dict:
    if len(data) > settings.max_upload_bytes:
        raise ParseError(f"File exceeds the {settings.max_upload_bytes // (1024 * 1024)} MB limit")
    if not data.strip():
        raise ParseError("File is empty")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ParseError("File is not valid UTF-8 text")
    if "\x00" in text:
        raise ParseError("Binary content detected; only text logs are supported")
    sha = hashlib.sha256(data).hexdigest()
    dup = conn.execute("SELECT id FROM ingestions WHERE sha256=?", (sha,)).fetchone()
    if dup:
        raise DuplicateIngestion(dup["id"])
    fmt = fmt or detect_format(filename, text)

    rows, errors, failed, total = [], [], 0, 0
    # Parse fully before touching the database so a bad file never leaves partial data.
    for _, rec, err in parse_records(text, fmt):
        total += 1
        if total > settings.max_events_per_upload:
            raise ParseError(f"File exceeds the {settings.max_events_per_upload} event limit")
        if err:
            failed += 1
            if len(errors) < 20:
                errors.append(err)
            continue
        try:
            rows.append(normalize(rec))
        except ParseError as e:
            failed += 1
            if len(errors) < 20:
                errors.append(f"record {total}: {e}")
    if total and not rows:
        raise ParseError("No valid events found. First errors: " + "; ".join(errors[:3]))

    cur = conn.execute(
        "INSERT INTO ingestions (filename, format, sha256, is_sample, total_records, stored_records, failed_records,"
        " skipped_records, errors, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (filename[:200], fmt, sha, int(is_sample), total, len(rows), failed, 0, json.dumps(errors), now_iso()),
    )
    ing_id = cur.lastrowid
    conn.executemany(
        f"INSERT INTO events ({','.join(COLS)}) VALUES ({','.join('?' * len(COLS))})",
        [[ing_id] + [r[c] for c in COLS[1:]] for r in rows],
    )
    record_activity(conn, "ingested", "ingestion", str(ing_id), f"{filename}: {len(rows)} events stored, {failed} failed")
    conn.commit()
    return {"id": ing_id, "filename": filename, "format": fmt, "total_records": total,
            "stored_records": len(rows), "failed_records": failed, "skipped_records": 0, "errors": errors}
