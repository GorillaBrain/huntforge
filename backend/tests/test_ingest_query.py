import io
import json

from app.query import QueryError, compile_query
import pytest


# ---------------- query language ----------------
def test_query_basic_and_or():
    sql, args = compile_query('user = alice AND (outcome = failure OR outcome = success)')
    assert "AND" in sql and "OR" in sql and args == ["alice", "failure", "success"]


def test_query_injection_is_parameterised():
    sql, args = compile_query('user = "x\' OR 1=1; DROP TABLE events; --"')
    assert "DROP" not in sql and "OR 1=1" not in sql
    assert "DROP TABLE events" in args[0]


def test_query_free_text_and_not():
    sql, args = compile_query('powershell NOT host = WS-BOB')
    assert "NOT" in sql and "%powershell%" in args


@pytest.mark.parametrize("bad", ["nofield >", "(user = a", "user = a)", "bogus = 1", "dst_port = abc", "AND"])
def test_query_errors(bad):
    with pytest.raises(QueryError):
        compile_query(bad)


# ---------------- ingestion ----------------
def test_sample_loads_and_is_searchable(client, sample):
    assert sample["stored_records"] > 300 and sample["failed_records"] == 0
    r = client.get("/api/events", params={"q": "src_ip = 203.0.113.45 AND outcome = failure"})
    assert r.json()["total"] == 14


def test_duplicate_upload_rejected(client, sample):
    r = client.post("/api/ingestion/sample")
    assert r.status_code == 409


def test_malformed_input_rejected_and_data_intact(client, sample):
    before = client.get("/api/events").json()["total"]
    for name, content in [("a.jsonl", b"{not json}\n{also bad"), ("b.json", b"[1, 2"), ("c.txt", b"hello world"), ("d.jsonl", b""),
                          ("e.jsonl", b"\x00\x01\x02\xff\xfe")]:
        r = client.post("/api/ingestion/upload", files={"file": (name, io.BytesIO(content))})
        assert r.status_code == 422, (name, r.text)
        assert r.json()["detail"]
    assert client.get("/api/events").json()["total"] == before


def test_partial_failures_reported(client):
    data = b'{"timestamp":"2025-01-01T00:00:00Z","event_type":"login","outcome":"failed","user":"x","src_ip":"1.2.3.4"}\n' \
           b'{"no_timestamp": true}\nnot json\n'
    r = client.post("/api/ingestion/upload", files={"file": ("p.jsonl", io.BytesIO(data))})
    assert r.status_code == 201
    j = r.json()
    assert j["stored_records"] == 1 and j["failed_records"] == 2 and len(j["errors"]) == 2
    e = client.get("/api/events").json()["items"][0]
    assert e["event_type"] == "authentication" and e["outcome"] == "failure" and e["username"] == "x"
    assert e["dst_ip"] is None  # missing stays missing


def test_oversize_upload_rejected(client, monkeypatch):
    monkeypatch.setenv("HUNTFORGE_MAX_UPLOAD_MB", "0.001")
    r = client.post("/api/ingestion/upload", files={"file": ("big.jsonl", io.BytesIO(b"x" * 5000))})
    assert r.status_code in (413, 422)


def test_syslog_format(client):
    line = b"Mar  3 10:00:01 host1 sshd[123]: Failed password for invalid user bob from 198.51.100.4 port 2222 ssh2\n"
    r = client.post("/api/ingestion/upload", files={"file": ("auth.log", io.BytesIO(line))})
    assert r.status_code == 201 and r.json()["format"] == "syslog-auth"
    e = client.get("/api/events", params={"username": "bob"}).json()["items"][0]
    assert e["src_ip"] == "198.51.100.4" and e["outcome"] == "failure"


# ---------------- events API ----------------
def test_pagination_sort_filter(client, sample):
    p1 = client.get("/api/events", params={"page_size": 10, "sort": "ts", "order": "asc"}).json()
    p2 = client.get("/api/events", params={"page_size": 10, "page": 2, "sort": "ts", "order": "asc"}).json()
    assert len(p1["items"]) == 10 and p1["items"][-1]["ts"] <= p2["items"][0]["ts"]
    assert client.get("/api/events", params={"sort": "raw; DROP"}).status_code == 400
    r = client.get("/api/events", params={"event_type": "persistence"}).json()
    assert r["total"] == 1


def test_bad_query_returns_400(client, sample):
    r = client.get("/api/events", params={"q": "(unclosed"})
    assert r.status_code == 400 and "Invalid query" in r.json()["detail"]


def test_event_detail_has_raw_and_xss_payload_is_data(client):
    payload = '<script>alert(1)</script>'
    line = json.dumps({"timestamp": "2025-01-01T00:00:00Z", "user": payload, "event_type": "login", "outcome": "success"}).encode()
    client.post("/api/ingestion/upload", files={"file": ("x.jsonl", io.BytesIO(line))})
    ev = client.get("/api/events").json()["items"][0]
    d = client.get(f"/api/events/{ev['id']}").json()
    assert d["username"] == payload and payload in d["raw"]


def test_csv_export_neutralises_formulas(client):
    line = json.dumps({"timestamp": "2025-01-01T00:00:00Z", "user": "=HYPERLINK(\"http://evil\")", "event_type": "login"}).encode()
    client.post("/api/ingestion/upload", files={"file": ("x.jsonl", io.BytesIO(line))})
    body = client.get("/api/events/export").text
    assert "'=HYPERLINK" in body and ",=HYPERLINK" not in body


def test_saved_searches_persist(client):
    assert client.post("/api/events/saved/searches", json={"name": "t", "query": "user = a"}).status_code == 201
    assert client.post("/api/events/saved/searches", json={"name": "t", "query": "(bad"}).status_code == 400
    assert len(client.get("/api/events/saved/searches").json()) == 1
