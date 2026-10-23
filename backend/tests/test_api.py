def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_overview_empty_then_populated(client):
    o = client.get("/api/overview").json()
    assert o["has_data"] is False and o["totals"]["events_ingested"] == 0
    client.post("/api/ingestion/sample")
    o = client.get("/api/overview").json()
    assert o["has_data"] and o["totals"]["events_ingested"] > 300 and o["totals"]["total_detections"] >= 8
    assert o["top_source_ips"] and o["top_detection_types"] and o["detections_over_time"]
    f = client.get("/api/overview", params={"severity": "critical"}).json()
    assert f["totals"]["total_detections"] < o["totals"]["total_detections"]


def test_workflow_hunt_to_case_to_report_with_persistence(client, sample):
    det = client.get("/api/detections", params={"rule_id": "HF-002"}).json()["items"][0]
    # Start a hunt from the finding
    hunt = client.post("/api/hunts", json={"title": "Admin compromise?", "detection_id": det["id"]}).json()
    assert hunt["query"] and hunt["hypothesis"]
    evs = client.get(f"/api/hunts/{hunt['id']}/events").json()
    assert evs["total"] > 0
    # hypothesis, notes, alternative, evidence
    client.patch(f"/api/hunts/{hunt['id']}", json={"hypothesis": "Credential guessing succeeded"})
    client.post(f"/api/hunts/{hunt['id']}/items", json={"kind": "note", "body": "Failures stopped after success"})
    client.post(f"/api/hunts/{hunt['id']}/items", json={"kind": "alternative", "body": "Admin typo from new VPN"})
    h = client.post(f"/api/hunts/{hunt['id']}/items", json={"kind": "evidence", "event_id": evs["items"][0]["id"], "body": "first hit"}).json()
    assert h["status"] == "in_progress" and any(p["done"] for p in h["progress"])
    assert client.post(f"/api/hunts/{hunt['id']}/items", json={"kind": "note", "body": "  "}).status_code == 422
    # promote to case
    case_id = client.post(f"/api/hunts/{hunt['id']}/case").json()["case_id"]
    assert client.post(f"/api/hunts/{hunt['id']}/case").json() == {"case_id": case_id, "created": False}
    client.patch(f"/api/cases/{case_id}", json={"conclusion": "Likely compromise of admin", "uncertainty": "Source IP ownership unknown",
                                               "recommendations": "Reset admin credentials", "assignee": "analyst1"})
    client.post(f"/api/cases/{case_id}/items", json={"kind": "note", "body": "Contacted owner"})
    # "refresh": a brand new request reads persisted data
    c = client.get(f"/api/cases/{case_id}").json()
    assert c["conclusion"] == "Likely compromise of admin" and c["assignee"] == "analyst1"
    assert c["item_counts"]["evidence"] >= 15 and c["item_counts"]["detection"] == 1 and c["timeline"]
    assert client.get(f"/api/detections/{det['id']}").json()["case_id"] == case_id
    assert client.get(f"/api/hunts/{hunt['id']}").json()["case_id"] == case_id
    # report reflects the real data
    md = client.get(f"/api/reports/cases/{case_id}", params={"format": "markdown"}).text
    for needle in ["Likely compromise of admin", "Source IP ownership unknown", det["id"], "203.0.113.45", "Contacted owner", "Reset admin credentials"]:
        assert needle in md, needle
    j = client.get(f"/api/reports/cases/{case_id}").json()
    assert j["scope"]["event_count"] == c["item_counts"]["evidence"]


def test_case_validation_and_report_escaping(client, sample):
    assert client.post("/api/cases", json={"title": ""}).status_code == 422
    assert client.post("/api/cases", json={"title": "x", "severity": "huge"}).status_code == 422
    assert client.post("/api/cases", json={"title": "x", "detection_id": "DET-NOPE"}).status_code == 404
    cid = client.post("/api/cases", json={"title": "<img src=x onerror=alert(1)>"}).json()["id"]
    client.patch(f"/api/cases/{cid}", json={"conclusion": "<script>alert(1)</script>"})
    html = client.get(f"/api/reports/cases/{cid}", params={"format": "html"})
    assert "<script>alert" not in html.text and "&lt;script&gt;" in html.text
    assert "default-src 'none'" in html.headers["content-security-policy"]
    assert client.get("/api/cases/CASE-9999").status_code == 404


def test_evidence_survives_dataset_deletion(client, sample):
    det = client.get("/api/detections", params={"rule_id": "HF-005"}).json()["items"][0]
    cid = client.post("/api/cases", json={"title": "c", "detection_id": det["id"]}).json()["id"]
    client.delete(f"/api/ingestion/{sample['id']}")
    c = client.get(f"/api/cases/{cid}").json()
    assert c["item_counts"]["evidence"] > 0 and all(i["snapshot"] for i in c["items"])


def test_entities_and_graph(client, sample):
    e = client.get("/api/entities/ip/203.0.113.45").json()
    assert e["observed"]["event_count"] == 15 and e["detections"]
    assert "does not indicate this entity is safe" in e["external_intelligence"]["note"]
    assert any(r["value"] == "admin" for r in e["observed"]["related"]["user"])
    assert client.get("/api/entities/user/nobody-here").status_code == 404
    assert client.get("/api/entities/bogus/x").status_code == 404
    s = client.get("/api/entities", params={"type": "host", "q": "web"}).json()["items"]
    assert [x["value"] for x in s] == ["SRV-WEB01"]
    g = client.get("/api/graph", params={"q": "host = SRV-WEB01"}).json()
    ids = {n["id"] for n in g["nodes"]}
    assert "host:SRV-WEB01" in ids and "ip:203.0.113.99" in ids
    assert all(e["source"] in ids and e["target"] in ids and e["event_ids"] for e in g["edges"])


def test_reset_requires_confirmation(client, sample):
    assert client.post("/api/ingestion/reset").status_code == 400
    assert client.post("/api/ingestion/reset", params={"confirm": "RESET"}).status_code == 200
    assert client.get("/api/overview").json()["has_data"] is False


def test_cors_and_rate_limit(client, monkeypatch):
    r = client.get("/api/health", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in r.headers
    r = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"
    monkeypatch.setenv("HUNTFORGE_RATE_LIMIT", "1")
    from app import main
    main._hits.clear()
    codes = [client.get("/api/health").status_code for _ in range(3)]
    assert 429 in codes


def test_migrations_idempotent(client):
    from app.core import migrate
    assert migrate() == []
