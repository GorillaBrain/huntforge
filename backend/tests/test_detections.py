from app.sample import generator


def _dets(client, **params):
    return client.get("/api/detections", params={"page_size": 100, **params}).json()


def test_expected_detections_on_sample(client, sample):
    items = _dets(client)["items"]
    found = {(d["rule_id"], d["entity_value"]) for d in items}
    for e in generator.EXPECTED:
        assert (e["rule_id"], e["entity_value"]) in found, e
    for e in generator.EXPECTED_ABSENT:
        assert (e["rule_id"], e["entity_value"]) not in found, e


def test_rule_test_endpoint_passes_for_all(client, sample):
    for r in client.get("/api/rules").json():
        t = client.get(f"/api/rules/{r['id']}/test").json()
        assert t["available"] and t["passed"], (r["id"], t)


def test_detections_reproducible_and_deduplicated(client, sample):
    first = sorted(d["id"] for d in _dets(client)["items"])
    res = client.post("/api/detections/run").json()
    assert res["created"] == 0 and res["refreshed"] == len(first)
    assert sorted(d["id"] for d in _dets(client)["items"]) == first


def test_severity_and_confidence_are_separate(client, sample):
    items = _dets(client)["items"]
    assert all(0 <= d["confidence"] <= 1 for d in items)
    assert len({(d["severity"], d["confidence"]) for d in items}) > 3
    assert len({d["confidence"] for d in items}) > 2


def test_findings_trace_to_events(client, sample):
    d = _dets(client, rule_id="HF-002")["items"][0]
    detail = client.get(f"/api/detections/{d['id']}").json()
    assert detail["events"] and len(detail["events"]) == len(detail["event_ids"])
    assert any(e["outcome"] == "success" for e in detail["events"])
    assert detail["recommended_steps"] and "not a confirmed attack" in detail["note"]
    assert detail["evidence"]["account_was_targeted"] is True


def test_status_change_persists_and_survives_rerun(client, sample):
    d = _dets(client)["items"][0]
    assert client.patch(f"/api/detections/{d['id']}", json={"status": "false_positive"}).status_code == 200
    client.post("/api/detections/run")
    assert client.get(f"/api/detections/{d['id']}").json()["status"] == "false_positive"
    assert client.patch(f"/api/detections/{d['id']}", json={"status": "bogus"}).status_code == 422


def test_disable_rule_and_params(client, sample):
    assert client.patch("/api/rules/HF-001", json={"params": {"threshold": 100}}).json()["params"]["threshold"] == 100
    r = client.post("/api/rules/HF-001/run", params={"ingestion_id": sample["id"]}).json()
    assert r["match_count"] == 0
    assert client.patch("/api/rules/HF-001", json={"params": {"nope": 1}}).status_code == 422
    assert client.patch("/api/rules/HF-001", json={"params": {"threshold": "x"}}).status_code == 422
    client.patch("/api/rules/HF-001", json={"enabled": False, "params": {"threshold": 10}})
    assert client.get("/api/rules/HF-001").json()["enabled"] is False


def test_negative_control_not_flagged_by_threshold_rule(client, sample):
    r = client.post("/api/rules/HF-001/run", params={"ingestion_id": sample["id"]}).json()
    assert {m["entity_value"] for m in r["matches"]} == {"203.0.113.45"}
