import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTFORGE_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("HUNTFORGE_RATE_LIMIT", "100000")
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def sample(client):
    r = client.post("/api/ingestion/sample")
    assert r.status_code == 201, r.text
    return r.json()
