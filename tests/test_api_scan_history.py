from fastapi.testclient import TestClient

from backend.api import app


client = TestClient(app)


def test_get_scan_history_by_id(monkeypatch):

    fake_history = [
        {
            "id": 1,
            "timestamp": "2026-10-08 10:00:00",
            "scanner": "nmap",
            "scan_type": "quick",
            "target": "scanme.nmap.org",
            "duration": 1.25,
            "findings": [],
            "status": "success"
        }
    ]

    def fake_get_history():
        return fake_history

    monkeypatch.setattr(
        "backend.api.scan_history.get_history",
        fake_get_history
    )

    response = client.get("/api/v1/history/1")

    assert response.status_code == 200

    data = response.json()

    assert "scan" in data
    assert data["scan"]["id"] == 1
    assert data["scan"]["scanner"] == "nmap"
    assert data["scan"]["scan_type"] == "quick"
    assert data["scan"]["target"] == "scanme.nmap.org"


def test_get_scan_history_by_id_not_found(monkeypatch):

    fake_history = [
        {
            "id": 1,
            "timestamp": "2026-10-08 10:00:00",
            "scanner": "nmap",
            "scan_type": "quick",
            "target": "scanme.nmap.org",
            "duration": 1.25,
            "findings": [],
            "status": "success"
        }
    ]

    def fake_get_history():
        return fake_history

    monkeypatch.setattr(
        "backend.api.scan_history.get_history",
        fake_get_history
    )

    response = client.get("/api/v1/history/999")

    assert response.status_code == 404

    data = response.json()

    assert data["detail"] == "Scan with ID 999 not found"