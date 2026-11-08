from fastapi.testclient import TestClient

from backend.api import app


client = TestClient(app)


def test_compare_scan_history(monkeypatch):

    fake_history = [
        {
            "id": 1,
            "timestamp": "2026-10-08 10:00:00",
            "scanner": "nmap",
            "scan_type": "quick",
            "target": "scanme.nmap.org",
            "duration": 1.2,
            "findings": [
                {
                    "finding_id": "NMAP-001",
                    "title": "Open SSH Port",
                    "severity": "Medium"
                },
                {
                    "finding_id": "NMAP-002",
                    "title": "Open HTTP Port",
                    "severity": "Medium"
                }
            ],
            "status": "success"
        },
        {
            "id": 2,
            "timestamp": "2026-10-08 11:00:00",
            "scanner": "nmap",
            "scan_type": "quick",
            "target": "scanme.nmap.org",
            "duration": 1.3,
            "findings": [
                {
                    "finding_id": "NMAP-001",
                    "title": "Open SSH Port",
                    "severity": "Medium"
                },
                {
                    "finding_id": "NMAP-003",
                    "title": "Open FTP Port",
                    "severity": "Medium"
                }
            ],
            "status": "success"
        }
    ]

    def fake_get_history():
        return fake_history

    monkeypatch.setattr(
        "backend.api.scan_history.get_history",
        fake_get_history
    )

    response = client.get(
        "/api/v1/history/compare",
        params={
            "previous_id": 1,
            "current_id": 2
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["previous_id"] == 1
    assert data["current_id"] == 2
    assert "comparison" in data