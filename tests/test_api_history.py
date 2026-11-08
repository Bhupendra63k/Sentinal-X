from fastapi.testclient import TestClient
from unittest.mock import patch

from backend.api import app

client = TestClient(app)


def test_get_scan_history_returns_saved_scans():
    mock_history = [
        {
            "id": 1,
            "timestamp": "2026-10-09 10:00:00",
            "scanner": "nmap",
            "scan_type": "quick",
            "target": "127.0.0.1",
            "duration": 1.25,
            "findings": [
                {
                    "finding_id": "NETWORK-23",
                    "title": "Telnet exposed",
                    "severity": "High"
                }
            ],
            "status": "completed"
        }
    ]

    with patch(
        "backend.api.scan_history.get_history",
        return_value=mock_history
    ):
        response = client.get("/api/v1/history")

    assert response.status_code == 200

    data = response.json()
    assert "history" in data

    history = data["history"]

    assert len(history) == 1
    assert history[0]["id"] == 1
    assert history[0]["scanner"] == "nmap"
    assert history[0]["scan_type"] == "quick"
    assert history[0]["target"] == "127.0.0.1"
    assert history[0]["findings"][0]["finding_id"] == "NETWORK-23"


def test_get_scan_history_returns_empty_list():
    with patch(
        "backend.api.scan_history.get_history",
        return_value=[]
    ):
        response = client.get("/api/v1/history")

    assert response.status_code == 200
    assert response.json()["history"] == []


def test_get_scan_history_preserves_multiple_scans():
    mock_history = [
        {
            "id": 1,
            "scanner": "nmap",
            "scan_type": "quick",
            "target": "127.0.0.1",
            "findings": [],
            "status": "completed"
        },
        {
            "id": 2,
            "scanner": "nikto",
            "scan_type": "basic",
            "target": "http://127.0.0.1",
            "findings": [],
            "status": "completed"
        }
    ]

    with patch(
        "backend.api.scan_history.get_history",
        return_value=mock_history
    ):
        response = client.get("/api/v1/history")

    assert response.status_code == 200

    data = response.json()
    history = data["history"]

    assert len(history) == 2
    assert history[0]["id"] == 1
    assert history[1]["id"] == 2
    assert history[0]["scanner"] == "nmap"
    assert history[1]["scanner"] == "nikto"
