
from fastapi.testclient import TestClient

from backend.api import app, scan_history

client = TestClient(app)


def test_get_scan_history_by_uuid(monkeypatch):
    scan_uuid = "8a9e7d6c-1234-4abc-9def-123456789abc"

    monkeypatch.setattr(
        scan_history,
        "get_scan_by_uuid",
        lambda scan_id: (
            {
                "id": 1,
                "scan_id": scan_uuid,
                "scanner": "credential_scanner",
            }
            if scan_id == scan_uuid
            else None
        ),
    )

    response = client.get(f"/api/v1/history/uuid/{scan_uuid}")

    assert response.status_code == 200
    assert response.json()["scan"]["scan_id"] == scan_uuid


def test_get_scan_history_by_uuid_not_found(monkeypatch):
    monkeypatch.setattr(
        scan_history,
        "get_scan_by_uuid",
        lambda scan_id: None,
    )

    response = client.get(
        "/api/v1/history/uuid/00000000-0000-4000-8000-000000000000"
    )

    assert response.status_code == 404


def test_get_scan_history_by_uuid_invalid_format():
    response = client.get("/api/v1/history/uuid/not-a-uuid")

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid scan UUID format"
