
from fastapi.testclient import TestClient

from backend.api import app, orchestrator, scan_history

client = TestClient(app)


def test_credential_scan_uuid_matches_saved_history(
    monkeypatch, tmp_path
):
    scan_uuid = "8a9e7d6c-1234-4abc-9def-123456789abc"

    scan_history.history_file = str(
        tmp_path / "scan_history.json"
    )

    fake_result = {
        "scanner": "credential_scanner",
        "scan_type": "hash_identification",
        "target": "test-hash",
        "status": "COMPLETED",
        "duration": 0.1,
        "scan_id": scan_uuid,
        "timestamp": "2026-10-13T00:00:00+00:00",
        "findings": [],
        "hashcat_result": None,
        "john_result": None,
        "error": None,
    }

    monkeypatch.setattr(
        orchestrator,
        "run_credential_scan",
        lambda **kwargs: fake_result,
    )

    response = client.post(
        "/api/v1/credential-scans",
        json={
            "scan_type": "hash_identification",
            "target": "test-hash",
        },
    )

    assert response.status_code == 200
    assert response.json()["result"]["scan_id"] == scan_uuid

    saved_scan = scan_history.get_scan_by_uuid(scan_uuid)

    assert saved_scan is not None
    assert saved_scan["scan_id"] == scan_uuid
    assert saved_scan["id"] == 1


