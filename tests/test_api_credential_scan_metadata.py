
from fastapi.testclient import TestClient

from backend.api import app, orchestrator, scan_history

client = TestClient(app)


def test_credential_scan_metadata_is_consistent(monkeypatch, tmp_path):
    scan_id = "8a9e7d6c-1234-4abc-9def-123456789abc"
    scan_history.history_file = str(tmp_path / "scan_history.json")

    fake_result = {
        "scanner": "credential_scanner",
        "scan_type": "hash_identification",
        "target": "test-hash",
        "status": "COMPLETED",
        "duration": 0.1,
        "scan_id": scan_id,
        "findings": [],
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

    body = response.json()
    assert body["scanner"] == "credential_scanner"
    assert body["scan_type"] == "hash_identification"
    assert body["result"]["scan_id"] == scan_id

    saved = scan_history.get_scan_by_uuid(scan_id)
    assert saved is not None
    assert saved["scan_id"] == scan_id
    assert saved["scan_type"] == "hash_identification"
