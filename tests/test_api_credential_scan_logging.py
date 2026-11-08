
import logging

from fastapi.testclient import TestClient
from backend.api import app, orchestrator, scan_history

client = TestClient(app)


def test_credential_scan_logs_safe_metadata(monkeypatch, caplog, tmp_path):
    scan_id = "8a9e7d6c-1234-4abc-9def-123456789abc"

    scan_history.history_file = str(tmp_path / "scan_history.json")

    result = {
        "scanner": "credential_scanner",
        "scan_type": "hash_identification",
        "target": "test-hash",
        "status": "COMPLETED",
        "scan_id": scan_id,
        "findings": [],
        "duration": 0.1,
        "error": None,
    }

    monkeypatch.setattr(
        orchestrator,
        "run_credential_scan",
        lambda **kwargs: result,
    )

    with caplog.at_level(logging.INFO, logger="backend.api"):
        response = client.post(
            "/api/v1/credential-scans",
            json={
                "scan_type": "hash_identification",
                "target": "test-hash",
            },
        )

    assert response.status_code == 200
    assert scan_id in caplog.text
    assert "hash_identification" in caplog.text
    assert "COMPLETED" in caplog.text
