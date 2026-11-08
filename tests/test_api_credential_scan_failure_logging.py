
import logging

from fastapi.testclient import TestClient

from backend.api import app, orchestrator

client = TestClient(app)


def test_credential_scan_failure_logs_scan_type(monkeypatch, caplog):
    def fail_scan(**kwargs):
        raise RuntimeError("sensitive internal detail")

    monkeypatch.setattr(
        orchestrator,
        "run_credential_scan",
        fail_scan,
    )

    with caplog.at_level(logging.ERROR, logger="backend.api"):
        response = client.post(
            "/api/v1/credential-scans",
            json={
                "scan_type": "hash_identification",
                "target": "test-hash",
            },
        )

    assert response.status_code == 500
    assert "hash_identification" in caplog.text
    assert "sensitive internal detail" not in response.text
    assert "sensitive internal detail" in caplog.text
    assert "internal error" in response.json()["detail"].lower()
