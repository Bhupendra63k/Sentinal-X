
from fastapi.testclient import TestClient

from backend.api import app, orchestrator

client = TestClient(app)


def test_full_scan_does_not_expose_internal_exception(monkeypatch):
    secret_detail = "C:\\internal\\secret_config.py"

    def fail_scan(*args, **kwargs):
        raise RuntimeError(secret_detail)

    monkeypatch.setattr(orchestrator, "run_full_scan", fail_scan)

    response = client.post(
        "/api/v1/scans/full",
        json={"target": "127.0.0.1"},
    )

    assert response.status_code == 500
    assert secret_detail not in response.text
    assert "internal error" in response.json()["detail"].lower()
