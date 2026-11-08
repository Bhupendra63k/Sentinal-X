
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.api import app

client = TestClient(app)


def test_individual_scan_does_not_expose_internal_exception():
    with patch(
        "backend.api.scanner_manager.start_scan",
        side_effect=RuntimeError("SECRET_INTERNAL_PATH")
    ):
        response = client.post(
            "/api/v1/scans",
            json={
                "scanner": "nmap",
                "scan_type": "quick",
                "target": "127.0.0.1"
            }
        )

    assert response.status_code == 500
    assert "SECRET_INTERNAL_PATH" not in response.text
    assert response.json()["detail"] == (
    "An internal error occurred while executing this scan."
)


def test_full_scan_does_not_expose_internal_exception():
    with patch(
        "backend.api.orchestrator.run_full_scan",
        side_effect=RuntimeError("SECRET_FULL_SCAN_ERROR")
    ):
        response = client.post(
            "/api/v1/scans/full",
            json={"target": "127.0.0.1"}
        )

    assert response.status_code == 500
    assert "SECRET_FULL_SCAN_ERROR" not in response.text
    assert response.json()["detail"] == (
    "An internal error occurred while executing the full scan"
)

def test_history_does_not_expose_internal_exception():
    with patch(
        "backend.api.scan_history.get_history",
        side_effect=RuntimeError("SECRET_HISTORY_ERROR")
    ):
        response = client.get("/api/v1/history")

    assert response.status_code == 500
    assert "SECRET_HISTORY_ERROR" not in response.text
    assert response.json()["detail"] == (
    "An internal error occurred while retrieving scan history"
)


def test_scan_comparison_does_not_expose_internal_exception():
    with patch(
        "backend.api.scan_history.get_history",
        side_effect=RuntimeError("SECRET_COMPARE_ERROR")
    ):
        response = client.get(
            "/api/v1/history/compare",
            params={"previous_id": 1, "current_id": 2}
        )

    assert response.status_code == 500
    assert "SECRET_COMPARE_ERROR" not in response.text
    assert response.json()["detail"] == (
    "An internal error occurred while comparing scans"
)


def test_credential_scan_does_not_expose_internal_exception():
    with patch(
        "backend.api.orchestrator.run_credential_scan",
        side_effect=RuntimeError("SECRET_CREDENTIAL_ERROR")
    ):
        response = client.post(
            "/api/v1/credential-scans",
            json={
                "scan_type": "hash_identification",
                "target": "test-hash"
            }
        )

    assert response.status_code == 500
    assert "SECRET_CREDENTIAL_ERROR" not in response.text
    assert response.json()["detail"] == (
    "An internal error occurred while executing credential scan."
)



def test_history_by_id_does_not_expose_internal_exception():
    with patch(
        "backend.api.scan_history.get_history",
        side_effect=RuntimeError("SECRET_HISTORY_BY_ID_ERROR")
    ):
        response = client.get("/api/v1/history/1")

    assert response.status_code == 500
    assert "SECRET_HISTORY_BY_ID_ERROR" not in response.text
    assert response.json()["detail"] == (
    "An internal error occurred while retrieving the scan"
)

