
from fastapi.testclient import TestClient
from backend.api import app

client = TestClient(app)


def test_individual_scan_rejects_empty_target():
    response = client.post(
        "/api/v1/scans",
        json={
            "scanner": "nmap",
            "scan_type": "quick",
            "target": "   "
        }
    )

    assert response.status_code == 422


def test_full_scan_rejects_empty_target():
    response = client.post(
        "/api/v1/scans/full",
        json={"target": "   "}
    )

    assert response.status_code == 422


def test_individual_scan_rejects_missing_target():
    response = client.post(
        "/api/v1/scans",
        json={
            "scanner": "nmap",
            "scan_type": "quick"
        }
    )

    assert response.status_code == 422
