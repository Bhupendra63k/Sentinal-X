import pytest
from fastapi.testclient import TestClient
from backend.api import app, orchestrator

client = TestClient(app)


def test_hash_identification_success(monkeypatch):
    def mock_run_credential_scan(**kwargs):
        return {
            "scanner": "credential_scanner",
            "scan_type": "hash_identification",
            "target": kwargs["target"],
            "findings": [],
            "hashcat_result": None,
            "john_result": None,
            "duration": "Unknown"
        }

    monkeypatch.setattr(
        orchestrator,
        "run_credential_scan",
        mock_run_credential_scan
    )

    response = client.post(
        "/api/v1/credential-scans",
        json={
            "scan_type": "hash_identification",
            "target": "5f4dcc3b5aa765d61d8327deb882cf99"
        }
    )

    assert response.status_code == 200
    data = response.json()
    assert data["scanner"] == "credential_scanner"
    assert data["scan_type"] == "hash_identification"
    assert data["result"]["findings"] == []


def test_invalid_credential_scan_type():
    response = client.post(
        "/api/v1/credential-scans",
        json={
            "scan_type": "invalid",
            "target": "test-hash"
        }
    )

    assert response.status_code == 400


def test_hashcat_missing_parameters():
    response = client.post(
        "/api/v1/credential-scans",
        json={
            "scan_type": "hashcat",
            "target": "test-hash"
        }
    )

    assert response.status_code == 400


def test_john_missing_parameters():
    response = client.post(
        "/api/v1/credential-scans",
        json={
            "scan_type": "john",
            "target": "test-hash"
        }
    )

    assert response.status_code == 400