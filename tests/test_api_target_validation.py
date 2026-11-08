
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.api import app

client = TestClient(app)


def test_nmap_rejects_url_target_before_scanning():
    payload = {
        "scanner": "nmap",
        "scan_type": "quick",
        "target": "https://example.com",
    }

    with patch(
        "backend.api.scanner_manager.start_scan"
    ) as mock_start_scan:
        response = client.post("/api/v1/scans", json=payload)

    assert response.status_code == 400
    assert "Nmap requires" in response.json()["detail"]
    mock_start_scan.assert_not_called()

