from unittest.mock import patch

from fastapi.testclient import TestClient
from backend.api import app

client = TestClient(app)


def test_credential_scan_rejects_malformed_target_before_execution():
    with patch(
        "backend.api.orchestrator.run_credential_scan"
    ) as mock_scan:
        response = client.post(
            "/api/v1/credential-scans",
            json={
                "scan_type": "hash_identification",
                "target": "https://"
            }
        )

    assert response.status_code == 422
    mock_scan.assert_not_called()
