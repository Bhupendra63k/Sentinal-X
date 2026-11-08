from fastapi.testclient import TestClient
from backend.api import app
from unittest.mock import patch

client=TestClient(app)
def test_individual_scan_saves_to_history():
    mock_result = {
        "scanner": "nmap",
        "scan_type": "quick",
        "target": "127.0.0.1",
        "findings": [],
        "status": "completed"
    }

    with patch(
        "backend.api.scanner_manager.start_scan",
        return_value=mock_result
    ), patch(
        "backend.api.scan_history.save_scan"
    ) as mock_save:

        response = client.post(
            "/api/v1/scans",
            json={
                "scanner": "nmap",
                "scan_type": "quick",
                "target": "127.0.0.1"
            }
        )

    assert response.status_code == 200
    mock_save.assert_called_once_with(mock_result)
