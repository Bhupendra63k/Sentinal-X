
from unittest.mock import patch

from fastapi.testclient import TestClient
from backend.api import app

client = TestClient(app)


def test_full_scan_saves_each_scanner_result():
    mock_result = {
        "results": [
            {
                "scanner": "nmap",
                "scan_type": "quick",
                "target": "127.0.0.1",
                "findings": [],
                "status": "completed"
            },
            {
                "scanner": "nikto",
                "scan_type": "basic",
                "target": "http://127.0.0.1",
                "findings": [],
                "status": "completed"
            }
        ],
        "execution_results": []
    }

    with patch(
        "backend.api.orchestrator.run_full_scan",
        return_value=mock_result
    ), patch(
        "backend.api.scan_history.save_scan"
    ) as mock_save:

        response = client.post(
            "/api/v1/scans/full",
            json={"target": "127.0.0.1"}
        )

    # Verify the API response.
    assert response.status_code == 200
    assert response.json()["result"] == mock_result

    # Print actual calls to help diagnose any mismatch.
    print("\nACTUAL SAVE CALLS:", mock_save.call_args_list)

    # Verify each scanner result is saved separately.
    assert mock_save.call_count == 2
    mock_save.assert_any_call(mock_result["results"][0])
    mock_save.assert_any_call(mock_result["results"][1])


def test_full_scan_returns_500_when_orchestrator_fails():
    with patch(
        "backend.api.orchestrator.run_full_scan",
        side_effect=RuntimeError("An internal error occurs while executing this scan")
    ):
        response = client.post(
            "/api/v1/scans/full",
            json={"target": "127.0.0.1"}
        )

    assert response.status_code == 500
    assert response.json()["detail"] == (
    "An internal error occurred while executing the full scan"
)

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
    assert response.json()["result"] == mock_result
    mock_save.assert_called_once_with(mock_result)


