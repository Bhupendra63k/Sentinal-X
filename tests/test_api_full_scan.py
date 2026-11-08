from fastapi.testclient import TestClient

from backend.api import app


client = TestClient(app)


def test_start_full_scan(monkeypatch):

    fake_result = {
        "results": [
            {
                "scanner": "nmap",
                "scan_type": "quick",
                "findings": []
            },
            {
                "scanner": "nikto",
                "scan_type": "basic",
                "findings": []
            },
            {
                "scanner": "nuclei",
                "scan_type": "default",
                "findings": []
            }
        ],
        "execution_results": [
            {
                "scanner_name": "nmap",
                "status": "success"
            },
            {
                "scanner_name": "nikto",
                "status": "success"
            },
            {
                "scanner_name": "nuclei",
                "status": "success"
            }
        ]
    }

    def fake_run_full_scan(target):
        return fake_result

    monkeypatch.setattr(
        "backend.api.orchestrator.run_full_scan",
        fake_run_full_scan
    )

    response = client.post(
        "/api/v1/scans/full",
        json={
            "target": "scanme.nmap.org"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["target"] == "scanme.nmap.org"
    assert "result" in data

    assert len(data["result"]["results"]) == 3
    assert len(data["result"]["execution_results"]) == 3