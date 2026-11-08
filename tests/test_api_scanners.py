from fastapi.testclient import TestClient

from backend.api import app


client = TestClient(app)


def test_start_nmap_scan():
    response = client.post(
        "/api/v1/scans",
        json={
            "scanner": "nmap",
            "scan_type": "quick",
            "target": "scanme.nmap.org"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["scanner"] == "nmap"
    assert data["scan_type"] == "quick"
    assert data["target"] == "scanme.nmap.org"
    assert "result" in data