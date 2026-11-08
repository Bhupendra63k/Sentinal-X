from history.scan_history import ScanHistory


def test_scan_history_comparison(tmp_path):
    history = ScanHistory()

    # Keep the test isolated from the real history file
    history.history_dir = str(tmp_path)
    history.history_file = str(tmp_path / "scan_history.json")

    # First scan
    history.save_scan({
        "scanner": "nmap",
        "scan_type": "quick",
        "target": "127.0.0.1",
        "findings": [
            {"finding_id": "SSH"},
            {"finding_id": "HTTP"},
            {"finding_id": "CSP"}
        ]
    })

    # Second scan
    history.save_scan({
        "scanner": "nmap",
        "scan_type": "quick",
        "target": "127.0.0.1",
        "findings": [
            {"finding_id": "SSH"},
            {"finding_id": "HTTPS"},
            {"finding_id": "CSP"}
        ]
    })

    result = history.compare_scans(1, 2)

    assert result["summary"]["new"] == 1
    assert result["summary"]["resolved"] == 1
    assert result["summary"]["persistent"] == 2


import pytest


def test_compare_scans_rejects_missing_previous_scan(tmp_path):
    history = ScanHistory()
    history.history_file = str(tmp_path / "scan_history.json")

    history.save_scan({
        "scanner": "nmap",
        "scan_type": "quick",
        "target": "127.0.0.1",
        "findings": [],
    })

    with pytest.raises(ValueError, match="Previous scan not found"):
        history.compare_scans(999, 1)


def test_compare_scans_rejects_missing_current_scan(tmp_path):
    history = ScanHistory()
    history.history_file = str(tmp_path / "scan_history.json")

    history.save_scan({
        "scanner": "nmap",
        "scan_type": "quick",
        "target": "127.0.0.1",
        "findings": [],
    })

    with pytest.raises(ValueError, match="Current scan not found"):
        history.compare_scans(1, 999)
