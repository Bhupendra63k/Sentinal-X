from history.scan_history import ScanHistory


def test_scan_history_preserves_detailed_findings(tmp_path):
    history = ScanHistory()
    history.history_dir = str(tmp_path)
    history.history_file = str(tmp_path / "scan_history.json")

    scan_result = {
        "scanner": "nmap",
        "scan_type": "quick",
        "target": "127.0.0.1",
        "duration": 1.25,
        "status": "completed",
        "findings": [
            {
                "finding_id": "NETWORK-23",
                "title": "Insecure remote access protocol exposed: Telnet",
                "severity": "High",
                "description": "Telnet is exposed on port 23."
            },
            {
                "finding_id": "NETWORK-80",
                "title": "Unencrypted HTTP service exposed",
                "severity": "Medium",
                "description": "HTTP is exposed on port 80."
            }
        ]
    }

    history.save_scan(scan_result)
    saved_history = history.get_history()

    assert len(saved_history) == 1

    saved_scan = saved_history[0]

    assert saved_scan["scanner"] == "nmap"
    assert saved_scan["scan_type"] == "quick"
    assert saved_scan["target"] == "127.0.0.1"
    assert saved_scan["status"] == "completed"
    assert isinstance(saved_scan["findings"], list)
    assert len(saved_scan["findings"]) == 2
    assert saved_scan["findings"] == scan_result["findings"]
    assert saved_scan["findings"][0]["finding_id"] == "NETWORK-23"
    assert saved_scan["findings"][1]["finding_id"] == "NETWORK-80"


def test_scan_history_appends_multiple_scans(tmp_path):
    history = ScanHistory()
    history.history_dir = str(tmp_path)
    history.history_file = str(tmp_path / "scan_history.json")

    first_scan = {
        "scanner": "nmap",
        "scan_type": "quick",
        "target": "127.0.0.1",
        "duration": 1.0,
        "status": "completed",
        "findings": [
            {
                "finding_id": "NETWORK-23",
                "title": "Telnet exposed",
                "severity": "High"
            }
        ]
    }

    second_scan = {
        "scanner": "nmap",
        "scan_type": "service",
        "target": "127.0.0.1",
        "duration": 2.0,
        "status": "completed",
        "findings": [
            {
                "finding_id": "NETWORK-80",
                "title": "HTTP service exposed",
                "severity": "Medium"
            }
        ]
    }

    history.save_scan(first_scan)
    history.save_scan(second_scan)

    saved_history = history.get_history()

    assert len(saved_history) == 2
    assert saved_history[0]["findings"] == first_scan["findings"]
    assert saved_history[1]["findings"] == second_scan["findings"]
    assert saved_history[0]["scan_type"] == "quick"
    assert saved_history[1]["scan_type"] == "service"
    assert saved_history[0]["id"] != saved_history[1]["id"]


def test_scan_history_survives_reload(tmp_path):
    history_file = tmp_path / "scan_history.json"

    history1 = ScanHistory()
    history1.history_dir = str(tmp_path)
    history1.history_file = str(history_file)

    scan_result = {
        "scanner": "nmap",
        "scan_type": "quick",
        "target": "127.0.0.1",
        "duration": 1.5,
        "status": "completed",
        "findings": [
            {
                "finding_id": "NETWORK-23",
                "title": "Telnet exposed",
                "severity": "High"
            }
        ]
    }

    history1.save_scan(scan_result)

    # A new instance simulates reloading the history from disk.
    history2 = ScanHistory()
    history2.history_dir = str(tmp_path)
    history2.history_file = str(history_file)

    saved_history = history2.get_history()

    assert len(saved_history) == 1
    assert saved_history[0]["target"] == "127.0.0.1"
    assert saved_history[0]["findings"] == scan_result["findings"]


def test_scan_history_assigns_sequential_ids(tmp_path):
    history = ScanHistory()
    history.history_dir = str(tmp_path)
    history.history_file = str(tmp_path / "scan_history.json")

    for scan_type in ["quick", "service", "os"]:
        history.save_scan({
            "scanner": "nmap",
            "scan_type": scan_type,
            "target": "127.0.0.1",
            "duration": 1.0,
            "status": "completed",
            "findings": []
        })

    saved_history = history.get_history()

    assert len(saved_history) == 3
    assert [scan["id"] for scan in saved_history] == [1, 2, 3]
    assert len({scan["id"] for scan in saved_history}) == 3
