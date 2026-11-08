
import json

from history.scan_history import ScanHistory


def test_scan_history_preserves_scan_uuid(tmp_path):
    history = ScanHistory()
    history.history_file = str(tmp_path / "scan_history.json")

    scan_uuid = "8a9e7d6c-1234-4abc-9def-123456789abc"

    result = {
        "scanner": "credential_scanner",
        "scan_type": "hash_identification",
        "target": "test-hash",
        "status": "COMPLETED",
        "duration": 0.15,
        "scan_id": scan_uuid,
        "findings": [],
    }

    history.save_scan(result)

    saved_history = history.get_history()

    assert len(saved_history) == 1
    assert saved_history[0]["scan_id"] == scan_uuid
    assert saved_history[0]["id"] == 1

    with open(history.history_file, "r", encoding="utf-8") as file:
        persisted_history = json.load(file)

    assert persisted_history[0]["scan_id"] == scan_uuid
