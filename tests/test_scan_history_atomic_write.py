
import json

from history.scan_history import ScanHistory


def test_atomic_write_preserves_history(tmp_path):
    history = ScanHistory()
    history.history_file = str(
        tmp_path / "scan_history.json"
    )

    history.save_scan({
        "scanner": "credential_scanner",
        "scan_type": "hash_identification",
        "target": "test-target",
        "scan_id": "8a9e7d6c-1234-4abc-9def-123456789abc",
        "status": "COMPLETED",
        "findings": [],
    })

    with open(history.history_file, encoding="utf-8") as file:
        saved = json.load(file)

    assert len(saved) == 1
    assert saved[0]["scan_id"] == (
        "8a9e7d6c-1234-4abc-9def-123456789abc"
    )
