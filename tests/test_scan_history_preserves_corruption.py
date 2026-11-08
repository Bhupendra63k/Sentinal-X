
import pytest

from history.scan_history import ScanHistory


def test_save_scan_preserves_corrupted_history_file(tmp_path):
    history = ScanHistory()
    history.history_file = str(tmp_path / "scan_history.json")

    corrupted_content = "{invalid json"

    with open(history.history_file, "w", encoding="utf-8") as file:
        file.write(corrupted_content)

    with pytest.raises(ValueError, match="history file is corrupted"):
        history.save_scan({
            "scanner": "credential_scanner",
            "scan_type": "hash_identification",
            "target": "test-target",
            "scan_id": "8a9e7d6c-1234-4abc-9def-123456789abc",
            "status": "COMPLETED",
            "findings": [],
        })

    with open(history.history_file, "r", encoding="utf-8") as file:
        assert file.read() == corrupted_content
