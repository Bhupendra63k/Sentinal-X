
import logging

from history.scan_history import ScanHistory


def test_corrupted_history_is_logged_and_preserved(tmp_path, caplog):
    history = ScanHistory()
    history.history_file = str(tmp_path / "scan_history.json")

    corrupted_content = "{invalid json"
    with open(history.history_file, "w", encoding="utf-8") as file:
        file.write(corrupted_content)

    with caplog.at_level(logging.ERROR):
        assert history.get_history() == []

    assert "invalid JSON" in caplog.text

    with open(history.history_file, "r", encoding="utf-8") as file:
        assert file.read() == corrupted_content
