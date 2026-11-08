
import json

import pytest

from history.scan_history import ScanHistory


@pytest.mark.parametrize("content", ["{invalid json", "{}", "null", '"text"'])
def test_get_history_returns_empty_list_for_invalid_structure(
    tmp_path, content
):
    history = ScanHistory()
    history.history_file = str(tmp_path / "scan_history.json")
    with open(history.history_file, "w", encoding="utf-8") as file:
        file.write(content)

    assert history.get_history() == []


def test_get_history_returns_saved_list(tmp_path):
    history = ScanHistory()
    history.history_file = str(tmp_path / "scan_history.json")
    expected = [{"id": 1, "scan_id": "test-uuid"}]

    with open(history.history_file, "w", encoding="utf-8") as file:
        json.dump(expected, file)

    assert history.get_history() == expected
