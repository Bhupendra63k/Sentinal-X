
import json

from history.scan_history import ScanHistory


def test_get_history_filters_malformed_records_and_preserves_file(tmp_path):
    history = ScanHistory()
    history.history_file = str(tmp_path / "scan_history.json")

    records = [
        {"id": 1, "scan_id": "abc-123", "findings": []},
        None,
        "unexpected record",
    ]

    with open(history.history_file, "w", encoding="utf-8") as file:
        json.dump(records, file)

    loaded = history.get_history()

    assert loaded == [{"id": 1, "scan_id": "abc-123", "findings": []}]

    with open(history.history_file, "r", encoding="utf-8") as file:
        persisted = json.load(file)

    assert persisted == records


