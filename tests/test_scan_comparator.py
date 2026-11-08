from core.scan_comparator import ScanComparator


def test_scan_comparator():
    previous = [
        {"finding_id": "SSH"},
        {"finding_id": "HTTP"},
        {"finding_id": "CSP"},
    ]

    current = [
        {"finding_id": "SSH"},
        {"finding_id": "HTTPS"},
        {"finding_id": "CSP"},
    ]

    comparator = ScanComparator()

    result = comparator.compare(previous, current)

    assert result["summary"]["new"] == 1
    assert result["summary"]["resolved"] == 1
    assert result["summary"]["persistent"] == 2