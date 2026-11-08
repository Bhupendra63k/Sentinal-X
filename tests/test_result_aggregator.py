from core.result_aggregator import ResultAggregator


def test_aggregate_basic_results():
    aggregator = ResultAggregator()

    results = [
        {
            "scanner": "Nmap",
            "scan_type": "quick",
            "duration": 10.5,
            "findings": [
                {
                    "scanner": "Nmap",
                    "target": "127.0.0.1",
                    "finding_id": "NMAP-001",
                    "title": "Open Port",
                    "severity": "Info"
                }
            ]
        },
        {
            "scanner": "Nuclei",
            "scan_type": "default",
            "duration": 20.5,
            "findings": [
                {
                    "scanner": "Nuclei",
                    "target": "http://127.0.0.1:8000",
                    "finding_id": "NUCLEI-001",
                    "title": "Missing Header",
                    "severity": "Medium"
                }
            ]
        }
    ]

    result = aggregator.aggregate(
        results,
        "http://127.0.0.1:8000"
    )

    assert result["scanner"] == "SentinalX"
    assert result["scan_type"] == "Full-security"
    assert result["target"] == "http://127.0.0.1:8000"

    assert result["scanners"] == [
        "Nmap",
        "Nuclei"
    ]

    assert result["scan_types"] == [
        "quick",
        "default"
    ]

    assert result["duration"] == 31.0
    assert len(result["findings"]) == 2


def test_aggregate_skips_empty_results():
    aggregator = ResultAggregator()

    results = [
        None,
        {},
        {
            "scanner": "Nmap",
            "scan_type": "quick",
            "duration": 5,
            "findings": []
        }
    ]

    result = aggregator.aggregate(
        results,
        "127.0.0.1"
    )

    assert result["scanners"] == ["Nmap"]
    assert result["scan_types"] == ["quick"]
    assert result["duration"] == 5.0
    assert result["findings"] == []


def test_duplicate_scanners_are_only_listed_once():
    aggregator = ResultAggregator()

    results = [
        {
            "scanner": "Nmap",
            "scan_type": "quick",
            "duration": 5,
            "findings": []
        },
        {
            "scanner": "Nmap",
            "scan_type": "service",
            "duration": 10,
            "findings": []
        }
    ]

    result = aggregator.aggregate(
        results,
        "127.0.0.1"
    )

    assert result["scanners"] == ["Nmap"]

    assert result["scan_types"] == [
        "quick",
        "service"
    ]


def test_duplicate_findings_are_removed():
    aggregator = ResultAggregator()

    finding = {
        "scanner": "Nuclei",
        "target": "http://127.0.0.1:8000",
        "finding_id": "NUCLEI-001",
        "title": "Test Finding",
        "severity": "High"
    }

    results = [
        {
            "scanner": "Nuclei",
            "scan_type": "default",
            "duration": 5,
            "findings": [finding]
        },
        {
            "scanner": "Nuclei",
            "scan_type": "default",
            "duration": 7,
            "findings": [finding.copy()]
        }
    ]

    result = aggregator.aggregate(
        results,
        "http://127.0.0.1:8000"
    )

    assert len(result["findings"]) == 1


def test_same_finding_id_from_different_scanners_is_kept():
    aggregator = ResultAggregator()

    nmap_finding = {
        "scanner": "Nmap",
        "target": "127.0.0.1",
        "finding_id": "TEST-001",
        "title": "Test",
        "severity": "Info"
    }

    nuclei_finding = {
        "scanner": "Nuclei",
        "target": "http://127.0.0.1:8000",
        "finding_id": "TEST-001",
        "title": "Test",
        "severity": "High"
    }

    results = [
        {
            "scanner": "Nmap",
            "scan_type": "quick",
            "duration": 5,
            "findings": [nmap_finding]
        },
        {
            "scanner": "Nuclei",
            "scan_type": "default",
            "duration": 10,
            "findings": [nuclei_finding]
        }
    ]

    result = aggregator.aggregate(
        results,
        "http://127.0.0.1:8000"
    )

    assert len(result["findings"]) == 2


def test_duration_invalid_value_defaults_to_zero():
    aggregator = ResultAggregator()

    results = [
        {
            "scanner": "Nmap",
            "scan_type": "quick",
            "duration": "invalid",
            "findings": []
        },
        {
            "scanner": "Nikto",
            "scan_type": "basic",
            "duration": 10,
            "findings": []
        }
    ]

    result = aggregator.aggregate(
        results,
        "http://127.0.0.1:8000"
    )

    assert result["duration"] == 10.0


def test_missing_duration_defaults_to_zero():
    aggregator = ResultAggregator()

    results = [
        {
            "scanner": "Nmap",
            "scan_type": "quick",
            "findings": []
        }
    ]

    result = aggregator.aggregate(
        results,
        "127.0.0.1"
    )

    assert result["duration"] == 0.0


def test_empty_results_return_valid_structure():
    aggregator = ResultAggregator()

    result = aggregator.aggregate(
        [],
        "127.0.0.1"
    )

    assert result == {
        "scanner": "SentinalX",
        "scan_type": "Full-security",
        "target": "127.0.0.1",
        "scanners": [],
        "scan_types": [],
        "scanner_results": [],
        "duration": 0,
        "findings": []
    }