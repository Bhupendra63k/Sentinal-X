from core.finding_summary import FindingSummary


def test_summarise_all_severities():
    summarizer = FindingSummary()

    findings = [
        {"severity": "Critical"},
        {"severity": "High"},
        {"severity": "Medium"},
        {"severity": "Low"},
        {"severity": "Info"},
    ]

    result = summarizer.summarise(findings)

    assert result["total"] == 5
    assert result["severity_counts"]["Critical"] == 1
    assert result["severity_counts"]["High"] == 1
    assert result["severity_counts"]["Medium"] == 1
    assert result["severity_counts"]["Low"] == 1
    assert result["severity_counts"]["Info"] == 1


def test_summarise_multiple_same_severity():
    summarizer = FindingSummary()

    findings = [
        {"severity": "High"},
        {"severity": "High"},
        {"severity": "Medium"},
        {"severity": "Info"},
    ]

    result = summarizer.summarise(findings)

    assert result["total"] == 4
    assert result["severity_counts"]["High"] == 2
    assert result["severity_counts"]["Medium"] == 1
    assert result["severity_counts"]["Info"] == 1
    assert result["severity_counts"]["Critical"] == 0
    assert result["severity_counts"]["Low"] == 0


def test_summarise_lowercase_severity():
    summarizer = FindingSummary()

    findings = [
        {"severity": "critical"},
        {"severity": "high"},
        {"severity": "medium"},
        {"severity": "low"},
        {"severity": "info"},
    ]

    result = summarizer.summarise(findings)

    assert result["severity_counts"]["Critical"] == 1
    assert result["severity_counts"]["High"] == 1
    assert result["severity_counts"]["Medium"] == 1
    assert result["severity_counts"]["Low"] == 1
    assert result["severity_counts"]["Info"] == 1


def test_unknown_severity_defaults_to_info():
    summarizer = FindingSummary()

    findings = [
        {"severity": "Unknown"},
        {"severity": "SomethingElse"},
    ]

    result = summarizer.summarise(findings)

    assert result["total"] == 2
    assert result["severity_counts"]["Info"] == 2


def test_missing_severity_defaults_to_info():
    summarizer = FindingSummary()

    findings = [
        {"title": "Finding without severity"}
    ]

    result = summarizer.summarise(findings)

    assert result["total"] == 1
    assert result["severity_counts"]["Info"] == 1


def test_prioritise_orders_findings_by_severity():
    summarizer = FindingSummary()

    findings = [
        {"severity": "Info", "title": "Info Finding"},
        {"severity": "Low", "title": "Low Finding"},
        {"severity": "Critical", "title": "Critical Finding"},
        {"severity": "Medium", "title": "Medium Finding"},
        {"severity": "High", "title": "High Finding"},
    ]

    result = summarizer.prioritise(findings)

    severities = [finding["severity"] for finding in result]

    assert severities == [
        "Critical",
        "High",
        "Medium",
        "Low",
        "Info",
    ]


def test_prioritise_does_not_remove_findings():
    summarizer = FindingSummary()

    findings = [
        {"severity": "High", "title": "Finding 1"},
        {"severity": "Low", "title": "Finding 2"},
        {"severity": "Critical", "title": "Finding 3"},
    ]

    result = summarizer.prioritise(findings)

    assert len(result) == len(findings)
    assert result[0]["title"] == "Finding 3"
    assert result[1]["title"] == "Finding 1"
    assert result[2]["title"] == "Finding 2"