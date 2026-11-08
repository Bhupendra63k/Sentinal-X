from core.finding import Finding


def test_finding_creation():
    finding = Finding(
        scanner="Nmap",
        target="127.0.0.1",
        finding_id="NMAP-001",
        title="Open SSH Port",
        severity="Info",
        description="SSH service detected",
        evidence="22/tcp open ssh",
        recommendation="Review exposed SSH service"
    )

    assert finding.scanner == "Nmap"
    assert finding.target == "127.0.0.1"
    assert finding.finding_id == "NMAP-001"
    assert finding.title == "Open SSH Port"
    assert finding.severity == "Info"
    assert finding.description == "SSH service detected"
    assert finding.evidence == "22/tcp open ssh"
    assert finding.recommendation == "Review exposed SSH service"


def test_default_values():
    finding = Finding(
        scanner="Nuclei",
        target="http://127.0.0.1:8000",
        finding_id="TEST-001",
        title="Test Finding"
    )

    assert finding.severity == "Info"
    assert finding.description == ""
    assert finding.evidence == ""
    assert finding.recommendation == ""


def test_to_dict():
    finding = Finding(
        scanner="Nuclei",
        target="http://127.0.0.1:8000",
        finding_id="TEST-001",
        title="Test Finding",
        severity="High",
        description="Test description",
        evidence="Test evidence",
        recommendation="Test recommendation"
    )

    result = finding.to_dict()

    assert result == {
        "scanner": "Nuclei",
        "target": "http://127.0.0.1:8000",
        "finding_id": "TEST-001",
        "title": "Test Finding",
        "severity": "High",
        "description": "Test description",
        "evidence": "Test evidence",
        "recommendation": "Test recommendation"
    }


def test_to_dict_returns_dictionary():
    finding = Finding(
        scanner="Nikto",
        target="http://127.0.0.1:8000",
        finding_id="NIKTO-001",
        title="Test Finding"
    )

    result = finding.to_dict()

    assert isinstance(result, dict)