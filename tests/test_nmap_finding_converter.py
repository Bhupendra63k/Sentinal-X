from scanners.reconnaissance.nmap.finding_converter import NmapFindingConverter
from core.finding import Finding


def test_convert_single_port():
    converter = NmapFindingConverter()

    result = {
        "target": "127.0.0.1",
        "ports": [
            {
                "port": "22",
                "protocol": "tcp",
                "state": "open",
                "service": "ssh"
            }
        ]
    }

    findings = converter.convert(result)

    assert len(findings) == 1

    finding = findings[0]

    assert isinstance(finding, Finding)
    assert finding.scanner == "Nmap"
    assert finding.target == "127.0.0.1"
    assert finding.finding_id == "NMAP-1"
    assert finding.title == "Open Port Detected"
    assert finding.severity == "Info"


def test_convert_multiple_ports():
    converter = NmapFindingConverter()

    result = {
        "target": "127.0.0.1",
        "ports": [
            {
                "port": "22",
                "protocol": "tcp",
                "state": "open",
                "service": "ssh"
            },
            {
                "port": "80",
                "protocol": "tcp",
                "state": "open",
                "service": "http"
            },
            {
                "port": "443",
                "protocol": "tcp",
                "state": "open",
                "service": "https"
            }
        ]
    }

    findings = converter.convert(result)

    assert len(findings) == 3

    assert findings[0].finding_id == "NMAP-1"
    assert findings[1].finding_id == "NMAP-2"
    assert findings[2].finding_id == "NMAP-3"


def test_finding_description_contains_port_and_service():
    converter = NmapFindingConverter()

    result = {
        "target": "127.0.0.1",
        "ports": [
            {
                "port": "22",
                "protocol": "tcp",
                "state": "open",
                "service": "ssh"
            }
        ]
    }

    findings = converter.convert(result)

    finding = findings[0]

    assert "22" in finding.description
    assert "ssh" in finding.description


def test_finding_evidence_contains_state_and_service():
    converter = NmapFindingConverter()

    result = {
        "target": "127.0.0.1",
        "ports": [
            {
                "port": "80",
                "protocol": "tcp",
                "state": "open",
                "service": "http"
            }
        ]
    }

    findings = converter.convert(result)

    finding = findings[0]

    assert "open" in finding.evidence
    assert "http" in finding.evidence


def test_empty_ports_returns_empty_findings():
    converter = NmapFindingConverter()

    result = {
        "target": "127.0.0.1",
        "ports": []
    }

    findings = converter.convert(result)

    assert findings == []


def test_missing_ports_returns_empty_findings():
    converter = NmapFindingConverter()

    result = {
        "target": "127.0.0.1"
    }

    findings = converter.convert(result)

    assert findings == []


def test_missing_target_uses_unknown():
    converter = NmapFindingConverter()

    result = {
        "ports": [
            {
                "port": "22",
                "service": "ssh",
                "state": "open"
            }
        ]
    }

    findings = converter.convert(result)

    assert len(findings) == 1
    assert findings[0].target == "Unknown"


def test_missing_port_fields_use_unknown():
    converter = NmapFindingConverter()

    result = {
        "target": "127.0.0.1",
        "ports": [
            {}
        ]
    }

    findings = converter.convert(result)

    assert len(findings) == 1

    finding = findings[0]

    assert "Unknown" in finding.description
    assert "Unknown" in finding.evidence