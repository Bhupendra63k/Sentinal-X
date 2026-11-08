from core.security_analysis_engine import SecurityAnalysisEngine


def test_security_analysis_engine_collects_findings():

    findings = [
        {
            "scanner": "Nmap",
            "target": "127.0.0.1",
            "finding_id": "NETWORK-23",
            "title": "Telnet exposed",
            "severity": "High",
            "description": "Telnet is exposed.",
            "evidence": "23/tcp open telnet",
            "recommendation": "Disable Telnet."
        },
        {
            "scanner": "Nikto",
            "target": "http://127.0.0.1",
            "finding_id": "WEB-001",
            "title": "Security header missing",
            "severity": "Medium",
            "description": "A security header is missing.",
            "evidence": "Missing header",
            "recommendation": "Configure the security header."
        }
    ]

    engine = SecurityAnalysisEngine()

    result = engine.analyze(findings)

    assert result["total_findings"] == 2

    assert len(result["findings"]) == 2

    assert result["findings"][0]["finding_id"] == "NETWORK-23"
    assert result["findings"][1]["finding_id"] == "WEB-001"