from core.security_analysis_engine import SecurityAnalysisEngine


def test_security_analysis_engine_prioritizes_findings_by_severity():

    findings = [
        {
            "scanner": "Nmap",
            "target": "127.0.0.1",
            "finding_id": "NETWORK-80",
            "title": "HTTP exposed",
            "severity": "Medium"
        },
        {
            "scanner": "Nmap",
            "target": "127.0.0.1",
            "finding_id": "NETWORK-23",
            "title": "Telnet exposed",
            "severity": "High"
        },
        {
            "scanner": "Nikto",
            "target": "http://127.0.0.1",
            "finding_id": "WEB-001",
            "title": "Security header missing",
            "severity": "Low"
        },
        {
            "scanner": "Nuclei",
            "target": "http://127.0.0.1",
            "finding_id": "CVE-001",
            "title": "Critical vulnerability",
            "severity": "Critical"
        },
        {
            "scanner": "Nmap",
            "target": "127.0.0.1",
            "finding_id": "NETWORK-22",
            "title": "Service detected",
            "severity": "Info"
        }
    ]

    engine = SecurityAnalysisEngine()

    prioritized = engine.prioritize(findings)

    assert prioritized[0]["severity"] == "Critical"
    assert prioritized[1]["severity"] == "High"
    assert prioritized[2]["severity"] == "Medium"
    assert prioritized[3]["severity"] == "Low"
    assert prioritized[4]["severity"] == "Info"