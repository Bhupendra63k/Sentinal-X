from core.security_analysis_engine import SecurityAnalysisEngine
from formatter.security_analysis_formatter import (
    SecurityAnalysisFormatter
)


def test_analysis_engine_to_formatter():

    findings = [
        {
            "scanner": "Nmap",
            "target": "127.0.0.1",
            "finding_id": "NETWORK-80",
            "title": "HTTP port exposed",
            "severity": "Medium",
            "description": "HTTP service detected",
            "evidence": "80/tcp open http"
        },
        {
            "scanner": "Nikto",
            "target": "127.0.0.1",
            "finding_id": "WEB-001",
            "title": "Web security issue",
            "severity": "Critical",
            "description": "Critical web issue detected",
            "evidence": "HTTP response"
        }
    ]

    engine = SecurityAnalysisEngine()

    analysis_result = engine.analyze(findings)

    formatter = SecurityAnalysisFormatter()

    output = formatter.format(analysis_result)

    assert "SECURITY ANALYSIS REPORT" in output
    assert "Overall Risk: Critical" in output
    assert "Total Findings: 2" in output

    assert "Critical: 1" in output
    assert "Medium: 1" in output

    assert "Security Insights" in output
    assert "Recommendations" in output

    assert "127.0.0.1" in output