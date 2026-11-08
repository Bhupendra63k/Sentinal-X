from core.security_analysis_engine import SecurityAnalysisEngine
from formatter.security_analysis_formatter import (
    SecurityAnalysisFormatter
)


def test_full_security_scan_analysis_flow():

    combined_result = {
        "target": "127.0.0.1",
        "findings": [
            {
                "scanner": "Nmap",
                "target": "127.0.0.1",
                "finding_id": "NETWORK-22",
                "title": "SSH port exposed",
                "severity": "High",
                "description": "SSH service detected",
                "evidence": "22/tcp open ssh"
            },
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
                "description": "Critical web security issue detected",
                "evidence": "HTTP response"
            }
        ]
    }

    # Security analysis
    engine = SecurityAnalysisEngine()

    analysis_result = engine.analyze(
        combined_result["findings"]
    )

    # Verify analysis
    assert analysis_result["total_findings"] == 3
    assert analysis_result["overall_risk"] == "Critical"

    assert analysis_result["severity_summary"]["Critical"] == 1
    assert analysis_result["severity_summary"]["High"] == 1
    assert analysis_result["severity_summary"]["Medium"] == 1

    assert len(analysis_result["correlations"]) == 1
    assert len(analysis_result["insights"]) == 1
    assert len(analysis_result["recommendations"]) == 1

    # Format analysis
    formatter = SecurityAnalysisFormatter()

    output = formatter.format(
        analysis_result
    )

    # Verify final CLI output
    assert "SECURITY ANALYSIS REPORT" in output
    assert "Overall Risk: Critical" in output
    assert "Total Findings: 3" in output

    assert "Critical: 1" in output
    assert "High: 1" in output
    assert "Medium: 1" in output

    assert "Security Insights" in output
    assert "Recommendations" in output

    assert "127.0.0.1" in output