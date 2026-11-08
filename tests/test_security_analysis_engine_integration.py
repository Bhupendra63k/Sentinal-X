from core.security_analysis_engine import SecurityAnalysisEngine


def test_security_analysis_engine_combines_analysis():

    findings = [
        {
            "finding_id": "NETWORK-80",
            "severity": "Medium"
        },
        {
            "finding_id": "NETWORK-23",
            "severity": "High"
        },
        {
            "finding_id": "WEB-001",
            "severity": "Critical"
        },
        {
            "finding_id": "NETWORK-22",
            "severity": "Info"
        }
    ]

    engine = SecurityAnalysisEngine()

    result = engine.analyze(findings)

    assert result["total_findings"] == 4

    assert result["severity_summary"]["Critical"] == 1
    assert result["severity_summary"]["High"] == 1
    assert result["severity_summary"]["Medium"] == 1
    assert result["severity_summary"]["Info"] == 1

    assert result["prioritized_findings"][0]["finding_id"] == "WEB-001"
    assert result["prioritized_findings"][1]["finding_id"] == "NETWORK-23"
    assert result["prioritized_findings"][2]["finding_id"] == "NETWORK-80"
    assert result["prioritized_findings"][3]["finding_id"] == "NETWORK-22"