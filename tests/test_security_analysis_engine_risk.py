from core.security_analysis_engine import SecurityAnalysisEngine


def test_overall_risk_returns_highest_severity():

    findings = [
        {"finding_id": "NETWORK-80", "severity": "Medium"},
        {"finding_id": "NETWORK-23", "severity": "High"},
        {"finding_id": "WEB-001", "severity": "Low"}
    ]

    engine = SecurityAnalysisEngine()

    risk = engine.overall_risk(findings)

    assert risk == "High"


def test_overall_risk_returns_critical_when_present():

    findings = [
        {"finding_id": "NETWORK-23", "severity": "High"},
        {"finding_id": "WEB-001", "severity": "Critical"}
    ]

    engine = SecurityAnalysisEngine()

    risk = engine.overall_risk(findings)

    assert risk == "Critical"


def test_overall_risk_returns_info_when_no_findings():

    engine = SecurityAnalysisEngine()

    risk = engine.overall_risk([])

    assert risk == "Info"