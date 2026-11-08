from core.security_analysis_engine import SecurityAnalysisEngine


def test_security_analysis_engine_generates_severity_summary():

    findings = [
        {"severity": "Critical"},
        {"severity": "High"},
        {"severity": "High"},
        {"severity": "Medium"},
        {"severity": "Low"},
        {"severity": "Info"},
        {"severity": "Info"}
    ]

    engine = SecurityAnalysisEngine()

    summary = engine.severity_summary(findings)

    assert summary["Critical"] == 1
    assert summary["High"] == 2
    assert summary["Medium"] == 1
    assert summary["Low"] == 1
    assert summary["Info"] == 2