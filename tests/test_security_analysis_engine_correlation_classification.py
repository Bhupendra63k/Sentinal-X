from core.security_analysis_engine import SecurityAnalysisEngine


def test_correlation_risk_returns_highest_severity():

    findings = [
        {
            "finding_id": "NETWORK-80",
            "severity": "Medium"
        },
        {
            "finding_id": "WEB-001",
            "severity": "High"
        },
        {
            "finding_id": "WEB-002",
            "severity": "Low"
        }
    ]

    engine = SecurityAnalysisEngine()

    risk = engine.correlation_risk(findings)

    assert risk == "High"


def test_correlation_risk_returns_critical_when_present():

    findings = [
        {
            "finding_id": "NETWORK-23",
            "severity": "High"
        },
        {
            "finding_id": "WEB-001",
            "severity": "Critical"
        }
    ]

    engine = SecurityAnalysisEngine()

    risk = engine.correlation_risk(findings)

    assert risk == "Critical"


def test_correlation_risk_returns_medium_when_no_higher_severity_exists():

    findings = [
        {
            "finding_id": "NETWORK-80",
            "severity": "Medium"
        },
        {
            "finding_id": "WEB-001",
            "severity": "Low"
        },
        {
            "finding_id": "NETWORK-22",
            "severity": "Info"
        }
    ]

    engine = SecurityAnalysisEngine()

    risk = engine.correlation_risk(findings)

    assert risk == "Medium"


def test_correlation_risk_returns_low_when_only_low_and_info_exist():

    findings = [
        {
            "finding_id": "WEB-001",
            "severity": "Low"
        },
        {
            "finding_id": "NETWORK-22",
            "severity": "Info"
        }
    ]

    engine = SecurityAnalysisEngine()

    risk = engine.correlation_risk(findings)

    assert risk == "Low"


def test_correlation_risk_returns_info_when_only_info_exists():

    findings = [
        {
            "finding_id": "NETWORK-22",
            "severity": "Info"
        }
    ]

    engine = SecurityAnalysisEngine()

    risk = engine.correlation_risk(findings)

    assert risk == "Info"


def test_correlation_risk_returns_info_when_empty():

    engine = SecurityAnalysisEngine()

    risk = engine.correlation_risk([])

    assert risk == "Info"


def test_correlation_risk_defaults_missing_severity_to_info():

    findings = [
        {
            "finding_id": "NETWORK-22"
        }
    ]

    engine = SecurityAnalysisEngine()

    risk = engine.correlation_risk(findings)

    assert risk == "Info"