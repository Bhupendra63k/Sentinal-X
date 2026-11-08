from core.security_analysis_engine import SecurityAnalysisEngine


def test_correlate_multiple_scanners_same_target():

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
            "title": "Web server issue detected",
            "severity": "High",
            "description": "Web server security issue",
            "evidence": "HTTP response"
        }
    ]

    engine = SecurityAnalysisEngine()

    correlations = engine.correlate(findings)

    assert len(correlations) == 1

    correlation = correlations[0]

    assert correlation["target"] == "127.0.0.1"
    assert correlation["finding_count"] == 2

    assert set(correlation["scanners"]) == {
        "Nmap",
        "Nikto"
    }

    assert set(correlation["finding_ids"]) == {
        "NETWORK-80",
        "WEB-001"
    }


def test_correlate_single_scanner():

    findings = [
        {
            "scanner": "Nmap",
            "target": "127.0.0.1",
            "finding_id": "NETWORK-22",
            "title": "SSH port exposed",
            "severity": "Medium"
        }
    ]

    engine = SecurityAnalysisEngine()

    correlations = engine.correlate(findings)

    assert correlations == []


def test_generate_critical_recommendation():

    insights = [
        {
            "type": "SECURITY_INSIGHT",
            "target": "127.0.0.1",
            "severity": "Critical",
            "title": "Multiple security findings detected",
            "correlation_type": "WEB_ATTACK_SURFACE",
            "finding_ids": [
                "NETWORK-80",
                "WEB-001"
            ]
        }
    ]

    engine = SecurityAnalysisEngine()

    recommendations = engine.generate_recommendations(
        insights
    )

    assert len(recommendations) == 1

    recommendation = recommendations[0]

    assert recommendation["type"] == (
        "SECURITY_RECOMMENDATION"
    )

    assert recommendation["target"] == "127.0.0.1"
    assert recommendation["severity"] == "Critical"

    assert recommendation["action"] == (
        "Investigate the affected target immediately, "
        "validate the findings, and prioritize remediation."
    )

    assert recommendation["finding_ids"] == [
        "NETWORK-80",
        "WEB-001"
    ]


def test_generate_high_recommendation():

    insights = [
        {
            "type": "SECURITY_INSIGHT",
            "target": "127.0.0.1",
            "severity": "High",
            "title": "Multiple security findings detected",
            "correlation_type": "WEB_ATTACK_SURFACE",
            "finding_ids": [
                "NETWORK-80"
            ]
        }
    ]

    engine = SecurityAnalysisEngine()

    recommendations = engine.generate_recommendations(
        insights
    )

    assert len(recommendations) == 1

    recommendation = recommendations[0]

    assert recommendation["severity"] == "High"

    assert recommendation["action"] == (
        "Investigate the affected target and prioritize "
        "remediation of the related findings."
    )


def test_generate_low_recommendation():

    insights = [
        {
            "type": "SECURITY_INSIGHT",
            "target": "127.0.0.1",
            "severity": "Low",
            "title": "Multiple security findings detected",
            "correlation_type": "GENERAL",
            "finding_ids": [
                "NETWORK-22"
            ]
        }
    ]

    engine = SecurityAnalysisEngine()

    recommendations = engine.generate_recommendations(
        insights
    )

    assert len(recommendations) == 1

    recommendation = recommendations[0]

    assert recommendation["severity"] == "Low"

    assert recommendation["action"] == (
        "Review the related findings and address the "
        "identified security issues."
    )


def test_generate_recommendations_no_insights():

    engine = SecurityAnalysisEngine()

    recommendations = engine.generate_recommendations([])

    assert recommendations == []