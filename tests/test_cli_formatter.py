from formatter.cli_formatter import CLIFormatter


def test_display_full_scan_summary_shows_security_analysis(capsys):
    formatter = CLIFormatter()

    result = {
        "target": "127.0.0.1",
        "duration": 12,
        "summary": {
            "total": 3
        },
        "scanners": [
            "Nmap",
            "Nikto",
            "Nuclei"
        ],
        "scan_types": [
            "quick",
            "basic",
            "default"
        ],
        "findings": [
            {
                "scanner": "Nmap",
                "finding_id": "NMAP-001"
            },
            {
                "scanner": "Nikto",
                "finding_id": "NIKTO-001"
            },
            {
                "scanner": "Nuclei",
                "finding_id": "NUCLEI-001"
            }
        ],
        "analysis": {
            "overall_risk": "Critical",
            "insights": [
                {
                    "title": "Multiple security findings detected"
                }
            ],
            "recommendations": [
                "Investigate the affected target immediately."
            ]
        }
    }

    formatter.display_full_scan_summary(result)

    output = capsys.readouterr().out

    assert "FULL SCAN SUMMARY" in output
    assert "127.0.0.1" in output
    assert "12 seconds" in output
    assert "Total Findings" in output
    assert "Critical" in output

    assert "Nmap" in output
    assert "Nikto" in output
    assert "Nuclei" in output