import main


def test_main_full_security_scan(monkeypatch, capsys):

    class FakeOrchestrator:

        def __init__(self, scanner_manager):
            pass

        def run_full_scan(self, target):
            return {
                "results": [
                    {
                        "scanner": "Nmap",
                        "scan_type": "quick",
                        "target": target,
                        "findings": [
                            {
                                "scanner": "Nmap",
                                "target": target,
                                "finding_id": "NETWORK-22",
                                "title": "SSH port exposed",
                                "severity": "High",
                                "description": "SSH service detected",
                                "evidence": "22/tcp open ssh"
                            }
                        ]
                    },
                    {
                        "scanner": "Nikto",
                        "scan_type": "basic",
                        "target": target,
                        "findings": [
                            {
                                "scanner": "Nikto",
                                "target": target,
                                "finding_id": "WEB-001",
                                "title": "Web security issue",
                                "severity": "Critical",
                                "description": "Critical web issue detected",
                                "evidence": "HTTP response"
                            }
                        ]
                    }
                ],
                "execution_results": []
            }


    class FakeScannerManager:

        def __init__(self):
            pass

        def register_scanner(self, scanner):
            pass


    monkeypatch.setattr(
        main,
        "ScanOrchestrator",
        FakeOrchestrator
    )

    monkeypatch.setattr(
        main,
        "ScannerManager",
        FakeScannerManager
    )


    inputs = iter([
        "4",
        "127.0.0.1"
    ])

    monkeypatch.setattr(
        "builtins.input",
        lambda _: next(inputs)
    )


    # Prevent actual history/report/log writes
    monkeypatch.setattr(
        main,
        "process_scan_result",
        lambda result: None
    )


    main.main()

    output = capsys.readouterr().out


    assert "FULL SECURITY SCAN" in output

    assert "SECURITY ANALYSIS REPORT" in output

    assert "Overall Risk: Critical" in output

    assert "Total Findings: 2" in output

    assert "Security Insights" in output

    assert "Recommendations" in output

    assert "127.0.0.1" in output