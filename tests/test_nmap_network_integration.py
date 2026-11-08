from scanners.reconnaissance.nmap.nmap_scanner import NmapScanner


def test_finding_manager_prevents_duplicate_network_findings(monkeypatch):

    nmap_output = """\
Nmap scan report for localhost (127.0.0.1)
Host is up (0.0010s latency).
PORT     STATE SERVICE
23/tcp   open  telnet
3306/tcp open  mysql
"""

    def fake_run(*args, **kwargs):

        class FakeResult:
            stdout = nmap_output
            returncode = 0

        return FakeResult()

    monkeypatch.setattr(
        "subprocess.run",
        fake_run
    )

    scanner = NmapScanner()

    scanner.scan(
        scan_type="quick",
        target="127.0.0.1"
    )

    first_count = scanner.finding_manager.count()

    scanner.scan(
        scan_type="quick",
        target="127.0.0.1"
    )

    second_count = scanner.finding_manager.count()

    assert second_count == first_count