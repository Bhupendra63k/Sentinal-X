import subprocess
from unittest.mock import patch

from scanners.reconnaissance.nmap.nmap_scanner import NmapScanner


def test_nmap_scan_returns_none_when_timed_out():
    scanner = NmapScanner()

    with patch(
        "scanners.reconnaissance.nmap.nmap_scanner.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=300),
    ) as mock_run:
        result = scanner.scan("quick", "192.0.2.10")

    assert result is None
    assert mock_run.call_args.kwargs["timeout"] == 300

