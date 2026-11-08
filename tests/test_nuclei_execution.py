from unittest.mock import patch

from scanners.reconnaissance.nuclei.nuclei_scanner import NucleiScanner


def test_nuclei_returns_none_when_process_fails():
    scanner = NucleiScanner()

    with patch(
        "scanners.reconnaissance.nuclei.nuclei_scanner.subprocess.run"
    ) as mock_run:
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = "simulated error"

        result = scanner.scan("default", "http://127.0.0.1:8000")

    assert result is None
id="nuclei-test"
