from unittest.mock import patch

from scanners.reconnaissance.Nikto.nikto_scanner import NiktoScanner


def test_nikto_returns_none_when_process_fails():
    scanner = NiktoScanner()

    with patch(
        "scanners.reconnaissance.Nikto.nikto_scanner.subprocess.run"
    ) as mock_run:
        mock_run.return_value.returncode = 2
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = "simulated error"

        result = scanner.scan("basic", "http://127.0.0.1:8000")

    assert result is None
id="nikto-test"
