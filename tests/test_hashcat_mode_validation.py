
from unittest.mock import patch

from scanners.credential_security.hashcat.hashcat_runner import HashcatRunner


def test_invalid_mode_is_rejected():
    runner = HashcatRunner()

    with patch(
        "scanners.credential_security.hashcat.hashcat_runner.subprocess.run"
    ) as mock_run:
        result = runner.run("hashes.txt", "invalid", "wordlist.txt")

    assert result["return_code"] == -1
    assert "Invalid Hashcat mode" in result["stderr"]
    mock_run.assert_not_called()


def test_blank_mode_is_rejected():
    runner = HashcatRunner()

    with patch(
        "scanners.credential_security.hashcat.hashcat_runner.subprocess.run"
    ) as mock_run:
        result = runner.run("hashes.txt", " ", "wordlist.txt")

    assert result["return_code"] == -1
    assert "Invalid Hashcat mode" in result["stderr"]
    mock_run.assert_not_called()


def test_numeric_mode_is_passed_to_hashcat():
    runner = HashcatRunner()

    with patch(
        "scanners.credential_security.hashcat.hashcat_runner.subprocess.run"
    ) as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""

        result = runner.run("hashes.txt", "0", "wordlist.txt")

    assert result["return_code"] == 0
    command = mock_run.call_args.args[0]
    assert command[command.index("-m") + 1] == "0"
