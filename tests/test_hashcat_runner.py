import subprocess
from unittest.mock import patch

from scanners.credential_security.hashcat.hashcat_runner import HashcatRunner


def test_hashcat_timeout_returns_structured_error():
    runner = HashcatRunner()

    with patch(
        "scanners.credential_security.hashcat.hashcat_runner.subprocess.run",
        side_effect=subprocess.TimeoutExpired(
            cmd="hashcat",
            timeout=1800
        ),
    ) as mock_run:
        result = runner.run("test_hashes.txt", "0", "test_wordlist.txt")

    assert result["tool"] == "hashcat"
    assert result["return_code"] == -1
    assert "timed out" in result["stderr"].lower()
    assert mock_run.call_args.kwargs["timeout"] == 1800
id="hashcat-test"
