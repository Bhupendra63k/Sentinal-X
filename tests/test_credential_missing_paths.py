
from unittest.mock import patch

from scanners.credential_security.credential_scanner import CredentialScanner


def test_missing_hash_file_returns_structured_error():
    scanner = CredentialScanner()

    with patch.object(scanner.hashcat_runner, "run") as mock_run:
        result = scanner.scan(
            scan_type="hashcat",
            target="test-target",
            hash_file=None,
            mode="0",
            wordlist="wordlist.txt",
        )

    error = result["hashcat_result"]

    assert error["return_code"] == -1
    assert error["cracked"] is False
    assert error["password"] is None
    assert "Hash file is required" in error["stderr"]
    mock_run.assert_not_called()


def test_missing_wordlist_returns_structured_error():
    scanner = CredentialScanner()

    with patch.object(scanner.john_runner, "run") as mock_run:
        result = scanner.scan(
            scan_type="john",
            target="test-target",
            hash_file="hashes.txt",
            wordlist=None,
        )

    error = result["john_result"]

    assert error["return_code"] == -1
    assert error["cracked"] is False
    assert error["password"] is None
    assert "Wordlist is required" in error["stderr"]
    mock_run.assert_not_called()
