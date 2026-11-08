from unittest.mock import patch

from scanners.credential_security.credential_scanner import CredentialScanner


def test_hashcat_rejects_missing_files():
    scanner = CredentialScanner()

    with patch.object(scanner.hashcat_runner, "run") as mock_run:
        result = scanner.scan(
            scan_type="hashcat",
            target="test-target",
            hash_file="missing_hashes.txt",
            mode="0",
            wordlist="missing_wordlist.txt",
        )

    assert result["hashcat_result"]["return_code"] == -1
    assert "does not exist" in result["hashcat_result"]["stderr"]
    mock_run.assert_not_called()


def test_john_rejects_missing_files():
    scanner = CredentialScanner()

    with patch.object(scanner.john_runner, "run") as mock_run:
        result = scanner.scan(
            scan_type="john",
            target="test-target",
            hash_file="missing_hashes.txt",
            wordlist="missing_wordlist.txt",
        )

    assert result["john_result"]["return_code"] == -1
    assert "does not exist" in result["john_result"]["stderr"]
    mock_run.assert_not_called()
id="credential-file-validation-tests"
