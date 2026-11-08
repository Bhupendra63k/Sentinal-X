
from unittest.mock import patch

from scanners.credential_security.credential_scanner import CredentialScanner


def test_hashcat_duration_is_exposed_at_top_level(tmp_path):
    hash_file = tmp_path / "hashes.txt"
    wordlist = tmp_path / "wordlist.txt"
    hash_file.write_text("example-hash", encoding="utf-8")
    wordlist.write_text("example-password", encoding="utf-8")

    scanner = CredentialScanner()

    with patch.object(
        scanner.hashcat_runner,
        "run",
        return_value={
            "tool": "hashcat",
            "return_code": 0,
            "stdout": "",
            "stderr": "",
        },
    ):
        result = scanner.scan(
            scan_type="hashcat",
            target="test-target",
            hash_file=str(hash_file),
            mode="0",
            wordlist=str(wordlist),
        )

    assert isinstance(result["duration"], float)
    assert result["duration"] >= 0



def test_hash_identification_duration_is_reported():
    scanner = CredentialScanner()

    with patch.object(scanner.identifier, "identify", return_value=[]):
        result = scanner.scan(
            scan_type="hash_identification",
            target="test-hash",
        )

    assert isinstance(result["duration"], float)
    assert result["duration"] >= 0
