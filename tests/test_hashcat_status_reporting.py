
from unittest.mock import patch

from scanners.credential_security.credential_scanner import CredentialScanner


def test_hashcat_failed_execution_has_failed_status(tmp_path):
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
            "return_code": 1,
            "stdout": "",
            "stderr": "Execution failed",
        },
    ):
        result = scanner.scan(
            scan_type="hashcat",
            target="test-target",
            hash_file=str(hash_file),
            mode="0",
            wordlist=str(wordlist),
        )

    assert result["hashcat_result"]["status"] == "FAILED"
    assert result["hashcat_result"]["cracked"] is False
