
from unittest.mock import patch

from scanners.credential_security.credential_scanner import CredentialScanner


def test_hashcat_rejects_same_hash_and_wordlist_file(tmp_path):
    file_path = tmp_path / "input.txt"
    file_path.write_text("example-data", encoding="utf-8")

    scanner = CredentialScanner()

    with patch.object(scanner.hashcat_runner, "run") as mock_run:
        result = scanner.scan(
            scan_type="hashcat",
            target="test-target",
            hash_file=str(file_path),
            mode="0",
            wordlist=str(file_path),
        )

    assert result["hashcat_result"]["return_code"] == -1
    assert "must be different files" in result["hashcat_result"]["stderr"]
    mock_run.assert_not_called()
