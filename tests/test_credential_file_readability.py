
from pathlib import Path
from unittest.mock import mock_open, patch

from scanners.credential_security.credential_scanner import CredentialScanner


def test_unreadable_hash_file_is_rejected(tmp_path):
    hash_file = tmp_path / "hashes.txt"
    wordlist = tmp_path / "wordlist.txt"

    hash_file.write_text("example-hash", encoding="utf-8")
    wordlist.write_text("example-password", encoding="utf-8")

    scanner = CredentialScanner()

    original_open = Path.open

    def mocked_open(path, *args, **kwargs):
        if path == hash_file:
            raise PermissionError("Access denied")
        return original_open(path, *args, **kwargs)

    with patch.object(Path, "open", mocked_open):
        with patch.object(
            scanner.hashcat_runner, "run"
        ) as mock_run:
            result = scanner.scan(
                scan_type="hashcat",
                target="test-target",
                hash_file=str(hash_file),
                mode="0",
                wordlist=str(wordlist),
            )

    assert result["hashcat_result"]["return_code"] == -1
    assert "cannot be read" in result["hashcat_result"]["stderr"]
    mock_run.assert_not_called()
