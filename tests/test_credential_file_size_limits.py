
from scanners.credential_security.credential_scanner import CredentialScanner


def test_oversized_hash_file_is_rejected(tmp_path):
    hash_file = tmp_path / "hashes.txt"
    wordlist = tmp_path / "wordlist.txt"

    hash_file.write_bytes(b"x" * (10 * 1024 * 1024 + 1))
    wordlist.write_text("example-password", encoding="utf-8")

    scanner = CredentialScanner()
    result = scanner.scan(
        scan_type="hashcat",
        target="test-target",
        hash_file=str(hash_file),
        mode="0",
        wordlist=str(wordlist),
    )

    assert result["hashcat_result"]["return_code"] == -1
    assert "exceeds the maximum size" in result["hashcat_result"]["stderr"]


def test_oversized_wordlist_is_rejected(tmp_path):
    hash_file = tmp_path / "hashes.txt"
    wordlist = tmp_path / "wordlist.txt"

    hash_file.write_text("example-hash", encoding="utf-8")
    wordlist.write_bytes(b"x" * (2 * 1024 * 1024 * 1024 + 1))

    scanner = CredentialScanner()
    result = scanner.scan(
        scan_type="john",
        target="test-target",
        hash_file=str(hash_file),
        wordlist=str(wordlist),
    )

    assert result["john_result"]["return_code"] == -1
    assert "exceeds the maximum size" in result["john_result"]["stderr"]
