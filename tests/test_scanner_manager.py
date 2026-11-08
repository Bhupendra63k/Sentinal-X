from core.scanner_manager import ScannerManager


class FakeScanner:
    name = "fake_scanner"

    def scan(self, scan_type, target, hash_file=None, mode=None, wordlist=None):
        return {
            "scan_type": scan_type,
            "target": target,
            "hash_file": hash_file,
            "mode": mode,
            "wordlist": wordlist
        }


def test_scanner_manager_passes_optional_parameters():
    manager = ScannerManager()

    scanner = FakeScanner()
    manager.register_scanner(scanner)

    result = manager.start_scan(
        scanner_name="fake_scanner",
        scan_type="john",
        target="test-hash",
        hash_file="tests/test_hashes.txt",
        mode=None,
        wordlist="tests/test_wordlist.txt"
    )

    assert result["scan_type"] == "john"
    assert result["target"] == "test-hash"
    assert result["hash_file"] == "tests/test_hashes.txt"
    assert result["mode"] is None
    assert result["wordlist"] == "tests/test_wordlist.txt"