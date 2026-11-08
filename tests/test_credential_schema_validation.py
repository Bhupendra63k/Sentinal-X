
import pytest
from pydantic import ValidationError

from backend.schemas import CredentialScanRequest


def test_hash_file_rejects_whitespace():
    with pytest.raises(ValidationError):
        CredentialScanRequest(
            scan_type="hashcat",
            target="test-hash",
            hash_file="   ",
            wordlist="wordlist.txt",
            mode="0",
        )


def test_wordlist_rejects_whitespace():
    with pytest.raises(ValidationError):
        CredentialScanRequest(
            scan_type="john",
            target="test-hash",
            hash_file="hashes.txt",
            wordlist="   ",
        )


@pytest.mark.parametrize("mode", ["", "   ", "abc", "-1"])
def test_mode_rejects_invalid_values(mode):
    with pytest.raises(ValidationError):
        CredentialScanRequest(
            scan_type="hashcat",
            target="test-hash",
            hash_file="hashes.txt",
            wordlist="wordlist.txt",
            mode=mode,
        )


def test_mode_accepts_zero():
    request = CredentialScanRequest(
        scan_type="hashcat",
        target="test-hash",
        hash_file="hashes.txt",
        wordlist="wordlist.txt",
        mode="0",
    )

    assert request.mode == "0"
