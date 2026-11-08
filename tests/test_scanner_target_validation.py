
import pytest

from backend.scanner_target_validation import validate_scanner_target


@pytest.mark.parametrize(
    "target",
    [
        "127.0.0.1",
        "scanme.nmap.org",
        "localhost",
    ],
)
def test_nmap_accepts_ip_and_hostname(target):
    assert validate_scanner_target("nmap", target) == target


@pytest.mark.parametrize(
    "target",
    [
        "https://example.com",
        "http://127.0.0.1",
    ],
)
def test_nmap_rejects_urls(target):
    with pytest.raises(ValueError, match="Nmap requires"):
        validate_scanner_target("nmap", target)
