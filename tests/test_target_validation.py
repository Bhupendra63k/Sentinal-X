
import pytest

from backend.target_validation import validate_target


@pytest.mark.parametrize(
    "target",
    [
        "127.0.0.1",
        "192.168.1.10",
        "scanme.nmap.org",
        "localhost",
        "https://example.com",
        "http://127.0.0.1:8080/path",
        "https://example.com/login",
        "2001:db8::1",
    ],
)
def test_valid_targets_are_accepted(target):
    assert validate_target(target) == target


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        "scan me.example",
        "https://",
        "http://example.com:99999",
        "-invalid.example",
        "https://user:password@example.com",
    ],
)
def test_invalid_targets_are_rejected(target):
    with pytest.raises(ValueError):
        validate_target(target)
