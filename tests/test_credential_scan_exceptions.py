
from unittest.mock import patch

from scanners.credential_security.credential_scanner import CredentialScanner


def test_hash_identification_exception_returns_safe_failure():
    scanner = CredentialScanner()

    with patch.object(
        scanner.identifier,
        "identify",
        side_effect=RuntimeError("internal test detail"),
    ):
        result = scanner.scan(
            scan_type="hash_identification",
            target="test-hash",
        )

    assert result["status"] == "FAILED"
    assert result["error"] == "Credential scan failed unexpectedly."
    assert result["timestamp"]
    assert result["duration"] != "Unknown"
    assert "internal test detail" not in str(result)
