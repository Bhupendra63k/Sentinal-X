
import logging
from unittest.mock import patch

from scanners.credential_security.credential_scanner import CredentialScanner


def test_unexpected_exception_is_logged():
    scanner = CredentialScanner()

    with patch.object(
        scanner.identifier,
        "identify",
        side_effect=RuntimeError("internal test detail"),
    ):
        with patch(
            "scanners.credential_security.credential_scanner.logger"
        ) as mock_logger:
            result = scanner.scan(
                scan_type="hash_identification",
                target="test-hash",
            )

    assert result["status"] == "FAILED"
    assert result["error"] == "Credential scan failed unexpectedly."
    mock_logger.exception.assert_called_once_with(
        "Credential scan failed unexpectedly."
    )


from unittest.mock import patch

from scanners.credential_security.credential_scanner import CredentialScanner


def test_exception_log_message_does_not_include_sensitive_values():
    scanner = CredentialScanner()
    sensitive_value = "example-secret-password"

    with patch.object(
        scanner.identifier,
        "identify",
        side_effect=RuntimeError(sensitive_value),
    ):
        with patch(
            "scanners.credential_security.credential_scanner.logger"
        ) as mock_logger:
            result = scanner.scan(
                scan_type="hash_identification",
                target="test-hash",
            )

    assert result["status"] == "FAILED"
    assert sensitive_value not in str(result)
    mock_logger.exception.assert_called_once_with(
        "Credential scan failed unexpectedly."
    )
