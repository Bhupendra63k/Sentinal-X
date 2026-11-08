from uuid import UUID
from unittest.mock import patch

from scanners.credential_security.credential_scanner import CredentialScanner


def test_scan_result_includes_valid_unique_id():
    scanner = CredentialScanner()

    with patch.object(scanner.identifier, "identify", return_value=[]):
        first = scanner.scan(
            scan_type="hash_identification",
            target="test-hash",
        )
        second = scanner.scan(
            scan_type="hash_identification",
            target="test-hash",
        )

    UUID(first["scan_id"])
    UUID(second["scan_id"])

    assert first["scan_id"] != second["scan_id"]


def test_unsupported_scan_also_includes_id():
    result = CredentialScanner().scan(
        scan_type="unsupported",
        target="test-target",
    )

    UUID(result["scan_id"])
    assert result["status"] == "FAILED"
