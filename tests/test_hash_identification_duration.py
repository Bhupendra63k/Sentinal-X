
from unittest.mock import patch

from scanners.credential_security.credential_scanner import CredentialScanner


def test_hash_identification_reports_duration():
    scanner = CredentialScanner()

    with patch.object(scanner.identifier, "identify", return_value=[]):
        result = scanner.scan(
            scan_type="hash_identification",
            target="test-hash",
        )

    assert isinstance(result["duration"], float)
    assert result["duration"] >= 0
    assert result["status"] == "COMPLETED"
