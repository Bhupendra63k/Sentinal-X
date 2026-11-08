
from datetime import datetime

from scanners.credential_security.credential_scanner import CredentialScanner


def test_hash_identification_result_includes_utc_timestamp():
    scanner = CredentialScanner()
    result = scanner.scan(
        scan_type="hash_identification",
        target="test-hash",
    )

    timestamp = result["timestamp"]
    parsed = datetime.fromisoformat(timestamp)

    assert parsed.tzinfo is not None
    assert parsed.utcoffset().total_seconds() == 0
