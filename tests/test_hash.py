from scanners.credential_security.credential_scanner import CredentialScanner


def test_credential_scanner():
    """Test basic hash identification through CredentialScanner."""

    scanner = CredentialScanner()

    result = scanner.scan(
        "hash_identification",
        "5f4dcc3b5aa765d61d8327deb882cf99"
    )

    # Basic result structure
    assert isinstance(result, dict)
    assert result["scanner"] == "credential_scanner"
    assert result["scan_type"] == "hash_identification"
    assert result["target"] == "5f4dcc3b5aa765d61d8327deb882cf99"

    # Findings should be returned
    assert "findings" in result
    assert isinstance(result["findings"], list)
    assert len(result["findings"]) > 0

    # Check Finding structure
    finding = result["findings"][0]

    assert isinstance(finding, dict)
    assert "scanner" in finding
    assert "target" in finding
    assert "finding_id" in finding
    assert "title" in finding
    assert "severity" in finding
    assert "description" in finding
    assert "evidence" in finding
    assert "recommendation" in finding


def test_credential_scanner_john():
    scanner = CredentialScanner()

    result = scanner.scan(
        "john",
        "5f4dcc3b5aa765d61d8327deb882cf99",
        "tests/test_hashes.txt",
        wordlist="tests/test_wordlist.txt"
    )

    assert isinstance(result, dict)
    assert result["scanner"] == "credential_scanner"
    assert result["scan_type"] == "john"
    assert result["target"] == "5f4dcc3b5aa765d61d8327deb882cf99"

    assert "john_result" in result
    assert isinstance(result["john_result"], dict)
    assert result["john_result"]["tool"] == "john"