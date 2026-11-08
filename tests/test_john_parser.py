def test_parse_show_output():
    from scanners.credential_security.john.john_parser import JohnParser

    parser = JohnParser()

    result = parser.parse({
        "tool": "john",
        "return_code": 0,
        "stdout": "",
        "stderr": "",
        "show_stdout": "?:test\n1 password hash cracked, 0 left\n",
        "hash_file": "tests/test_hashes.txt"
    })

    assert result["cracked"] is True
    assert result["password"] == "test"
    assert result["hash_file"] == "tests/test_hashes.txt"