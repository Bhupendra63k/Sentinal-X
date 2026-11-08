from scanners.credential_security.hashcat.hashcat_parser import HashcatParser

def test_hashcat_parser_cracked_result():
    parser=HashcatParser()
    result={
        "tool":"hashcat",
        "return_code":0,
        "stdout":"password123",
        "stderr":""
    }
    parsed=parser.parse(result)

    assert parsed["tool"]=="hashcat"
    assert parsed["cracked"] is True
    assert parsed["password"] == "password123"

def test_hashcat_parser_no_result():
    parser=HashcatParser()
    result={
        "tool":"hashcat",
        "return_code":-1,
        "stdout":"",
        "stderr":""
    }
    parsed=parser.parse(result)

    assert parsed["tool"]=="hashcat"
    assert parsed["cracked"] is False
    assert parsed["password"] is None
