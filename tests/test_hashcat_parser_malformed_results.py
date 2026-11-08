
from scanners.credential_security.hashcat.hashcat_parser import HashcatParser


def test_parser_handles_none_result():
    result = HashcatParser().parse(None)

    assert result["return_code"] == -1
    assert result["cracked"] is False
    assert result["password"] is None


def test_parser_handles_none_stdout_and_stderr():
    result = HashcatParser().parse({
        "return_code": 0,
        "stdout": None,
        "stderr": None,
    })

    assert result["stdout"] == ""
    assert result["stderr"] == ""
    assert result["cracked"] is False


def test_parser_handles_non_string_output():
    result = HashcatParser().parse({
        "return_code": 0,
        "stdout": 123,
        "stderr": ["unexpected", "data"],
    })

    assert result["stdout"] == ""
    assert result["stderr"] == ""
    assert result["cracked"] is False


def test_parser_rejects_non_integer_return_code():
    result = HashcatParser().parse({
        "return_code": "0",
        "stdout": "example-password",
        "stderr": "",
    })

    assert result["return_code"] == -1
    assert result["cracked"] is False
    assert result["password"] is None
