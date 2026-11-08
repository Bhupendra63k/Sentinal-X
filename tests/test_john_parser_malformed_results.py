
from scanners.credential_security.john.john_parser import JohnParser


def test_parser_handles_none_result():
    result = JohnParser().parse(None)

    assert result["return_code"] == -1
    assert result["cracked"] is False
    assert result["password"] is None


def test_parser_handles_none_output():
    result = JohnParser().parse({
        "return_code": 0,
        "stdout": None,
        "show_stdout": None,
        "stderr": None,
    })

    assert result["stdout"] == ""
    assert result["show_stdout"] == ""
    assert result["stderr"] == ""
    assert result["cracked"] is False


def test_parser_handles_non_string_output():
    result = JohnParser().parse({
        "return_code": 0,
        "stdout": 123,
        "show_stdout": ["unexpected"],
        "stderr": {"error": "unexpected"},
    })

    assert result["stdout"] == ""
    assert result["show_stdout"] == ""
    assert result["stderr"] == ""
    assert result["cracked"] is False


def test_parser_rejects_boolean_return_code():
    result = JohnParser().parse({
        "return_code": True,
        "show_stdout": "example-hash:example-password",
    })

    assert result["return_code"] == -1
    assert result["cracked"] is False
    assert result["password"] is None


def test_parser_still_extracts_successful_password():
    result = JohnParser().parse({
        "return_code": 0,
        "stdout": "",
        "show_stdout": "example-hash:example-password",
    })

    assert result["cracked"] is True
    assert result["password"] == "example-password"
