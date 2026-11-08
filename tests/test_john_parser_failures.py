
from scanners.credential_security.john.john_parser import JohnParser


def test_failed_execution_does_not_report_cracked_password():
    parser = JohnParser()

    result = parser.parse({
        "return_code": 1,
        "stdout": "example-hash:example-password",
        "show_stdout": "",
        "stderr": "John execution failed",
    })

    assert result["return_code"] == 1
    assert result["cracked"] is False
    assert result["password"] is None


def test_successful_execution_parses_password():
    parser = JohnParser()

    result = parser.parse({
        "return_code": 0,
        "stdout": "",
        "show_stdout": "example-hash:example-password",
        "stderr": "",
    })

    assert result["cracked"] is True
    assert result["password"] == "example-password"


def test_successful_execution_without_password_is_not_cracked():
    parser = JohnParser()

    result = parser.parse({
        "return_code": 0,
        "stdout": "No passwords cracked",
        "show_stdout": "",
        "stderr": "",
    })

    assert result["cracked"] is False
    assert result["password"] is None
