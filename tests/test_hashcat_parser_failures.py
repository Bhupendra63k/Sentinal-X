
from scanners.credential_security.hashcat.hashcat_parser import HashcatParser


def test_nonzero_exit_code_does_not_mark_password_as_cracked():
    parser = HashcatParser()

    result = parser.parse({
        "tool": "hashcat",
        "return_code": 2,
        "stdout": "possibly misleading output",
        "stderr": "Hashcat execution failed",
    })

    assert result["return_code"] == 2
    assert result["cracked"] is False
    assert result["password"] is None
    assert result["stderr"] == "Hashcat execution failed"


def test_empty_stdout_does_not_mark_password_as_cracked():
    parser = HashcatParser()

    result = parser.parse({
        "return_code": 0,
        "stdout": "",
        "stderr": "",
    })

    assert result["cracked"] is False
    assert result["password"] is None


def test_successful_output_extracts_first_password():
    parser = HashcatParser()

    result = parser.parse({
        "return_code": 0,
        "stdout": "example-password\nanother-password\n",
        "stderr": "",
    })

    assert result["cracked"] is True
    assert result["password"] == "example-password"
