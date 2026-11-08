from unittest.mock import patch

from scanners.credential_security.john.john_runner import JohnRunner


def test_john_show_command(monkeypatch):
    runner = JohnRunner()
    captured = {}

    class FakeResult:
        returncode = 0
        stdout = "098f6bcd4621d373cade4e832627b4f6:test\n"
        stderr = ""

    def fake_run(command, capture_output, text, timeout=None):
        captured["command"] = command
        captured["timeout"] = timeout
        return FakeResult()

    monkeypatch.setattr(
        "scanners.credential_security.john.john_runner.subprocess.run",
        fake_run,
    )

    result = runner.show_cracked("tests/test_hashes2.txt")

    assert captured["command"] == [
        "john",
        "--show",
        "--format=Raw-MD5",
        "--pot=tests/test_john.pot",
        "tests/test_hashes2.txt",
    ]
    assert captured["timeout"] == 1800
    assert result["tool"] == "john"
    assert result["return_code"] == 0
    assert result["stdout"] == (
        "098f6bcd4621d373cade4e832627b4f6:test\n"
    )


def test_john_show_not_installed(monkeypatch):
    runner = JohnRunner()

    def fake_run(command, capture_output, text, timeout=None):
        raise FileNotFoundError

    monkeypatch.setattr(
        "scanners.credential_security.john.john_runner.subprocess.run",
        fake_run,
    )

    result = runner.show_cracked("tests/test_hashes2.txt")

    assert result["tool"] == "john"
    assert result["return_code"] == -1
    assert "not installed" in result["stderr"].lower()
id="john-show-full"
