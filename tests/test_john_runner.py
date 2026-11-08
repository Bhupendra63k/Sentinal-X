import subprocess
from unittest.mock import patch

from scanners.credential_security.john.john_runner import JohnRunner


def test_john_runner_initialization():
    runner = JohnRunner()

    assert runner.name == "john"


def test_john_runner_command(monkeypatch):
    runner = JohnRunner()
    captured = {}

    class FakeResult:
        returncode = 0
        stdout = "user:hello123"
        stderr = ""

    def fake_run(command, capture_output, text, timeout=None):
        captured["command"] = command
        captured["timeout"] = timeout
        return FakeResult()

    monkeypatch.setattr(
        "scanners.credential_security.john.john_runner.subprocess.run",
        fake_run,
    )

    result = runner.run(
        "tests/test_hashes.txt",
        "tests/test_wordlist.txt",
    )

    assert captured["command"] == [
        "john",
        "--format=Raw-MD5",
        "--pot=tests/test_john.pot",
        "--wordlist=tests/test_wordlist.txt",
        "tests/test_hashes.txt",
    ]
    assert captured["timeout"] == 1800
    assert result["tool"] == "john"
    assert result["return_code"] == 0
    assert result["stdout"] == "user:hello123"


def test_john_runner_not_installed(monkeypatch):
    runner = JohnRunner()

    def fake_run(command, capture_output, text, timeout=None):
        raise FileNotFoundError

    monkeypatch.setattr(
        "scanners.credential_security.john.john_runner.subprocess.run",
        fake_run,
    )

    result = runner.run(
        "tests/test_hashes.txt",
        "tests/test_wordlist.txt",
    )

    assert result["tool"] == "john"
    assert result["return_code"] == -1
    assert "not installed" in result["stderr"].lower()


def test_john_runner_timeout_returns_structured_error():
    runner = JohnRunner()

    with patch(
        "scanners.credential_security.john.john_runner.subprocess.run",
        side_effect=subprocess.TimeoutExpired(
            cmd="john",
            timeout=1800,
        ),
    ) as mock_run:
        result = runner.run(
            "tests/test_hashes.txt",
            "tests/test_wordlist.txt",
        )

    assert result["tool"] == "john"
    assert result["return_code"] == -1
    assert "timed out" in result["stderr"].lower()
    assert result["stdout"] == ""
    assert mock_run.call_args.kwargs["timeout"] == 1800
