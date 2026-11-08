import pytest
from core.scan_orchestrator import ScanOrchestrator


class FakeScannerManager:
    """Fake scanner manager to simulate scanner calls and results."""

    def __init__(self, results=None):
        self.results = results or {}
        self.calls = []

    def start_scan(self, scanner_name, scan_type, target):
        """Record scanner call and return predefined result."""
        self.calls.append({
            "scanner_name": scanner_name,
            "scan_type": scan_type,
            "target": target
        })

        return self.results.get(scanner_name)


# -------------------------------
# Core Behavior Tests
# -------------------------------

def test_full_scan_calls_all_scanners():
    """Ensure all scanners are invoked and results collected."""

    manager = FakeScannerManager(
        results={
            "nmap": {"scanner": "Nmap", "findings": []},
            "nikto": {"scanner": "Nikto", "findings": []},
            "nuclei": {"scanner": "Nuclei", "findings": []},
        }
    )

    orchestrator = ScanOrchestrator(manager)

    scan_data = orchestrator.run_full_scan(
        "http://127.0.0.1:8000"
    )

    results = scan_data["results"]

    assert len(results) == 3

    assert [
        call["scanner_name"]
        for call in manager.calls
    ] == [
        "nmap",
        "nikto",
        "nuclei"
    ]


def test_full_scan_uses_correct_scan_types():
    """Verify correct scan types are passed to each scanner."""

    manager = FakeScannerManager(
        results={
            "nmap": {"scanner": "Nmap"},
            "nikto": {"scanner": "Nikto"},
            "nuclei": {"scanner": "Nuclei"},
        }
    )

    orchestrator = ScanOrchestrator(manager)

    scan_data = orchestrator.run_full_scan(
        "http://127.0.0.1:8000"
    )

    results = scan_data["results"]

    assert len(results) == 3

    assert [
        result["scanner"]
        for result in results
    ] == [
        "Nmap",
        "Nikto",
        "Nuclei"
    ]

    # Scan types must match orchestrator definition

    assert manager.calls[0]["scan_type"] == "quick"
    assert manager.calls[1]["scan_type"] == "basic"
    assert manager.calls[2]["scan_type"] == "default"


def test_full_scan_normalizes_targets():
    """Check target normalization for different scanners."""

    manager = FakeScannerManager(
        results={
            "nmap": {"scanner": "Nmap"},
            "nikto": {"scanner": "Nikto"},
            "nuclei": {"scanner": "Nuclei"},
        }
    )

    orchestrator = ScanOrchestrator(manager)

    scan_data = orchestrator.run_full_scan(
        "http://127.0.0.1:8000"
    )

    results = scan_data["results"]

    # Targets must be normalized differently per scanner

    assert manager.calls[0]["target"] == "127.0.0.1"

    assert manager.calls[1]["target"] == (
        "http://127.0.0.1:8000"
    )

    assert manager.calls[2]["target"] == (
        "http://127.0.0.1:8000"
    )


def test_full_scan_collects_successful_results():
    """Ensure successful scanner results are collected."""

    manager = FakeScannerManager(
        results={
            "nmap": {"scanner": "Nmap", "findings": []},
            "nikto": {"scanner": "Nikto", "findings": []},
            "nuclei": {"scanner": "Nuclei", "findings": []},
        }
    )

    orchestrator = ScanOrchestrator(manager)

    scan_data = orchestrator.run_full_scan(
        "http://127.0.0.1:8000"
    )

    results = scan_data["results"]

    assert len(results) == 3

    assert [
        result["scanner"]
        for result in results
    ] == [
        "Nmap",
        "Nikto",
        "Nuclei"
    ]


# -------------------------------
# Failure Handling Tests
# -------------------------------

def test_failed_scanner_is_not_added_to_results():
    """Failed scanner should not appear in results."""

    manager = FakeScannerManager(
        results={
            "nmap": {"scanner": "Nmap", "findings": []},
            "nikto": None,
            "nuclei": {"scanner": "Nuclei", "findings": []},
        }
    )

    orchestrator = ScanOrchestrator(manager)

    scan_data = orchestrator.run_full_scan(
        "http://127.0.0.1:8000"
    )

    results = scan_data["results"]

    assert len(results) == 2

    assert [
        result["scanner"]
        for result in results
    ] == [
        "Nmap",
        "Nuclei"
    ]

def test_run_credential_scan():
    class FakeCredentialScanner:
        def scan(
            self,
            scan_type,
            target,
            hash_file=None,
            mode=None,
            wordlist=None
        ):
            return {
                "scanner": "credential_scanner",
                "scan_type": scan_type,
                "target": target,
                "hash_file": hash_file,
                "mode": mode,
                "wordlist": wordlist
            }

    class FakeScannerManager:
        def start_scan(
            self,
            scanner_name,
            scan_type,
            target,
            hash_file=None,
            mode=None,
            wordlist=None
        ):
            scanner = FakeCredentialScanner()

            return scanner.scan(
                scan_type,
                target,
                hash_file,
                mode,
                wordlist
            )

    orchestrator = ScanOrchestrator(
        FakeScannerManager()
    )

    result = orchestrator.run_credential_scan(
        scan_type="john",
        target="5f4dcc3b5aa765d61d8327deb882cf99",
        hash_file="tests/test_hashes.txt",
        wordlist="tests/test_wordlist.txt"
    )

    assert result["scanner"] == "credential_scanner"
    assert result["scan_type"] == "john"
    assert result["target"] == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert result["hash_file"] == "tests/test_hashes.txt"
    assert result["wordlist"] == "tests/test_wordlist.txt"
    assert "duration" in result
    
def test_all_failed_scanners_returns_empty_list():
    """If all scanners fail, return empty results list."""

    manager = FakeScannerManager(
        results={
            "nmap": None,
            "nikto": None,
            "nuclei": None
        }
    )

    orchestrator = ScanOrchestrator(manager)

    scan_data = orchestrator.run_full_scan(
        "http://127.0.0.1:8000"
    )

    results = scan_data["results"]

    assert results == []


# -------------------------------
# Order Tests
# -------------------------------

def test_scanners_run_in_correct_order():
    """Scanners must run in defined order: Nmap → Nikto → Nuclei."""

    manager = FakeScannerManager(
        results={
            "nmap": {"scanner": "Nmap"},
            "nikto": {"scanner": "Nikto"},
            "nuclei": {"scanner": "Nuclei"},
        }
    )

    orchestrator = ScanOrchestrator(manager)

    orchestrator.run_full_scan(
        "http://127.0.0.1:8000"
    )

    order = [
        call["scanner_name"]
        for call in manager.calls
    ]

    assert order == [
        "nmap",
        "nikto",
        "nuclei"
    ]