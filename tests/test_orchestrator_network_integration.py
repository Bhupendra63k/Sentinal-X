from core.scan_orchestrator import ScanOrchestrator
from core.scanner_manager import ScannerManager
from scanners.reconnaissance.nmap.nmap_scanner import NmapScanner


class FailingNmapScanner:

    name = "nmap"

    def scan(
        self,
        scan_type,
        target,
        hash_file=None,
        mode=None,
        wordlist=None
    ):
        raise RuntimeError("Simulated Nmap failure")


class SuccessfulScanner:

    name = "nikto"

    def scan(
        self,
        scan_type,
        target,
        hash_file=None,
        mode=None,
        wordlist=None
    ):
        return {
            "scanner": "Nikto",
            "target": target,
            "findings": []
        }


def test_orchestrator_isolates_nmap_failure():

    scanner_manager = ScannerManager()

    scanner_manager.register_scanner(
        FailingNmapScanner()
    )

    scanner_manager.register_scanner(
        SuccessfulScanner()
    )

    orchestrator = ScanOrchestrator(
        scanner_manager
    )

    result = orchestrator.run_full_scan(
        "127.0.0.1"
    )

    execution_results = result["execution_results"]

    nmap_execution = next(
        execution
        for execution in execution_results
        if execution["scanner_name"] == "nmap"
    )

    nikto_execution = next(
        execution
        for execution in execution_results
        if execution["scanner_name"] == "nikto"
    )

    assert nmap_execution["status"] == "failed"

    assert nmap_execution["error"] == (
        "Simulated Nmap failure"
    )

    assert nmap_execution["result"] is None

    assert nikto_execution["status"] == "success"

    assert nikto_execution["result"] is not None