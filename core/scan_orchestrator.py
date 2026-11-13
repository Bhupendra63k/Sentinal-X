import time
from core.target_normalizer import TargetNormalizer


class ScanOrchestrator:

    def __init__(self, scanner_manager):
        self.scanner_manager = scanner_manager

    def run_full_scan(self, target: str, validated_targets: dict = None) -> dict:
        results = []
        execution_results = []
        aggregated_findings = []

        if validated_targets is None:
            targets = TargetNormalizer().normalize(target)
        else:
            targets = validated_targets

        host_target = targets.get("host_target") or targets.get("nmap_target")
        web_target = targets.get("web_target")

        pipeline_start = time.time()

        for scanner, scan_type, target_type in self.scanner_manager.get_pipeline_scanners():
            scanner_name = scanner.name
            scanner_target = host_target if target_type in {"host", "nmap"} else web_target

            print(f"\n[ORCHESTRATOR] Starting {scanner_name} ({scan_type}) against {scanner_target}...")
            start_time = time.time()

            execution = {
                "scanner_name": scanner_name,
                "scan_type": scan_type,
                "target_type": target_type,
                "target": scanner_target,
                "status": "failed",
                "duration": 0,
                "result": None,
                "error": None,
            }

            try:
                scanner_result = self.scanner_manager.start_scan(
                    scanner_name=scanner_name,
                    scan_type=scan_type,
                    target=scanner_target,
                )
                duration = round(time.time() - start_time, 2)
                execution["duration"] = duration

                if not isinstance(scanner_result, dict):
                    execution["error"] = "Scanner returned an invalid result format."
                    execution_results.append(execution)
                    continue

                scanner_status = str(scanner_result.get("status", "")).strip().lower()
                if scanner_status in {"failed", "error"} or scanner_result.get("error"):
                    execution["status"] = "failed"
                    execution["error"] = scanner_result.get("error") or f"{scanner_name} reported scan failure."
                else:
                    execution["status"] = "success"
                    findings = scanner_result.get("findings", [])
                    for f in findings:
                        f.setdefault("scanner", scanner_name)
                    aggregated_findings.extend(findings)

                execution["result"] = scanner_result
                execution_results.append(execution)
                scanner_result["duration"] = duration
                results.append(scanner_result)
                print(f"[ORCHESTRATOR] {scanner_name} {execution['status']} after {duration}s")

            except Exception as exc:
                duration = round(time.time() - start_time, 2)
                execution["duration"] = duration
                execution["error"] = f"{scanner_name} execution failed: {exc}"
                execution_results.append(execution)
                print(f"[ORCHESTRATOR] {scanner_name} failed after {duration}s: {exc}")

        total_duration = round(time.time() - pipeline_start, 2)

        return {
            "target": target,
            "status": "COMPLETED",
            "total_duration": total_duration,
            "summary": {
                "scanners_executed": len(execution_results),
                "total_findings": len(aggregated_findings),
            },
            "findings": aggregated_findings,
            "execution_results": execution_results,
            "results": results,
        }

    def run_credential_scan(self, scan_type, target, hash_file, wordlist, mode=None):
        start_time = time.time()
        result = self.scanner_manager.start_scan(
            scanner_name="credential_scanner",
            scan_type=scan_type,
            target=target,
            hash_file=hash_file,
            mode=mode,
            wordlist=wordlist,
        )
        duration = round(time.time() - start_time, 2)
        if result is not None:
            result["duration"] = duration
        return result