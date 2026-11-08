import time
from core.target_normalizer import TargetNormalizer


class ScanOrchestrator:

    def __init__(self, scanner_manager):
        self.scanner_manager = scanner_manager

        self.scan_config = [
            {
                "scanner_name": "nmap",
                "scan_type": "quick",
                "target_type": "nmap"
            },
            {
                "scanner_name": "nikto",
                "scan_type": "basic",
                "target_type": "web"
            },
            {
                "scanner_name": "nuclei",
                "scan_type": "default",
                "target_type": "web"
            }
        ]

    def run_full_scan(self, target,validated_targets=None):

        results = []
        execution_results = []

        # ============================================================
        # TARGET NORMALIZATION
        # ============================================================

        if validated_targets is None:
            targets=TargetNormalizer().normalize(target)
            nmap_target=targets["nmap_target"]
            web_target=targets["web_target"]
        else:
            nmap_target=validated_targets["nmap_target"]
            web_target=validated_targets["web_target"]

        print("\n[TARGET NORMALIZER]")
        print(f"original:{target}")
        print(f"Nmap    :{nmap_target}")
        print(f"web     :{web_target}")

        # ============================================================
        # SCANNER EXECUTION
        # ============================================================

        for config in self.scan_config:

            scanner_name = config["scanner_name"]
            scan_type = config["scan_type"]
            target_type = config["target_type"]

            if target_type == "nmap":
                scanner_target = nmap_target
            else:
                scanner_target = web_target

            print(
                f"\n[ORCHESTRATOR] Starting "
                f"{scanner_name}..."
            )

            start_time = time.time()

            execution = {
                "scanner_name": scanner_name,
                "scan_type": scan_type,
                "target_type": target_type,
                "target": scanner_target,
                "status": "",
                "duration": 0,
                "result": None,
                "error": None,
            }

            try:
                scanner_result = self.scanner_manager.start_scan(scanner_name=scanner_name,scan_type=scan_type,target=scanner_target)
                duration = round(time.time() - start_time,2)
                execution["duration"] = duration
                if not isinstance(scanner_result,dict):
                    execution["status"]="failed"
                    execution["error"]=("Scanner returned no valid result")
                    execution_results.append(execution)
                    print(f"[ORCHESTRATOR] {scanner_name}"
                          f"returned no valid result after {duration}s")
                    continue
                scanner_status=str(scanner_result.get("status","")).strip().lower()
                if scanner_status in {"failed","error"} or scanner_result.get("error"):
                    execution["status"]="failed"
                    execution["error"]=(scanner_result.get("error") or f"{scanner_name} reported a failed scan.")
                else:
                    execution["status"]="success"
                execution["result"]=scanner_result
                execution_results.append(execution)
                scanner_result["duration"]=duration
                results.append(scanner_result)
                print(f"[ORCHESTRATOR] {scanner_name} "
                      f"{execution['status']} after {duration}s")

            except Exception as exc:
                duration=round(time.time()-start_time,2)
                execution["status"]="failed"
                execution["duration"]=duration
                execution["error"] = (
                    f"{scanner_name} execution failed: {exc}"
                )
                execution_results.append(execution)
                print(f"[ORCHESTRATOR] {scanner_name} failed "
                     f"after {duration}s: {exc}")
                continue

        # ============================================================
        # FINAL RESULT
        # ============================================================

        return {
            "results": results,
            "execution_results": execution_results
        }

    def run_credential_scan(self,scan_type,target,hash_file,wordlist,mode=None):

        start_time = time.time()

        result = self.scanner_manager.start_scan(
            scanner_name="credential_scanner",
            scan_type=scan_type,
            target=target,
            hash_file=hash_file,
            mode=mode,
            wordlist=wordlist
        )

        duration = round(time.time() - start_time,2)

        if result is not None:
            result["duration"] = duration

        return result