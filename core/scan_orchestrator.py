import time
from core.target_normalizer import TargetNormalizer

class ScanOrchestrator:

    def __init__(self, scanner_manager):
        self.scanner_manager = scanner_manager

    def run_full_scan(self, target):

        results = []
        # ============================================================
        # NMAP
        # ============================================================
        normalizer=TargetNormalizer()
        targets=normalizer.normalize(target)
        nmap_target=targets["nmap_target"]
        web_target=targets["web_target"]
        print("\n[TARGET NORMALIZER]")
        print(f"original:{target}")
        print(f"Nmap    :{nmap_target}")
        print(f"web     :{web_target}")

        print("\n[ORCHESTRATOR] Starting Nmap...")
        start_time = time.time()

        nmap_result = self.scanner_manager.start_scan(
            scanner_name="nmap",
            scan_type="quick",
            target=nmap_target
        )

        nmap_duration = round(time.time() - start_time, 2)

        if nmap_result is not None:
            nmap_result["duration"] = nmap_duration

            results.append(nmap_result)

            print(
                f"[ORCHESTRATOR] Nmap completed "
                f"in {nmap_duration}s"
            )

        else:

            print(
                f"[ORCHESTRATOR] Nmap failed "
                f"after {nmap_duration}s"
            )

        # ============================================================
        # NIKTO
        # ============================================================

        print("\n[ORCHESTRATOR] Starting Nikto...")
        start_time = time.time()

        nikto_result = self.scanner_manager.start_scan(
            scanner_name="nikto",
            scan_type="basic",
            target=web_target
        )

        nikto_duration = round(time.time() - start_time, 2)

        if nikto_result is not None:
            nikto_result["duration"] = nikto_duration

            results.append(nikto_result)

            print(
                f"[ORCHESTRATOR] Nikto completed "
                f"in {nikto_duration}s"
            )

        else:

            print(
                f"[ORCHESTRATOR] Nikto failed "
                f"after {nikto_duration}s"
            )

        # ============================================================
        # NUCLEI
        # ============================================================

        print("\n[ORCHESTRATOR] Starting Nuclei...")
        start_time = time.time()

        nuclei_result = self.scanner_manager.start_scan(
            scanner_name="nuclei",
            scan_type="default",
            target=web_target
        )

        nuclei_duration = round(time.time() - start_time, 2)

        if nuclei_result is not None:
            nuclei_result["duration"] = nuclei_duration

            results.append(nuclei_result)

            print(
                f"[ORCHESTRATOR] Nuclei completed "
                f"in {nuclei_duration}s"
            )

        else:

            print(
                f"[ORCHESTRATOR] Nuclei failed "
                f"after {nuclei_duration}s"
            )

        # ============================================================
        # FINAL RESULT
        # ============================================================

        return results