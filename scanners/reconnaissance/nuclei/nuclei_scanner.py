import subprocess
import time
import uuid

try:
    from .parser import NucleiParser
except (ImportError, ValueError):
    from parser import NucleiParser

class NucleiScanner:
    def __init__(self):
        self.name = "nuclei"
        self.parser = NucleiParser()
        self.scan_commands = {
            "default": ["-tags", "tech,ssl", "-silent", "-jsonl"],
            "cve": ["-tags", "cve", "-silent", "-jsonl"],
            "misconfig": ["-tags", "misconfig", "-silent", "-jsonl"],
            "exposures": ["-tags", "exposure", "-silent", "-jsonl"],
        }

    def scan(self, scan_type: str, target: str) -> dict:
        scan_id = str(uuid.uuid4())

        if scan_type not in self.scan_commands:
            return {
                "scan_id": scan_id,
                "scanner": self.name,
                "scan_type": scan_type,
                "target": target,
                "status": "FAILED",
                "findings": [],
                "error": f"Invalid Nuclei scan type: {scan_type}",
            }

        normalized_target = target.strip()
        if not normalized_target.startswith(("http://", "https://")):
            normalized_target = f"https://{normalized_target}"

        command = ["nuclei", "-u", normalized_target] + self.scan_commands[scan_type]
        collected_stdout = []
        collected_stderr = []
        start_time = time.time()

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            if process.stdout:
                for line in iter(process.stdout.readline, ""):
                    collected_stdout.append(line)
                    clean = line.strip()
                    if clean.startswith("{"):
                        print("[*] [Nuclei] Matched finding", flush=True)

            process.wait(timeout=300)
            if process.stderr:
                collected_stderr.append(process.stderr.read())

        except FileNotFoundError:
            return {
                "scan_id": scan_id,
                "scanner": self.name,
                "scan_type": scan_type,
                "target": target,
                "status": "FAILED",
                "findings": [],
                "error": "Nuclei binary not found in system PATH.",
            }
        except subprocess.TimeoutExpired:
            process.kill()
            return {
                "scan_id": scan_id,
                "scanner": self.name,
                "scan_type": scan_type,
                "target": target,
                "status": "FAILED",
                "findings": [],
                "error": "Nuclei scan timed out after 300 seconds.",
            }
        except Exception as exc:
            return {
                "scan_id": scan_id,
                "scanner": self.name,
                "scan_type": scan_type,
                "target": target,
                "status": "FAILED",
                "findings": [],
                "error": f"Nuclei execution failed: {exc}",
            }

        duration = round(time.time() - start_time, 2)
        raw_output = "".join(collected_stdout)
        findings = self.parser.parse(raw_output, normalized_target)

        return {
            "scan_id": scan_id,
            "scanner": self.name,
            "scan_type": scan_type,
            "status": "COMPLETED",
            "target": target,
            "duration": duration,
            "summary": {
                "total_findings": len(findings),
            },
            "findings": findings,
            "error": None,
        }


if __name__ == "__main__":
    scanner = NucleiScanner()
    res = scanner.scan("default", "https://google.com")
    import json
    print(json.dumps(res, indent=2))