import subprocess
import uuid
from urllib.parse import urlparse
from .finding_converter import NiktoFindingConverter
from .parser import NiktoParser

class NiktoScanner:
    def __init__(self):
        self.name = "nikto"
        self.parser = NiktoParser()
        self.finding_converter = NiktoFindingConverter()
        
        # Standard Nikto CLI arguments
        # -maxtime requires time suffix (e.g., '120s' or '2m')
        self.scan_commands = {
            "basic": ["-ask", "no", "-maxtime", "120s", "-h"],
            "ssl": ["-ask", "no", "-ssl", "-maxtime", "120s", "-h"],
            "redirects": ["-ask", "no", "-followredirects", "-maxtime", "120s", "-h"],
            "info": ["-ask", "no", "-Tuning", "1,2,3,b", "-maxtime", "120s", "-h"],
            "injection": ["-ask", "no", "-Tuning", "4", "-maxtime", "120s", "-h"],
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
                "error": f"Invalid Nikto scan type: {scan_type}"
            }
        parsed_url=urlparse(target if '://' in target else f"http://{target}")
        host=parsed_url.hostname or target
        port=str(parsed_url.port) if parsed_url.port else ("443" if parsed_url.scheme=="https" else "80")

        flags =list(self.scan_commands[scan_type])
        if parsed_url.scheme == "https" and "-ssl" not in flags:
            h_index=flags.index("-h")
            flags.insert(h_index,"-ssl")

        command = ["nikto"] + flags + [host,"-p",port]
        collected_stdout = []
        collected_stderr = []

        try:
            # bufsize=1 enables line-buffered output streaming
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            # Stream findings in real-time as Nikto discovers them
            if process.stdout:
                for line in iter(process.stdout.readline, ""):
                    collected_stdout.append(line)
                    clean_line = line.strip()
                    if clean_line and clean_line.startswith("+"):
                        print(f"[*] {clean_line}", flush=True)

            process.wait(timeout=140)
            if process.stderr:
                stderr_data = process.stderr.read()
                if stderr_data:
                    collected_stderr.append(stderr_data)

        except FileNotFoundError:
            return {
                "scan_id": scan_id,
                "scanner": self.name,
                "scan_type": scan_type,
                "target": target,
                "status": "FAILED",
                "findings": [],
                "error": "Nikto is not installed or not found in system PATH."
            }

        except subprocess.TimeoutExpired:
            process.kill()
            raw_output = "".join(collected_stdout)

            # If findings were collected before timeout, return them as partial results
            if "+ Target IP:" in raw_output:
                parsed_result = self.parser.parse(raw_output, target)
                findings = self.finding_converter.convert(parsed_result.get("raw_findings", []))
                return {
                    "scan_id": scan_id,
                    "scanner": self.name,
                    "scan_type": scan_type,
                    "status": "PARTIAL_TIMEOUT",
                    "target": target,
                    "duration": 120.0,
                    "summary": {
                        "ip_address": parsed_result.get("ip_address"),
                        "port": parsed_result.get("port"),
                        "server": parsed_result.get("server"),
                        "total_findings": len(findings)
                    },
                    "findings": findings,
                    "server_notes": parsed_result.get("server_notes", []),
                    "error": "Scan hit the time limit; returning partial findings."
                }

            return {
                "scan_id": scan_id,
                "scanner": self.name,
                "scan_type": scan_type,
                "target": target,
                "status": "FAILED",
                "findings": [],
                "error": "Nikto scan timed out."
            }

        except Exception as exc:
            return {
                "scan_id": scan_id,
                "scanner": self.name,
                "scan_type": scan_type,
                "target": target,
                "status": "FAILED",
                "findings": [],
                "error": f"Nikto execution failed: {exc}"
            }

        full_stdout = "".join(collected_stdout)
        full_stderr = "".join(collected_stderr)

        # Catch CLI flag syntax errors and parameter rejections
        if "requires a value" in full_stdout or "Unknown option" in full_stdout:
            error_line = next(
                (line.strip() for line in full_stdout.splitlines() if "requires a value" in line or "Unknown option" in line),
                "Invalid Nikto CLI parameters."
            )
            return {
                "scan_id": scan_id,
                "scanner": self.name,
                "scan_type": scan_type,
                "target": target,
                "status": "FAILED",
                "findings": [],
                "error": error_line
            }

        # Catch DNS resolution and unreachable host failures
        if "[FAIL]" in full_stdout or "0 host(s) tested" in full_stdout:
            error_line = next(
                (line.replace("+ [FAIL] ", "").strip() for line in full_stdout.splitlines() if "[FAIL]" in line or "ERROR:" in line),
                f"Could not connect to target host '{target}'."
            )
            return {
                "scan_id": scan_id,
                "scanner": self.name,
                "scan_type": scan_type,
                "target": target,
                "status": "FAILED",
                "findings": [],
                "error": error_line
            }

        # Catch non-zero exit codes if stdout has no valid scan data
        if process.returncode != 0 and "+ Target IP:" not in full_stdout:
            return {
                "scan_id": scan_id,
                "scanner": self.name,
                "scan_type": scan_type,
                "target": target,
                "status": "FAILED",
                "findings": [],
                "error": full_stderr.strip() or full_stdout.strip() or "Nikto exited with an error."
            }

        # Parse complete results
        parsed_result = self.parser.parse(full_stdout, target)
        findings = self.finding_converter.convert(parsed_result.get("raw_findings", []))

        return {
            "scan_id": scan_id,
            "scanner": self.name,
            "scan_type": scan_type,
            "status": "COMPLETED",
            "target": target,
            "duration": parsed_result.get("duration"),
            "summary": {
                "ip_address": parsed_result.get("ip_address"),
                "port": parsed_result.get("port"),
                "server": parsed_result.get("server"),
                "total_findings": len(findings)
            },
            "findings": findings,
            "server_notes": parsed_result.get("server_notes", []),
            "error": None
        }


if __name__ == "__main__":
    scanner = NiktoScanner()
    result = scanner.scan("basic", "http://127.0.0.1:8000")
    print("\n--- FINAL NIKTO RESULT ---")
    print(result)
    print("--- END RESULT ---")