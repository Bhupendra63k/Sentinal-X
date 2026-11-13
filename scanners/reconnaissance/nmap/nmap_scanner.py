from .parser import NmapParser
from scanners.network.network_analyzer import NetworkSecurityAnalyzer
from .finding_converter import NmapFindingConverter
from core.finding_manager import FindingManager
import subprocess
import time
from datetime import datetime


class NmapScanner:
    """Nmap scanner class to perform nmap scanning operations"""

    def __init__(self):
        self.name = "nmap"
        self.converter = NmapFindingConverter()
        self.finding_manager = FindingManager()
        self.network_analyzer=NetworkSecurityAnalyzer()
        self.parser = NmapParser()

        self.scan_commands = {
            "quick": ["-F", "-T4"],
            "service": ["-sV", "-T4"],
            "os": ["-O", "-T4"],
            "aggressive": ["-A", "-T4"],
            "full": ["-p-", "-sV", "-O", "-T4"]
        }

    def scan(self,scan_type,target,hash_file=None,mode=None,wordlist=None):

        if scan_type not in self.scan_commands:
            print(f"Invalid scan type: {scan_type}")
            return None

        command = ["nmap"] + self.scan_commands[scan_type] + [target]

        start_time = time.time()
        scan_started = datetime.now()

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300
            )
            if result.returncode!=0:
                return {
                    "scanner":"Nmap",
                    "scan_type":scan_type,
                    "target":target,
                    "status":"FAILED",
                    "findings":[],
                    "error":(
                        result.stderr.strip()
                        or "Nmap exited with a non-zero return code."
                    )
                }

            end_time = time.time()
            duration = round(end_time - start_time, 2)

        except FileNotFoundError:
            print("Nmap is not installed or not found in the system path.")
            return None

        except subprocess.TimeoutExpired:
            print("Nmap scan timed out after 300 seconds.")
            return None

        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return None

        parsed_output = self.parser.parse(result.stdout)
        
        parsed_output["scanner"] = "Nmap"
        parsed_output["scan_type"] = scan_type
        parsed_output["scan_started"] = scan_started.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        parsed_output["duration"] = duration

        findings = self.converter.convert(parsed_output)
        network_findings=self.network_analyzer.analyze(parsed_output)
        findings.extend(network_findings)
        
        self.finding_manager.clear()
        self.finding_manager.add_findings(findings)

        parsed_output["findings"] = [
            finding.to_dict() if hasattr(finding,"to_dict") else finding
            for finding in findings
        ]

        return parsed_output


if __name__ == "__main__":
    nmap_scanner = NmapScanner()