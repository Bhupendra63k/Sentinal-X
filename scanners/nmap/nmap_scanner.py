from .parser import NmapParser
from .finding_converter import NmapFindingConverter
from core.finding_manager import FindingManager
import subprocess
import time
from datetime import datetime

class NmapScanner:
    """Nmap scanner class to perform nmap scanning operations"""
    def __init__(self):
        self.name="nmap"
        self.converter=NmapFindingConverter()
        self.finding_manager=FindingManager()
        self.parser=NmapParser()
        self.scan_commands = {
            "quick": ["-F","-T4"],
            "service": ["-sV","-T4"],
            "os": ["-O","-T4"],
            "aggressive": ["-A","-T4"],
            "full": ["-p-", "-sV", "-O","-T4"]
        }
    
    def scan(self, scan_type, target):
        if scan_type not in self.scan_commands:
            print(f"Invalid scan type: {scan_type}")
            return

        command = ["nmap"] + self.scan_commands[scan_type] + [target]
        print("\n"+"="*60)
        print("                 SENTINALX NMAP SCAN")
        print("="*60)
        print(f"Scan Type:{scan_type}")
        print(f"Target:{target}")
        print(f"Command:{' '.join(command)}")
        print("="*60)
        print("Nmap has started....Please wait....\n")
        start_time = time.time()
        scan_started = datetime.now()

        try:
            result = subprocess.run(
            command,
            capture_output=True,
            text=True
    )

            end_time = time.time()
            duration = round(end_time - start_time, 2)

            print("\n--- NMAP DEBUG ---")
            print("Return code:", result.returncode)
            print("STDOUT length:", len(result.stdout))
            print("STDERR length:", len(result.stderr))

            if result.stderr:
               print("STDERR:")
               print(result.stderr)

            print("--- END DEBUG ---\n")

        except FileNotFoundError:
            print("Nmap is not installed or not found in the system path.")
            return None
 
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return None
        parsed_output = self.parser.parse(result.stdout)
    

        parsed_output["scanner"] = "Nmap"
        parsed_output["scan_type"] = scan_type
        parsed_output["scan_started"] = scan_started.strftime("%Y-%m-%d %H:%M:%S")
        parsed_output["duration"] = duration
        findings=self.converter.convert(parsed_output)
        self.finding_manager.clear()
        self.finding_manager.add_findings(findings)
        parsed_output["findings"]=[
            finding.to_dict()
            for finding in findings
        ]
        return parsed_output


if __name__=="__main__":
    nmap_scanner=NmapScanner()


