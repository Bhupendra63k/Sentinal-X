import subprocess
import time

from .parser import NucleiParser
from .finding_converter import NucleiFindingConverter

class NucleiScanner:
    def __init__(self):
        self.name="nuclei"
        self.parser=NucleiParser()
        self.converter=NucleiFindingConverter()

    def scan(self,scan_type,target):
        command=[
            "nuclei",
            "-u",target,
            "-jsonl"
        ]
        print("\n"+"="*60)
        print("                SENTINALX NUCLEI SCAN")
        print("="*60)
        print(f"target:{target}")
        print(f"command:{' '.join(command)}")
        print("="*60)
        print("Nuclei has started ....please wait ....")
        start_time=time.time()
        try:
            result=subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=1800)
        except FileNotFoundError:
            print("Nuclei is not installed or not found in system PATH.")
            return None

        except subprocess.TimeoutExpired:
            print("Nuclei scan timed out")
            return None

        except Exception as e:
            print(f"An unexpected error occured:{e}")
            return None
        duration =round(time.time()-start_time,2)
        if result.returncode!=0:
            print("Nuclei scan failed.")
            print(result.stderr)
            return None
        parsed_results=self.parser.parse(result.stdout)
        findings=self.converter.convert(parsed_results)
        return{
            "scanner":"Nuclei",
            "scan_type":scan_type,
            "target":target,
            "duration":duration,
            "findings":[
                finding.to_dict()
                for finding in findings
            ]
        }
if __name__=="__main__":
    scanner=NucleiScanner()
    result=scanner.scan("default","http://127.0.0.1:8000")
    print("\n---NUCLEI RESULT---")
    print(result)
    print("---END RESULT---")

