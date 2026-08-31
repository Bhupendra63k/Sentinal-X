from .parser import NiktoParser
import subprocess
from .finding_converter import NiktoFindingConverter

class NiktoScanner:
    def __init__(self):
        self.name="nikto"
        self.parser=NiktoParser()
        self.finding_converter=NiktoFindingConverter()
        self.scan_commands={
            "basic":["-ask","no","-h"],
            "ssl":["-ask","no","-ssl","-h"],
            "redirects":["-ask","no","-followredirects","-h"],
            "info":["-ask","no","-Tuning","3","-h"],
            "injection":["-ask","no","-Tuning","4","-h"]
        }

    def scan(self,scan_type,target):
        if scan_type not in self.scan_commands:
            print(f"Invalid scan type:{scan_type}")
            return 
        command=["nikto"]+self.scan_commands[scan_type]+[target]
        print("Nikto command:", " ".join(command))
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300
            )
        except FileNotFoundError:
            print("Nikto is not installed or not found on system PATH")
            return
        except subprocess.TimeoutExpired:
            print("Nikto scan timed out")
            return
        except Exception as e:
            print(f"An unexpected error occured:{e}")
            return 
        print("return code:",result.returncode)
        if result.returncode != 0:
            print("Error occurred during Nikto scan")
            print("STDERR :",result.stderr)
        parsed_result=self.parser.parse(result.stdout,target)
        parsed_result["scan_type"]=scan_type
        parsed_result["findings"] = [
            finding.to_dict()
            for finding in self.finding_converter.convert(parsed_result)
]
        return parsed_result

if __name__ == "__main__":
    scanner = NiktoScanner()

    result = scanner.scan(
        "basic",
        "http://127.0.0.1:8000"
    )

    print("\n--- NIKTO RESULT ---")
    print(result)
    print("--- END RESULT ---")