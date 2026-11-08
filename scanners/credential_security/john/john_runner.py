import subprocess
from pathlib import Path

class JohnRunner:
    def __init__(self):
        self.name="john"
        project_root=Path(__file__).resolve().parents[3]
        self.runtime_dir=project_root/"data"
        self.runtime_dir.mkdir(parents=True,exist_ok=True)
        self.pot_file=self.runtime_dir/"john.pot"

    def run(self,hash_file,wordlist):
        command=["john",
                "--format=Raw-MD5",
                f"--pot={self.pot_file}",
                f"--wordlist="+ wordlist,
                hash_file,
                ]
        try:
            result=subprocess.run(command,capture_output=True,text=True,timeout=1800)
            return {
                "tool":self.name,
                "return_code":result.returncode,
                "stderr":result.stderr,
                "stdout":result.stdout,
                "hash_file":str(hash_file)
            }

        except FileNotFoundError:
            return {
                "tool":self.name,
                "return_code":-1,
                "stderr":"john the ripper is not installed or path does not exist",
                "stdout":""
                        }

        except subprocess.TimeoutExpired:
             return {
                  "tool":self.name,
                  "return_code":-1,
                  "stderr":"John execution timed out after 1800 seconds.",
                  "stdout":""
             }
    def show_cracked(self,hash_file):
        command=[
            "john",
            "--show",
            "--format=Raw-MD5",
            f"--pot={self.pot_file}",
            hash_file,
        ]
        try:
            result=subprocess.run(command,capture_output=True,text=True,timeout=1800)
            return {
                    "tool":self.name,
                        "return_code":result.returncode,
                        "stderr":result.stderr,
                        "stdout":result.stdout,
                        "hash_file":str(hash_file)
                    }
        
        except FileNotFoundError:
                    return {
                        "tool":self.name,
                        "return_code":-1,
                        "stderr":"john the ripper is not installed or path does not exist",
                        "stdout":""
                                }
        except subprocess.TimeoutExpired:
             return {
                  "tool":self.name,
                  "return_code":-1,
                  "stderr":"John execution timed out after 1800 seconds.",
                  "stdout":""
             }
