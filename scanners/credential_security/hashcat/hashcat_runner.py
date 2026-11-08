import subprocess 

class HashcatRunner:
    def __init__(self):
        self.name="hashcat"

    def run(self,hash_file,mode,wordlist):
        if mode is None or not str(mode).strip().isdigit():
            return {
                "tool":self.name,
                "return_code":-1,
                "stdout":"",
                "stderr":"Invalid Hashcat mode. Mode must be a non-negative integer.",
            }
        mode=str(mode).strip()
        command=["hashcat","-m",str(mode),hash_file,wordlist,"--potfile-disable","--outfile-format=2","--quiet"]
        try:
            result=subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=1800
            )
            return {
                "tool":self.name,
                "return_code":result.returncode,
                "stdout":result.stdout,
                "stderr":result.stderr
            }

        except FileNotFoundError:
            return {
                "tool":self.name,
                "return_code":-1,
                "stdout":"",
                "stderr":"Hashcat is not installed or not available in PATH."
            }
        except subprocess.TimeoutExpired:
            return {
                "tool":self.name,
                "return_code":-1,
                "stdout":"",
                "stderr":"Hashcat execution timed out after 1800 seconds."
            }