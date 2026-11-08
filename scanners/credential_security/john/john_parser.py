import re

class JohnParser:
    def parse(self, result):
        if not isinstance(result,dict):
            result={}

        stdout = result.get("stdout", "")
        show_stdout = result.get("show_stdout", "")
        stderr = result.get("stderr", "")
        return_code = result.get("return_code", -1)
        hash_file = result.get("hash_file")

        if not isinstance(stdout,str):
            stdout=""
        if not isinstance(stderr,str):
            stderr=""
        if not isinstance(show_stdout,str):
            show_stdout=""
        if not isinstance(return_code,int) or isinstance(return_code,bool):
            return_code=-1
        if not isinstance(hash_file,str):
            hash_file=None
        cracked_passwords = []
        output = show_stdout if show_stdout else stdout
        if return_code==0:
            for line in output.splitlines():
                line = line.strip()
                if not line or ":" not in line:
                    continue
                if line.startswith(("Loaded", "Remaining ")):
                    continue
                parts=line.split(":",1)
                if len(parts)==2:
                    password=parts[1].strip()
                    if password and password not in cracked_passwords:
                        cracked_passwords.append(password)

        summary_match = re.search(r"(\d+)\s+password hashes? cracked,\s*(\d+)\s+left",show_stdout or stdout,re.IGNORECASE)
        if summary_match:
            cracked_count =int(summary_match.group(1))
            remaining_count =int(summary_match.group(2))
        else:
            cracked_count = len(cracked_passwords)
            remaining_count = None     
        total_hashes = cracked_count + (remaining_count)
        warnings=[line.replace("Warning:","").strip() for line in stderr.splitlines() if "warning:" in line.lower()]

        return {
            "tool": "john",
            "return_code": return_code,
            "cracked": bool(cracked_passwords),
            "cracked_passwords":cracked_passwords,
            "total_hashes": total_hashes,
            "cracked_count": cracked_count,
            "remaining_count": remaining_count,
            "hash_file": hash_file,
            "warnings":warnings
            }
        
