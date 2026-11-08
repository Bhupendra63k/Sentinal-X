class HashcatParser:
    def parse(self,result):
        if not isinstance(result,dict):
            result={}
        stdout=result.get("stdout") or ""
        stderr=result.get("stderr") or ""
        return_code=result.get("return_code",-1)

        if not isinstance(stdout,str):
            stdout=""
        if not isinstance(stderr,str):
            stderr=""
        if not isinstance(return_code,int):
            return_code=-1

        cracked_password=None
        if return_code==0 and stdout.strip():
            cracked_password=stdout.strip().splitlines()[0]
        return {
            "tool":"hashcat",
            "return_code":return_code,
            "cracked":cracked_password is not None,
            "password":cracked_password,
            "stdout":stdout,
            "stderr":stderr,
        }