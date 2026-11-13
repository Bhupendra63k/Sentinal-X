import json 
import subprocess
import time
import uuid

try:
    from .parser import Hping3Parser
except (ImportError,ValueError):
    from parser import Hping3Parser

class Hping3Scanner:
    def __init__(self):
        self.name="hping3"
        self.parser=Hping3Parser()
        self.scan_commands = {
            "icmp_ping": ["-1", "-c", "4"],
            "syn_probe": ["-S", "-p", "80", "-c", "4"],
            "syn_probe_https": ["-S", "-p", "443", "-c", "4"],
        }
    def scan(self,scan_type:str,target:str)->dict:
        scan_id=str(uuid.uuid4())
        clean_target=target.strip()
        if scan_type not in self.scan_commands:
            return {
                "scan_id":scan_id,
                "scanner":self.name,
                "scan_type":scan_type,
                "target":clean_target,
                "status":"FAILED",
                "findings":[],
                "error":f"Invalid hping3 scan profile: {scan_type}",
            }
        command=["hping3"]+self.scan_commands[scan_type]+[clean_target]
        start_time=time.time()
        try:
            process=subprocess.run(command,capture_output=True,text=True,timeout=15)
            output=process.stdout+"\n"+process.stderr
        except FileNotFoundError:
            return {
                    "scan_id":scan_id,
                    "scanner":self.name,
                    "scan_type":scan_type,
                    "target":clean_target,
                    "status":"FAILED",
                    "findings":[],
                    "error":"hping3 binary not found in system PATH.Install it via 'apt install hping3",
                        }
        except subprocess.TimeoutExpired:
                return {
                    "scan_id":scan_id,
                    "scanner":self.name,
                    "scan_type":scan_type,
                    "target":clean_target,
                    "status":"FAILED",
                    "findings":[],
                    "error":"hping3 probe timed out after 15 seconds.",
                                }
        except Exception as exc:
                    return {
                    "scan_id":scan_id,
                    "scanner":self.name,
                    "scan_type":scan_type,
                    "target":clean_target,
                    "status":"FAILED",
                    "findings":[],
                    "error":f"Execution failed: {exc}",
                                }
        duration=round(time.time()-start_time,2)
        findings=self.parser.parse(output,clean_target)
        return {
            "scan_id":scan_id,
            "scanner":self.name,
            "scan_type":scan_type,
            "status":"COMPLETED",
            "target":clean_target,
            "duration":duration,
            "summary":{
                 "total_findings":len(findings),
            },
            "findings":findings,
            "error":None,
                                }

if __name__=="__main__":
    scanner=Hping3Scanner()
    res=scanner.scan("icmp_ping","127.0.0.1")
    print(json.dumps(res,indent=2))