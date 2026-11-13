import json
import subprocess
import time
import uuid

try:
    from .parser import TcpdumpParser
except (ImportError, ValueError):
    from parser import TcpdumpParser

class TcpdumpScanner:
    def __init__(self):
        self.name="tcpdump"
        self.parser=TcpdumpParser()
        self.scan_commands={
            "quick_capture":["-c","50","-nn","-v"],
            "traffic_audit":["-c","150","-nn","-v"]
        }

    def scan(self,scan_type:str,target:str)->dict:
        scan_id=str(uuid.uuid4())
        interface=target.strip() if target else "any"

        if scan_type not in self.scan_commands:
            return {
                "scan_id":scan_id,
                "scanner":self.name,
                "scan_type":scan_type,
                "target":interface,
                "status":"FAILED",
                "findings":[],
                "error":f"Invalid tcpdump scan profile:{scan_type}",
            }
        command=["tcpdump","-i",interface] + self.scan_commands[scan_type]
        start_time=time.time()

        try:
            process=subprocess.run(command,capture_output=True,text=True,timeout=30)
            output=process.stdout+"\n"+process.stderr
            if process.returncode !=0:
                return {
                    "scan_id":scan_id,
                    "scanner":self.name,
                    "scan_type":scan_type,
                    "target":interface,
                    "status":"FAILED",
                    "findings":[],
                    "error":process.stderr.strip() or process.stderr.strip() or "tcpdump process failed.",
                }
        except FileNotFoundError:
            return {
                "scan_id":scan_id,
                "scanner":self.name,
                "scan_type":scan_type,
                "target":interface,
                "status":"FAILED",
                "findings":[],
                "error":"tcpdump binary not found in system PATH."

            }
        except subprocess.TimeoutExpired:
            return {
                "scan_id":scan_id,
                "scanner":self.name,
                "scan_type":scan_type,
                "target":interface,
                "status":"FAILED",
                "findings":[],
                "error":"Packet capture timed out before reaching requested packet count."
            }
        except Exception as exc:
            return {
                "scan_id":scan_id,
                "scanner":self.name,
                "scan_type":scan_type,
                "target":interface,
                "status":"FAILED",
                "findings":[],
                "error":f"Capture execution failed:{exc}"
            }

        duration=round(time.time()-start_time,2)
        findings=self.parser.parse(output,interface)
        return {
            "scan_id":scan_id,
            "scanner":self.name,
            "scan_type":scan_type,
            "status":"COMPLETED",
            "target":interface,
            "duration":duration,
            "summary":{
                "total_findings":len(findings),
            },
            "findings":findings,
            "error":None

        }

if __name__=="__main__":
    scanner=TcpdumpScanner()
    res=scanner.scan("quick_capture","eth0")
    print(json.dumps(res,indent=2))

