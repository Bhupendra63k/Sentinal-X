import json
import shutil
import subprocess
import time
import uuid
from core.base_scanner import BaseScanner

class WhatwebScanner(BaseScanner):
    def __init__(self):
        self.name="whatweb"
        self.category="reconnaissance"
        self.description = "Web technology stack, CMS, framework, and server fingerprinting"
        self.target_type="web"
        self.target_type=True
        self.pipeline_order=25
        self.default_pipeline_scan="passive"
        self.scan_commands={
            "passive":["-a","1"],
            "aggressive":["-a","3"]
        }

    def scan(self,scan_type:str,target:str,**kwargs) ->dict:
        scan_id=str(uuid.uuid4())
        clean_target=target.strip()
        start_time=time.time()
        if scan_type not in self.scan_commands:
            return {
                "scan_id":scan_id,
                "scanner":self.name,
                "scan_type":scan_type,
                "target":clean_target,
                "status":"FAILED",
                "findings":[],
                "error":f"Invalid Whatweb scan profile: {scan_type}",
            }
        bin_path=shutil.which("whatweb")
        if not bin_path:
            return {
            "scan_id": scan_id,
            "scanner":self.name,
            "scan_type":scan_type,
            "target":clean_target,
            "status":"FAILED",
            "findings":[],
            "error":"whatweb binary not found.Install via 'sudo apt install whatweb'.",
            }
        cmd=[bin_path,"--color=never","--log-json=-"] + self.scan_commands[scan_type] +[clean_target]
        findings=[]
        try:
            proc=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
            for line in proc.stdout.splitlines():
                line=line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    data=json.loads(line)
                    plugins=data.get("plugins",{})
                    detected=[]
                    for tech,details in plugins.items():
                        if tech in {"Title","IP","Country"}:
                            continue
                        versions=details.get("version",[])
                        ver_str=f" v{versions[0]}" if versions else ""
                        detected.append(f"{tech}{ver_str}")
                    if detected:
                        findings.append({
                            "finding_id":"WEB-TECH-FINGERPRINT",
                            "scanner":self.name,
                            "url":data.get("target",clean_target),
                            "title":f"Web Stack Fingerprinted ({len(detected)} technologies)",
                            "severity":"Info",
                            "description": f"Detected technologies on {clean_target}: {', '.join(detected)}",
                            "recommendation": "Suppress verbose Server and X-Powered-By version headers.",
                        })
                except json.JSONDecodeError:
                    continue
        except subprocess.TimeoutExpired:
            return {
                "scan_id":scan_id,
                "scanner":self.name,
                "scan_type":scan_type,
                "target":clean_target,
                "status":"FAILED",
                "findings":[],
                "error":"Whatweb timed out after 30 seconds."
            }
        except Exception as e:
            return {
                "scan_id":scan_id,
                "scanner":self.name,
                "scan_type":scan_type,
                "target":clean_target,
                "status":"FAILED",
                "findings":[],
                "error":f"WhatWeb execution failed:{e}",
            }
        duration=round(time.time()-start_time,2)
        return {
            "scan_id":scan_id,
            "scanner":self.name,
            "scan_type":scan_type,
            "status":"COMPLETED",
            "target":clean_target,
            "duration":duration,
            "summary":{"total_findings":len(findings)},
            "findings":findings,
            "error":None   
        }