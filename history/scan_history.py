import json
import os
from datetime import datetime

class ScanHistory:
    def __init__(self):
        self.history_dir="history"
        self.history_file=os.path.join(self.history_dir,"scan_history.json")
        os.makedirs(self.history_dir,exist_ok=True)

    def save_scan(self,result):
        history=[]
        if os.path.exists(self.history_file):
            with open(self.history_file,"r") as f:
                try:
                    history=json.load(f)
                except json.JSONDecodeError:
                    history=[]
        scan_type=result.get("scan_type",result.get("friendly_scan_type","Unknown"))
        target=result.get("target",result.get("Target","Unknown"))
        findings=result.get("findings",[])
        history_entry={
            "id":len(history)+1,
            "timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scanner":result.get("scanner","Unknown"),
            "scan_type":scan_type,
            "target":target,
            "duration":result.get("duration","Unknown"),
            "findings":len(findings)

        }
        history.append(history_entry)
        with open(self.history_file,"w") as f:
            json.dump(history,f,indent=4)

    def get_history(self):
        if not os.path.exists(self.history_file):
            return []
        with open(self.history_file,"r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
        