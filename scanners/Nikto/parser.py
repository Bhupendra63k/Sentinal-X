import re
from datetime import datetime

class NiktoParser:
    """Parser for Nikto scanner output."""
    def parse(self,output,target):
        result={
            "scanner": "Nikto",
            "Target": target,
            "ip_address": None,
            "Host": None,
            "port": None,
            "platform": None,
            "server": None,
            "start_time": None,
            "end_time": None,
            "findings": []
        }
        lines=output.splitlines()
        for line in lines:
            line=line.strip()
            if line.startswith("+ Target IP:"):
                result["ip_address"]=line.split(":",1)[1].strip()
            elif line.startswith("+ Target Hostname:"):
                result["Host"]=line.split(":",1)[1].strip()
            elif line.startswith("+ Target Port:"):
                result["port"]=line.split(":")[1].strip()
            elif line.startswith("+ Server:"):
                result["server"]=line.split(":")[1].strip()
            elif line.startswith("+ Platform:"):
                result["platform"]=line.split(":")[1].strip()
            elif line.startswith("+ ["):
                match=re.match(r"\+\s+\[(\d+)\]\s+(.*)",line)
                if match:
                    reference=match.group(1)
                    finding=match.group(2).strip()
                    result["findings"].append({"reference": reference, "finding": finding})
            elif line.startswith("+ Start Time:"):
                result["start_time"]=line.split(":",1)[1].strip()
            elif line.startswith("+ End Time:"):
                result["end_time"]=line.split(":",1)[1].strip()

            if result["start_time"] and result["end_time"]:
                try:
                    start_str=result["start_time"].split(" (")[0]
                    end_str=result["end_time"].split(" (")[0]
                    start=datetime.strptime(start_str, "%Y-%m-%d %H:%M:%S")
                    end=datetime.strptime(end_str, "%Y-%m-%d %H:%M:%S")
                    result["duration"]=round((end-start).total_seconds(),2)
                except ValueError as e:
                    print(f"Duration calculation failed: {e}")
                    result["duration"]=None
        return result