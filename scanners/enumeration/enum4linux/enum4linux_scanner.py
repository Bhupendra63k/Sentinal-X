import re
import shutil
import subprocess
import time
import uuid
from core.base_scanner import BaseScanner


class Enum4linuxScanner(BaseScanner):
    def __init__(self):
        self.name = "enum4linux"
        self.category = "enumeration"
        self.description = "SMB/Samba share, user, group, and anonymous Null-Session enumeration"
        self.target_type = "host"
        self.include_in_pipeline = False
        self.pipeline_order = 50
        self.default_pipeline_scan = "basic_smb"
        self.scan_commands = {
            "basic_smb": ["-S", "-U", "-o"],
            "shares_only": ["-S"],
            "full_enum": ["-a"],
        }

    def scan(self, scan_type: str, target: str, **kwargs) -> dict:
        scan_id = str(uuid.uuid4())
        clean_target = target.strip()
        start_time = time.time()

        if scan_type not in self.scan_commands:
            return {
                "scan_id": scan_id,
                "scanner": self.name,
                "scan_type": scan_type,
                "target": clean_target,
                "status": "FAILED",
                "findings": [],
                "error": f"Invalid Enum4linux scan profile: {scan_type}",
            }

        bin_path = shutil.which("enum4linux")
        if not bin_path:
            return {
                "scan_id": scan_id,
                "scanner": self.name,
                "scan_type": scan_type,
                "target": clean_target,
                "status": "FAILED",
                "findings": [],
                "error": "enum4linux binary not found. Install via 'sudo apt install enum4linux'.",
            }

        cmd = [bin_path] + self.scan_commands[scan_type] + [clean_target]
        findings = []

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = proc.stdout + "\n" + proc.stderr

            if "allows sessions using username '', password ''" in output.lower():
                findings.append({
                    "finding_id": "SMB-NULL-SESSION",
                    "scanner": self.name,
                    "url": f"smb://{clean_target}",
                    "title": "SMB Anonymous Null Session Allowed",
                    "severity": "High",
                    "description": f"Host {clean_target} permits unauthenticated SMB null sessions.",
                    "recommendation": "Disable anonymous IPC$ and SMB null sessions in Samba/Windows policy.",
                })

            shares = re.findall(r"^\s*([A-Za-z0-9_$-]+)\s+Disk\s+(.*)$", output, re.MULTILINE)
            for share_name, comment in shares:
                findings.append({
                    "finding_id": f"SMB-SHARE-{share_name.upper()}",
                    "scanner": self.name,
                    "url": f"smb://{clean_target}/{share_name}",
                    "title": f"SMB Share Exposed: {share_name}",
                    "severity": "Medium" if share_name.upper() not in {"IPC$", "PRINT$"} else "Info",
                    "description": f"Discovered network share '{share_name}' ({comment.strip() or 'No comment'}).",
                    "recommendation": "Audit share ACLs and disable guest/anonymous read access.",
                })

            users = re.findall(r"user:\[([^\]]+)\]\s+rid:\[([^\]]+)\]", output)
            if users:
                user_list = ", ".join([u[0] for u in users[:15]])
                findings.append({
                    "finding_id": "SMB-USERS-ENUMERATED",
                    "scanner": self.name,
                    "url": f"smb://{clean_target}",
                    "title": f"Enumerated {len(users)} SMB User Accounts",
                    "severity": "Medium",
                    "description": f"Retrieved user accounts via RPC/RID cycling: {user_list}",
                    "recommendation": "Restrict anonymous SAMR enumeration.",
                })

        except subprocess.TimeoutExpired:
            return {
                "scan_id": scan_id,
                "scanner": self.name,
                "scan_type": scan_type,
                "target": clean_target,
                "status": "FAILED",
                "findings": [],
                "error": "Enum4linux timed out after 60 seconds.",
            }
        except Exception as exc:
            return {
                "scan_id": scan_id,
                "scanner": self.name,
                "scan_type": scan_type,
                "target": clean_target,
                "status": "FAILED",
                "findings": [],
                "error": f"Enum4linux failed: {exc}",
            }

        duration = round(time.time() - start_time, 2)
        return {
            "scan_id": scan_id,
            "scanner": self.name,
            "scan_type": scan_type,
            "status": "COMPLETED",
            "target": clean_target,
            "duration": duration,
            "summary": {"total_findings": len(findings)},
            "findings": findings,
            "error": None,
        }