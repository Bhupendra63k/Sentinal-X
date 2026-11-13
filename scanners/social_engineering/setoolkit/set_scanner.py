import shutil
import subprocess
import time
import uuid
from core.base_scanner import BaseScanner


class SetoolkitScanner(BaseScanner):
    def __init__(self):
        self.name = "setoolkit"
        self.category = "social_engineering"
        self.description = "Social-Engineer Toolkit: Domain spoofing audit, harvester readiness & QR payload vector"
        self.target_type = "host"
        self.include_in_pipeline = False
        self.pipeline_order = 80
        self.default_pipeline_scan = "spoof_surface_audit"
        self.scan_commands = {
            "spoof_surface_audit": "Audit SPF/DMARC records for email spoofing susceptibility",
            "harvester_port_check": "Verify SET binary and local port 80 listener readiness",
            "generate_qr_payload": "Generate a QR code attack vector via SET CLI automation",
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
                "error": f"Invalid SET scan profile: {scan_type}",
            }

        set_path = shutil.which("setoolkit")
        if not set_path:
            return {
                "scan_id": scan_id,
                "scanner": self.name,
                "scan_type": scan_type,
                "target": clean_target,
                "status": "FAILED",
                "findings": [],
                "error": "setoolkit binary not found. Install via 'sudo apt install set'.",
            }

        findings = []

        try:
            if scan_type == "spoof_surface_audit":
                spf_proc = subprocess.run(
                    ["dig", "+short", "TXT", clean_target],
                    capture_output=True, text=True, timeout=10
                )
                dmarc_proc = subprocess.run(
                    ["dig", "+short", "TXT", f"_dmarc.{clean_target}"],
                    capture_output=True, text=True, timeout=10
                )

                if "v=spf1" not in spf_proc.stdout.lower():
                    findings.append({
                        "finding_id": "SET-MISSING-SPF",
                        "scanner": self.name,
                        "url": f"domain://{clean_target}",
                        "title": "Missing SPF Record (Email Spoofing Risk)",
                        "severity": "High",
                        "description": f"No SPF record found for {clean_target}; attackers can spoof emails in spear-phishing campaigns.",
                        "recommendation": "Publish a strict TXT SPF record ending with '-all'.",
                    })

                if "v=dmarc1" not in dmarc_proc.stdout.lower():
                    findings.append({
                        "finding_id": "SET-MISSING-DMARC",
                        "scanner": self.name,
                        "url": f"domain://{clean_target}",
                        "title": "Missing DMARC Policy",
                        "severity": "Medium",
                        "description": f"No DMARC policy detected at _dmarc.{clean_target}.",
                        "recommendation": "Configure a DMARC policy with p=quarantine or p=reject.",
                    })

                if not findings:
                    findings.append({
                        "finding_id": "SET-SPOOF-PROTECTED",
                        "scanner": self.name,
                        "url": f"domain://{clean_target}",
                        "title": "Anti-Spoofing Controls Configured",
                        "severity": "Info",
                        "description": f"SPF and DMARC records are present for {clean_target}.",
                        "recommendation": "Monitor DMARC aggregate reports regularly.",
                    })

            elif scan_type == "harvester_port_check":
                ss_proc = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=5)
                port_80_busy = ":80 " in ss_proc.stdout
                findings.append({
                    "finding_id": "SET-HARVESTER-ENV",
                    "scanner": self.name,
                    "url": f"http://{clean_target}:80",
                    "title": "Port 80 Occupied" if port_80_busy else "SET Credential Harvester Ready",
                    "severity": "Info",
                    "description": (
                        "Port 80 is already in use locally; free port 80 before starting SET harvester."
                        if port_80_busy else
                        f"SET verified at {set_path} and port 80 is free for authorized cloning simulations."
                    ),
                    "recommendation": "Run credential harvesting simulations strictly within authorized lab scope.",
                })

            elif scan_type == "generate_qr_payload":
                qr_input = f"1\n8\n{clean_target}\n99\n99\n"
                subprocess.run(
                    [set_path],
                    input=qr_input,
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                findings.append({
                    "finding_id": "SET-QRCODE-GENERATED",
                    "scanner": self.name,
                    "url": clean_target,
                    "title": "SET QR Code Phishing Vector Generated",
                    "severity": "Info",
                    "description": f"Generated QR payload targeting {clean_target} inside /root/.set/reports/.",
                    "recommendation": "Review /root/.set/reports/qrcode_attack.png for authorized security awareness testing.",
                })

        except Exception as exc:
            return {
                "scan_id": scan_id,
                "scanner": self.name,
                "scan_type": scan_type,
                "target": clean_target,
                "status": "FAILED",
                "findings": [],
                "error": f"SET execution failed: {exc}",
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