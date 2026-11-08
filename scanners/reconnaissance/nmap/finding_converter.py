
from core.finding import Finding
from core.severity_normalizer import SeverityNormalizer


class NmapFindingConverter:
    """Convert Nmap port data into standardized findings."""

    def convert(self, result):
        findings = []
        target = result.get("target", "Unknown")
        normalizer = SeverityNormalizer()

        for index, port in enumerate(result.get("ports", []), start=1):
            if str(port.get("state", "")).lower() != "open":
                continue

            port_number = port.get("port", "Unknown")
            service = port.get("service") or "Unknown"
            protocol = port.get("protocol") or "Unknown"
            service_name = str(service).lower()

            severity = "Info"

            if service_name == "telnet" or str(port_number) == "23":
                severity = "High"
            elif service_name in {"mysql", "postgresql", "mongodb", "redis"}:
                severity = "High"
            elif service_name in {"ssh", "rdp", "vnc", "http", "smb", "ftp"}:
                severity = "Medium"

            finding = Finding(
                scanner="Nmap",
                target=target,
                finding_id=f"NMAP-{index}",
                title="Open Port Detected",
                severity=normalizer.normalize(severity),
                description=(
                    f"Port {port_number}/{protocol} "
                    f"running {service} is open."
                ),
                evidence=(
                    f"Port: {port_number}, Protocol: {protocol}, "
                    f"State: open, Service: {service}"
                ),
                recommendation=(
                    "Verify that this service is required, check its "
                    "configuration and exposure, and restrict access "
                    "where appropriate."
                ),
            )

            findings.append(finding)

        return findings
