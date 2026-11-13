class NetworkSecurityAnalyzer:
    def analyze(self, nmap_result):
        findings = []
        ports = nmap_result.get("ports", [])
        target = nmap_result.get("target", "unknown")
        open_ports = []

        # --- Host Down Check ---
        if nmap_result.get("host_status") == "DOWN":
            findings.append({
                "scanner": "NetworkSecurity",
                "target": target,
                "finding_id": "NETWORK-HOST-DOWN",
                "title": "Host appears to be down",
                "severity": "Info",
                "description": (
                    f"The target {target} appears to be down or "
                    "unreachable according to Nmap result."
                ),
                "evidence": f"Host status: {nmap_result.get('host_status')}",
                "recommendation": (
                    "Verify that the target is online and reachable "
                    "before performing further security analysis."
                )
            })

        # --- Port Analysis ---
        for port in ports:
            if port.get("state") != "open":
                continue

            open_ports.append(port)
            finding = {
                "scanner": "NetworkSecurity",
                "target": target,
                "finding_id": f"NETWORK-{port.get('port')}",
                "title": f"Open port detected :{port.get('port')}",
                "severity": "Info",
                "description": (
                    f"Port {port.get('port')}/{port.get('protocol')} "
                    f"is exposed and running {port.get('service')}"
                ),
                "evidence": (
                    f"{port.get('port')}/{port.get('protocol')} "
                    f"{port.get('state')} {port.get('service')}"
                ),
                "recommendation": (
                    "Verify that this service is required and "
                    "restrict access if it is not necessary."
                )
            }

            # --- Service-Specific Rules ---
            service = port.get("service")
            if service in ["mysql", "postgresql", "mongodb", "redis"]:
                finding.update({
                    "severity": "High",
                    "title": f"Database service exposed: {service}",
                    "description": (
                        f"Database service {service} is exposed "
                        f"on port {port.get('port')}."
                    ),
                    "recommendation": (
                        "Restrict database access to trusted hosts or networks "
                        "and avoid exposing databases directly to untrusted networks."
                    )
                })

            elif service in ["ssh", "telnet", "rdp", "vnc"]:
                finding.update({
                    "severity": "Medium",
                    "title": f"Remote access service exposed: {service}",
                    "description": (
                        f"Remote access service {service} is exposed "
                        f"on port {port.get('port')}."
                    ),
                    "recommendation": (
                        "Verify that remote access is required and restrict "
                        "access to trusted networks or hosts."
                    )
                })

            if service == "telnet":
                finding.update({
                    "severity": "High",
                    "title": "Insecure remote access protocol exposed: Telnet",
                    "description": (
                        f"Telnet is exposed on port {port.get('port')}. "
                        "Telnet does not provide encrypted communication."
                    ),
                    "recommendation": (
                        "Disable Telnet where possible and use SSH or another "
                        "secure remote-access protocol instead."
                    )
                })

            if service == "http":
                finding.update({
                    "severity": "Medium",
                    "title": "Unencrypted HTTP service exposed",
                    "description": (
                        f"HTTP is exposed on port {port.get('port')}. "
                        "HTTP does not provide encrypted transport."
                    ),
                    "recommendation": (
                        "Use HTTPS instead of HTTP and redirect HTTP traffic "
                        "to HTTPS where appropriate."
                    )
                })

            if service == "smb":
                finding.update({
                    "severity": "Medium",
                    "title": "SMB service exposed",
                    "description": (
                        f"SMB is exposed on port {port.get('port')}. "
                        "Exposed SMB services should be restricted to trusted "
                        "networks and hosts."
                    ),
                    "recommendation": (
                        "Restrict SMB access to trusted networks and hosts, "
                        "and disable SMB where it is not required."
                    )
                })

            if service == "ftp":
                finding.update({
                    "severity": "Medium",
                    "title": "Insecure file transfer service exposed: ftp",
                    "description": (
                        f"FTP is exposed on port {port.get('port')}. "
                        "FTP does not provide encrypted communication by default."
                    ),
                    "recommendation": (
                        "Use a secure file transfer protocol such as SFTP where possible "
                        "and restrict FTP access to trusted networks and hosts."
                    )
                })

            # --- Version Info ---
            if port.get("version") and finding["severity"] == "Info":
                finding.update({
                    "title": f"Service version detected: {service}",
                    "description": (
                        f"{service} is exposing version information: "
                        f"{port.get('version')}."
                    ),
                    "recommendation": (
                        "Review whether service version information needs to be "
                        "exposed and keep the service updated."
                    )
                })

            findings.append(finding)

        # --- Correlation Findings ---
        sensitive_services = {
            port.get("service")
            for port in open_ports
            if port.get("service") in ["telnet", "mysql", "postgresql", "mongodb", "redis"]
        }

        if len(sensitive_services) >= 2:
            findings.append({
                "scanner": "NetworkSecurity",
                "target": target,
                "finding_id": "NETWORK-SENSITIVE-EXPOSURE",
                "title": "Multiple sensitive network services exposed",
                "severity": "High",
                "description": (
                    "Multiple sensitive network services are exposed: "
                    + ", ".join(sorted(sensitive_services)) + "."
                ),
                "evidence": (
                    "Sensitive services detected: "
                    + ", ".join(sorted(sensitive_services))
                ),
                "recommendation": (
                    "Review whether these services are required and restrict "
                    "access to trusted hosts or networks."
                )
            })

        if len(open_ports) > 3:
            findings.append({
                "scanner": "NetworkSecurity",
                "target": target,
                "finding_id": "NETWORK-EXPOSURE",
                "title": "Multiple network services exposed",
                "severity": "Info",
                "description": (
                    f"The target has {len(open_ports)} open network services. "
                    "Multiple exposed services increase the network exposure "
                    "surface and should be reviewed."
                ),
                "evidence": f"{len(open_ports)} open network services detected.",
                "recommendation": (
                    "Review all exposed services and disable or restrict "
                    "services that are not required."
                )
            })

        return findings