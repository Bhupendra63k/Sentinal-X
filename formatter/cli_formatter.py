class CLIFormatter:

    def display_summary(self,result):

        target=result["target"]
        ip=result["ip"]
        status=result["host_status"]
        port=result["ports"]
        scanner = result["scanner"]
        friendly_scan_type = result["scan_type"]
        scan_started = result["scan_started"]
        duration = result["duration"]

        print("="*60)
        print("         SCAN SUMMARY")
        print("="*60)

        scan_type_names = {
                    "quick": "Quick Scan",
                    "service": "Service Scan",
                            "os": "OS Detection",
                    "aggressive": "Aggressive Scan",
                    "full": "Full Scan"
                }

        friendly_scan_type = scan_type_names.get(result["scan_type"], result["scan_type"])

        print(f"Scanner Used : {scanner}")
        print(f"Scan Type: {friendly_scan_type}")
        print(f"Target: {target}")
        print(f"IP Address: {ip}")
        print(f"Host Status: {status}")
        print(f"Open ports: {len(result['ports'])}")
        print(f"Scan Started: {scan_started}")
        print(f"Scan Duration: {duration} seconds")

    def scanner_menu(self):
        print("="*60)
        print("              SentinelX-v1.0")
        print("       Modular Security Scanning Framework")
        print("="*60)
        print()
        print("Available Scanners:")
        print("-"*60)
        print("1. Nmap Scanner")
        print("2. Nikto")
        print("3. Nuclei")
        print("4. Full Security Scan")
        print("5. Scan History")
        print("0. Exit")

    def scan_menu(self):
        print("="*60)
        print("              Nmap Scan Types")
        print("="*60)
        print("1. Quick Scan")
        print("2. Service Scan")
        print("3. OS Detection")
        print("4. Aggressive Scan")
        print("5. Full Scan")
        print("0. Exit")
    
    def display_ports(self,result):
        print("="*60)
        print("             OPEN PORTS")
        print("="*60)
        print("port/protocol   state   service")
        print("-"*60)
        for p in result["ports"]:
            port_protocol = f"{p['port']}/{p['protocol']}"
            state = p["state"]
            service = p["service"]
            print(f"{port_protocol:<20}{state:<12}{service}")

    def nikto_scan_menu(self):
        print("="*60)
        print("              Nikto Scan Types")
        print("="*60)
        print("1.Basic Scan")
        print("2.ssl")
        print("3.redirects")
        print("4.info")
        print("5.injection")
        print("0.Exit")

    def nikto_display_summary(self,result):
        print("="*60)
        print("                     NIKTO SCAN SUMMARY")
        print("="*60)

        print(f"scanner used:{result.get('scanner','Nikto')}")
        print(f"Target:{result.get('Target','Unknown')}")
        print(f"ip address:{result.get('ip_address','Unknown')}")
        print(f"Host:{result.get('Host','Unknown')}")
        print(f"port:{result.get('port','Unknown')}")
        print(f"platform:{result.get('platform','Unknown')}")
        print(f"server:{result.get('server','Unknown')}")
        print(f"start time:{result.get('start_time','Unknown')}")
        print(f"end time:{result.get('end_time','Unknown')}")
        findings=result.get("findings",[])
        print(f"Total Findings:{len(findings)}")

    def display_nikto_findings(self,result):
            findings=result.get("findings",[])
            if not findings:
                print("No findings were reported by nikto")
            for index, finding in enumerate(findings,start=0):
                print(
                    f"{index}.[{finding.get('reference','N/A')}] "
                    f"{finding.get('finding','N/A')}"
                )

    
        

        