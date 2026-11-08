class CLIFormatter:
    WIDTH=60

    def _line(self, char="="):
        print(char * self.WIDTH)
    
    def _title(self,title):
        self._line()
        print((title.center(self.WIDTH)))
        self._line()

    def _field(self,label,value):
        print(f"{label:<15}: {value}")

    def display_nuclei_summary(self, result):
       self._title("NUCLEI SCAN SUMMARY")

       self._field("Target",result.get("target","Unknown"))
       self._field("Findings",len(result.get("findings",[])))
       print()

    def display_summary(self, result):
        target = result["target"]
        ip = result["ip"]
        status = result["host_status"]
        port = result["ports"]
        scanner = result["scanner"]
        friendly_scan_type = result["scan_type"]
        scan_started = result["scan_started"]
        duration = result["duration"]

        self._line()
        self._title("SCAN SUMMARY")
        self._line()

        scan_type_names = {
            "quick": "Quick Scan",
            "service": "Service Scan",
            "os": "OS Detection",
            "aggressive": "Aggressive Scan",
            "full": "Full Scan"
        }

        friendly_scan_type = scan_type_names.get(result["scan_type"], result["scan_type"])

        self._field("Scanner Used", scanner)
        self._field("Scan Type", friendly_scan_type)
        self._field("Target", target)
        self._field("IP Address", ip)
        self._field("Host Status", status)
        self._field("Open ports", len(result['ports']))
        self._field("Scan Started", scan_started)
        self._field("Scan Duration", f"{duration} seconds")

    def scanner_menu(self):
        self._line()
        print("              SentinelX-v1.0")
        print("       Modular Security Scanning Framework")
        self._line()
        print()
        print("Available Scanners:")
        self._line("-")
        print("1. Nmap Scanner")
        print("2. Nikto")
        print("3. Nuclei")
        print("4. Full Security Scan")
        print("5. Scan History")
        print("6. Credential Security Scanner")
        print("0. Exit")

    def scan_menu(self):
        self._line()
        print("              Nmap Scan Types")
        self._line("-")
        print("1. Quick Scan")
        print("2. Service Scan")
        print("3. OS Detection")
        print("4. Aggressive Scan")
        print("5. Full Scan")
        print("0. Exit")

    def display_ports(self, result):
        self._line()
        print("              OPEN PORTS")
        self._line("-")
        print("port/protocol   state   service")
        self._line("-")
        for p in result["ports"]:
            port_protocol = f"{p['port']}/{p['protocol']}"
            state = p["state"]
            service = p["service"]
            print(f"{port_protocol:<20}{state:<12}{service}")

    def nikto_scan_menu(self):
        self._line()
        print("              Nikto Scan Types")
        self._line("-")
        print("1.Basic Scan")
        print("2.ssl")
        print("3.redirects")
        print("4.info")
        print("5.injection")
        print("0.Exit")

    def nikto_display_summary(self, result):
        self._line()
        print("              NIKTO SCAN SUMMARY")
        self._line("-")

        print(f"scanner used:{result.get('scanner', 'Nikto')}")
        print(f"Target:{result.get('Target', 'Unknown')}")
        print(f"ip address:{result.get('ip_address', 'Unknown')}")
        print(f"Host:{result.get('Host', 'Unknown')}")
        print(f"port:{result.get('port', 'Unknown')}")
        print(f"platform:{result.get('platform', 'Unknown')}")
        print(f"server:{result.get('server', 'Unknown')}")
        print(f"start time:{result.get('start_time', 'Unknown')}")
        print(f"end time:{result.get('end_time', 'Unknown')}")
        findings = result.get("findings", [])
        print(f"Total Findings:{len(findings)}")

    def display_nikto_findings(self, result):
        findings = result.get("findings", [])
        self._title("NIKTO FINDINGS")
        if not findings:
            print("No findings were reported by nikto.")
            self._line("-")
            return
        for index, finding in enumerate(findings, start=1):
            print(f"[{index}] {finding.get('title', 'Unknown')}")
            self._field("severity", finding.get("severity", "Info"))
            self._field("Finding_Id", finding.get("finding_id", "Unknown"))
            self._field("description", finding.get("description", 'Unknown'))
            self._field("Evidence", finding.get("evidence", "Unknown"))
            self._field("reference", finding.get("reference", "Unknown"))
            print()
        self._line("-")

    def display_full_scan_summary(self, result):
        self._title("FULL SCAN SUMMARY")
        self._field("Target", result.get("target", "Unknown"))
        self._field("Duration", f"{result.get('duration', 0)} seconds")
        self._field(
            "Total Findings",result.get("summary", {}).get("total", 0))
        analysis=result.get('analysis',{})
        self._field("Overall Risk :",analysis.get("overall_risk","Info"))
        print()
        self._line("-")
        print(
            f"{'Scanner':<15}"
            f"{'Type':<15}"
            f"{'Findings':<15}")
        self._line("-")
        findings = result.get("findings", [])
        for scanner, scan_type in zip(
            result.get("scanners", []),
            result.get("scan_types", [])
       ):
            finding_count = sum(
                1 for finding in findings
                if finding.get("scanner") == scanner)
            print(
                f"{scanner:<15}"
                f"{scan_type:<15}"
                f"{finding_count:<15}")
            self._line("-")

    def display_scan_comparison(self,result):
        self._title("SCAN COMPARISON")
        summary=result.get("summary",{})
        self._field("New Findings",summary.get("new",0))
        self._field("Resolved",summary.get("resolved",0))
        self._field("Persistent",summary.get("persistent",0))
        print()
        for section,title in [("new","NEW FINDINGS"),("resolved","RESOLVED FINDINGS"),("persistent","PERSISTENT FINDINGS")]:
            print(title)
            self._line("-")
            findings=result.get(section,[])
            if not findings:
                print(None)
            else:
                for finding in findings:
                    print(f"-{finding.get('finding_id','Unknown')} "
                          f"| {finding.get('title','Unknown')}")
            print()