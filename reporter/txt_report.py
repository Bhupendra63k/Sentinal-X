from datetime import datetime
import os

class TXTReport:
    "it shows the report in text format"
    def save_reports(self,result):
        "saves scan results to a text file"
        scanner=result.get("scanner","unknown").lower()
        if scanner=="nmap":
            self.save_reports_nmap(result)
        elif scanner=="nikto":
            self.save_reports_nikto(result)
        elif scanner=="nuclei":
            self.save_reports_nuclei(result)
        elif scanner=="sentinalx":
            self.save_reports_sentinalx(result)
        elif scanner=="credential_scanner":
            self.save_reports_credential_scanner(result)
        else:
            print(f"unsupported scanner type:{scanner}.")

    def save_reports_nmap(self,result):
        target = result["target"]
        ip = result["ip"]
        status = result["host_status"]
        ports = result["ports"]
        scanner = result["scanner"]
        friendly_scan_type = result["scan_type"]
        scan_started = result["scan_started"]
        duration = result["duration"]
        os.makedirs("reports", exist_ok=True)
        filename = result.get("filename", os.path.join("reports",f"{target}_scan.txt"))

        if isinstance(ports, list):
            open_ports = ", ".join(
                str(item.get("port", item)) if isinstance(item, dict) else str(item)
                for item in ports
            )
        else:
            open_ports = str(ports)

        with open(filename, "w") as f:
            f.write("="*60 + "\n")
            f.write("               SentinalX scan results\n")
            f.write("="*60 + "\n")
            f.write(f"target: {target}\n")
            f.write(f"IP: {ip}\n")
            f.write(f"Host Status: {status}\n")
            f.write(f"Open Ports: {open_ports}\n")
            f.write(f"Scanner: {scanner}\n")
            f.write(f"Scan Type: {friendly_scan_type}\n")
            f.write(f"Scan Started: {scan_started}\n")
            f.write(f"Duration: {duration} seconds\n\n")

            f.write("="*60 + "\n")
            f.write("               Open Ports Details\n")
            f.write("="*60 + "\n")
            f.write(f"{'Port':<10}{'Protocol':<15}{'Service':<20}{'State':<10}\n")
            f.write("-"*60 + "\n")
            for port in ports:
                f.write(
                    f"{port['port']}/{port['protocol']:<15}"
                    f"{port['service']:<20}{port['state']:<10}\n"
                )
    def save_reports_nikto(self,result):
        scanner=result.get('scanner','Nikto')
        target=result.get('Target','Unknown')
        ip_address=result.get('ip_address','Unknown')
        host=result.get('Host','Unknown')
        port=result.get('port','Unknown')
        platform=result.get('platform','Unknown')
        server=result.get('server','Unknown')
        start_time=result.get('start_time','Unknown')
        end_time=result.get('end_time','Unknown')
        findings=result.get("findings",[])

        timestamp=datetime.now().strftime("%Y%m%d_%H%M%S")
        filename=f"reports/{scanner.lower()}_report_{timestamp}.txt"
        with open(filename,"w") as f:
            f.write("="*60 +"\n")
            f.write("              SentinalX Nikto scan Report\n")
            f.write("="*60 +"\n")

            f.write(f"scanner :{scanner}\n")
            f.write(f"target :{target}\n")
            f.write(f"ip_address:{ip_address}\n")
            f.write(f"host :{host}\n")
            f.write(f"port :{port}\n")
            f.write(f"platform:{platform}\n")
            f.write(f"server:{server}\n")
            f.write(f"start_time :{start_time}")
            f.write(f"end_time :{end_time}")
            f.write(f"findings:{len(findings)}")
            f.write("="*60 +"\n")
            f.write("        FINDINGS")
            f.write("="*60 +"\n")
            if not findings:
                f.write("No findings Detected.\n")
            else:
                for index,finding in enumerate(findings,start=1):
                    reference=finding.get("reference","N/A")
                    description=finding.get("finding","N/A")

                    f.write(f"{index}. [{reference}] {description} \n")

    def save_reports_nuclei(self,result):
        scanner=result.get("scanner","Nuclei")
        target=result.get("target","Unknown")
        scan_type=result.get("scan_type","Unknown")
        duration=result.get("duration","Unknown")
        findings=result.get("findings",[])
        timestamp=datetime.now().strftime("%Y%m%d_%H%M%S")
        filename=f"reports/{scanner.lower()}_report_{timestamp}.txt"
        with open(filename,"w") as f:
            f.write("="*60+"\n")
            f.write("              SentinalX Nuclei Scan Report\n")
            f.write("="*60+"\n")
            f.write(f"scanner :{scanner}\n")
            f.write(f"Target :{target}\n")
            f.write(f"Scan Type:{scan_type}\n")
            f.write(f"Duration :{duration}\n")
            f.write(f"Findings :{len(findings)}\n")
            f.write(f"="*60+"\n")
            f.write("              FINDINGS\n")
            f.write(f"="*60+"\n")
            if not findings:
                f.write("No findingd detected.\n")
            else:
                for index,finding in enumerate(findings,start=1):
                    f.write(f"\n{index}.{finding.get('title','Unknown')}\n")
                    f.write(f"   Severity:{finding.get('severity','Unknown')}\n")
                    f.write(f"   Finding ID    : {finding.get('finding_id','Unknown')}\n")
                    f.write(f"   Description   : {finding.get('description','')}\n")
                    f.write(f"   Evidence     : {finding.get('evidence','')}\n")
                    f.write(f"   Recommendation: {finding.get('recommendation','')}\n")


    def save_reports_sentinalx(self,result):
        timestamp=datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs("reports",exist_ok=True)
        filename=f"reports/sentinalx_report_{timestamp}.txt"
        findings=result.get("findings",[])
        summary=result.get("summary",{})
        analysis=result.get("analysis",{})

        with open(filename,"w",encoding="utf-8") as f:
            f.write("="*70+"\n")
            f.write("              SENTINALX SECURITY REPORT\n")
            f.write("="*70+"\n\n")
            f.write(f"Target    :{result.get('target','Unknown')}\n")
            f.write(f"Scan Type :{result.get('scan_type','Unknown')}\n")
            f.write(f"Duration  :{result.get('duration',0)} seconds\n")
            scanners=result.get("scanners",[])
            f.write(f"Scanners :{', '.join(scanners) if scanners else 'Unknown'}\n")
            f.write("\n")
            f.write("-"*70+"\n")
            f.write("                    FINDING SUMMARY\n")
            f.write("-"*70+"\n\n")
            if isinstance(summary,dict):
                f.write(f"Critical      :{summary.get('Critical',0)}\n")
                f.write(f"High          :{summary.get('High',0)}\n")
                f.write(f"Medium        :{summary.get('Medium',0)}\n")
                f.write(f"Low           :{summary.get('Low',0)}\n")
                f.write(f"Info          :{summary.get('Info',0)}\n")
            f.write("\n"+ "-"*70+"\n")
            f.write("                  SECURITY ANALYSIS\n")
            f.write("-"*70+"\n\n")
            f.write(f"Overall Risk : {analysis.get('overall_risk','Unknown')}\n")
            f.write(f"Total findings : {analysis.get('total_findings',0)}\n\n")
            f.write("Security Insights\n")
            insights=analysis.get("insights",[])
            if not insights:
                f.write("No security insights generated.\n")
            else:
                for insight in insights:
                    f.write(f"[{insight.get('severity','Info')}]"
                    f"{insight.get('title','Security Insight')}\n")
                    f.write(f"Target : {insight.get('target','unknown')}\n")
                    f.write(f"Type   : {insight.get('correlation_type','GENERAL')}\n")
                    f.write(f"\nRecommendations\n")
                    recommendations=insight.get('recommendations',[])
                    if not recommendations:
                        f.write("No recommendations generated.\n")
                    else:
                        for recommendation in recommendations:
                            f.write(
                                f"[{recommendation.get('severity','Info')}] "
                                f"{recommendation.get('action','')}\n")
                            f.write(f"Target : {recommendation.get('target','Unknown')}\n")
                    f.write("\n")
            for index,finding in enumerate(findings,start=1):
                f.write(f"[{index}] {finding.get('title','Unknown')}\n")
                f.write(f"Severity       :{finding.get('severity','Info')}\n")
                f.write(f"Scanner        :{finding.get('scanner','Unknown')}\n")
                f.write(f"Finding_id     :{finding.get('finding_id','Unknown')}\n")
                f.write(f"Target         :{finding.get('target','Unknown')}\n")
                f.write(f"Description    :{finding.get('description','')}\n")
                f.write(f"Evidence       :{finding.get('evidence','')}\n")
                f.write(f"Recommendation :{finding.get('recommendation','')}\n")
                f.write("\n"+"-"*70+"\n\n")
        print(f"sentinalX report saved: {filename}")

    def save_reports_credential_scanner(self,result):
        scanner=result.get("scanner","Credential Scanner")
        target=result.get("target","Unknown")
        scan_type=result.get("scan_type","Unknown")
        findings=result.get("findings",[])

        timestamp=datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs("reports",exist_ok=True)
        filename=f"reports/credential_scanner_report_{timestamp}.txt"

        with open(filename,"w",encoding="utf-8") as f:
            f.write("="*70+"\\n")
            f.write("              CREDENTIAL SCANNER REPORT\\n")
            f.write("="*70+"\\n\\n")
            f.write(f"Scanner   :{scanner}\\n")
            f.write(f"Target    :{target}\\n")
            f.write(f"Scan Type :{scan_type}\\n")
            f.write(f"Duration  :{result.get('duration',0)} seconds\\n")
            f.write("\\n")

            f.write("-"*70+"\\n")
            f.write("                    FINDINGS\\n")
            f.write("-"*70+"\\n\\n")

            if not findings:
                f.write("No findings detected.\\n")
            else:
                for index,finding in enumerate(findings,start=1):
                    f.write(f"[{index}] {finding.get('title','Unknown')}\\n")
                    f.write(f"Severity       :{finding.get('severity','Info')}\\n")
                    f.write(f"Scanner        :{finding.get('scanner','Unknown')}\\n")
                    f.write(f"Finding_id     :{finding.get('finding_id','Unknown')}\\n")
                    f.write(f"Target         :{finding.get('target','Unknown')}\\n")
                    f.write(f"Description    :{finding.get('description','')}\\n")
                    f.write(f"Evidence       :{finding.get('evidence','')}\\n")
                    f.write(f"Recommendation :{finding.get('recommendation','')}\\n")
                    f.write("\\n"+"-"*70+"\\n\\n")

            if scan_type=="john":
                john_result=result.get("john_result")

                f.write("\\n")
                f.write("-"*70+"\\n")
                f.write("                    JOHN THE RIPPER\\n")
                f.write("-"*70+"\\n\\n")

                if john_result:
                    f.write(f"Return code : {john_result.get('return_code','Unknown')}\\n")
                    f.write(f"Cracked     : {john_result.get('cracked',False)}\\n")
                    f.write(f"Password    : {john_result.get('password','N/A')}\\n")
                    f.write(f"ERROR       : {john_result.get('stderr','')}\\n")

            if scan_type=="hashcat":
                hashcat_result=result.get("hashcat_result")

                f.write("\\n")
                f.write("-"*70+"\\n")
                f.write("                    HASHCAT\\n")
                f.write("-"*70+"\\n\\n")

                if hashcat_result:
                    f.write(f"Return code : {hashcat_result.get('return_code','Unknown')}\\n")
                    f.write(f"Cracked     : {hashcat_result.get('cracked',False)}\\n")
                    f.write(f"Password    : {hashcat_result.get('password','N/A')}\\n")
                    f.write(f"ERROR       : {hashcat_result.get('stderr','')}\\n")

        print(f"Credential Scanner report saved: {filename}")


