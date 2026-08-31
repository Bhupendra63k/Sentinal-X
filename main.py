from core.scanner_manager import ScannerManager
from scanners.nmap.nmap_scanner import NmapScanner
from scanners.Nikto.nikto_scanner import NiktoScanner
from formatter.cli_formatter import CLIFormatter
from reporter.json_report import JSONReport
from logger.scan_logger import ScanLogger
from reporter.txt_report import TXTReport
from history.scan_history import ScanHistory
from scanners.nuclei.nuclei_scanner import NucleiScanner
from core.finding_summary import FindingSummary
from core.scan_orchestrator import ScanOrchestrator
from core.result_aggregator import ResultAggregator

def display_finding_summary(result):
    summary=result.get("summary",{})
    print("\n"+"="*60)
    print("             FINDING SUMMARY")
    print("="*60)
    print(f"total findings:{summary.get('total',0)}")
    severity_counts=summary.get("severity_counts",{})
    for severity in ["Critical","High","Medium","Low","Info"]:
        print(
            f"{severity:<10}: "
            f"{severity_counts.get(severity,0)}"
        )
    print("="*60)

def process_scan_result(result):
    findings=result.get("findings",[])
    summarizer=FindingSummary()
    summary=summarizer.summarise(findings)
    result["summary"]=summary
    scan_history = ScanHistory()
    scan_history.save_scan(result)

    json_reporter = JSONReport()
    json_reporter.save_reports(result)

    txt_reporter = TXTReport()
    txt_reporter.save_reports(result)

    scan_logger = ScanLogger()
    scan_logger.log_scan(result)

    
def main():
    nmap_scanner=NmapScanner()
    nikto_scanner=NiktoScanner()
    nuclei_scanner=NucleiScanner()
    scanner_manager=ScannerManager()
    scanner_manager.register_scanner(nmap_scanner)
    scanner_manager.register_scanner(nikto_scanner)
    scanner_manager.register_scanner(nuclei_scanner)
    orchestrator=ScanOrchestrator(scanner_manager)
    

    formatter = CLIFormatter()
    formatter.scanner_menu()
    choice = input("Select Scanner : ")
    if choice=="1":
        formatter.scan_menu()
        scan_choice = input("Select Scan Type : ")
        scan_type_map = {
            "1": "quick",
            "2": "service",
            "3": "os",
            "4": "aggressive",
            "5": "full"
        }
        scan_type=scan_type_map.get(scan_choice)
        if scan_type is None:
            print("Invalid choice. Exiting...")
            return
        target = input("Enter Target IP or Domain: ").strip()
        if not target:
             print("target cannot be empty. Exiting...")
             return
        
        result=scanner_manager.start_scan(scanner_name="nmap",scan_type=scan_type,target=target)
        if result is None:
            print("Scan failed. Exiting...")
            return
        process_scan_result(result)
        display_finding_summary(result)

        formatter.display_summary(result)
        formatter.display_ports(result)
        
    elif choice=="0":
        print("Exiting...")
        return

        #ask for ip
    elif choice=="2":
        print("Nikto selected")
        formatter.nikto_scan_menu()
        scan_choice=input("Select Scan Type : ")
        scan_type_map={
            "1":"basic",
            "2":"ssl",
            "3":"redirects",
            "4":"info",
            "5":"injection"
        }
        scan_type=scan_type_map.get(scan_choice)
        if scan_type is None:
            print("Invalid choice. Exiting...")
            return
        target=input("Enter Target URL :").strip()
        if not target:
            print("Target cannot be empty.  Exiting....")
            return 
        result=scanner_manager.start_scan(scanner_name="nikto",scan_type=scan_type,target=target)
        if result is None:
            print("Scan failed. Exiting...")
            return
        process_scan_result(result)
        display_finding_summary(result)

        formatter.nikto_display_summary(result)
        formatter.display_nikto_findings(result)
        
    elif choice=="3":
        print("Nuclei selected")
        target=input("Enter Target URL :").strip()
        if not target:
            print("Target cannot be empty.Existing ....")
            return 
        result=scanner_manager.start_scan(
            scanner_name="nuclei",
            scan_type="default",
            target=target 
        )
        if result is None:
            print("Scan failed. Exiting...")
            return
        process_scan_result(result)
        display_finding_summary(result)

    elif choice=="4":
        print("Full Security Scan Selected")
        target=input("Enter Target URL/IP :").strip()
        if not target:
            print("Target cant be empty.Exiting ...")
            return
        results=orchestrator.run_full_scan(target)
        aggregator=ResultAggregator()
        combined_result=aggregator.aggregate(results,target)
        summarizer=FindingSummary()
        prioritised_findings=summarizer.prioritise(combined_result["findings"])
        combined_result["findings"]=prioritised_findings
        combined_result["summary"]=summarizer.summarise(prioritised_findings)
        process_scan_result(combined_result)
        display_finding_summary(combined_result)
        print("\n"+"="*60)
        print("           FULL SECURITY SCAN")
        print("="*60)
        print(f"Scanner completed:{len(results)}")
        for result in results:
            print(
                f"{result.get('scanner','Unknown')} |"
                f"{result.get('scan_type','Unknown')} |"
                f"{len(result.get('findings',[]))} findings"
            )
        print("="*60)
    elif choice=="5":
        scan_history=ScanHistory()
        history=scan_history.get_history()

        print("="*60)
        print("             SCAN HISTORY")
        print("="*60)
        if not history:
            print("No scan history available.")
        for scan in history:
            print(
                f"ID: {scan['id']} | "
                f"{scan['scanner']} | "
                f"{scan['scan_type']} | "
                f"{scan['target']} | "
                f"{scan['duration']} sec | "
                f"{scan['findings']} findings "
            )
    else:
        print("Invalid choice.   Existing....")
            #ask for ip

if __name__=="__main__":
    main()
