import copy

from core.finding_summary import FindingSummary
from core.result_aggregator import ResultAggregator
from core.scan_orchestrator import ScanOrchestrator
from core.scanner_manager import ScannerManager
from formatter.cli_formatter import CLIFormatter
from history.scan_history import ScanHistory
from logger.scan_logger import ScanLogger
from reporter.json_report import JSONReport
from reporter.txt_report import TXTReport
from scanners.credential_security.credential_scanner import CredentialScanner
from scanners.reconnaissance.Nikto.nikto_scanner import NiktoScanner
from scanners.reconnaissance.nmap.nmap_scanner import NmapScanner
from scanners.reconnaissance.nuclei.nuclei_scanner import NucleiScanner
from core.security_analysis_engine import SecurityAnalysisEngine
from formatter.security_analysis_formatter import SecurityAnalysisFormatter


def display_finding_summary(result):
    summary = result.get("summary", {})
    print("\n" + "=" * 60)
    print("              FINDING SUMMARY")
    print("=" * 60)
    print(f"total findings: {summary.get('total', 0)}")
    severity_counts = summary.get("severity_counts", {})
    for severity in ["Critical", "High", "Medium", "Low", "Info"]:
        print(f"{severity:<10}: {severity_counts.get(severity, 0)}")
    print("-" * 60)


def process_scan_result(result):
    findings = result.get("findings", [])
    summarizer = FindingSummary()
    summary = summarizer.summarise(findings)
    result["summary"] = summary

    safe_result = copy.deepcopy(result)
    if safe_result.get("john_result"):
        safe_result["john_result"]["password"] = None

    if safe_result.get("hashcat_result"):
        safe_result["hashcat_result"]["password"] = None

    scan_history = ScanHistory()
    scan_history.save_scan(safe_result)

    json_reporter = JSONReport()
    json_reporter.save_reports(safe_result)

    txt_reporter = TXTReport()
    txt_reporter.save_reports(safe_result)

    scan_logger = ScanLogger()
    scan_logger.log_scan(safe_result)

def get_menu_choice(prompt,valid_choice):
    while True:
        choice=input(prompt).strip()
        if choice in valid_choice:
            return choice
        print(f"Invalid choice: {choice!r}. "
              f"Choose one of: {', '.join(valid_choice)}.")

def get_integer_input(prompt,field_name):
    while True:
        value =get_required_input(prompt,field_name)
        try:
            number=int(value)
        except ValueError:
            print(f"{field_name} must be a whole number.")
            continue
        if number>0:
            return number
        print(f"{field_name} must be greater than zero.")

def get_required_input(prompt,field_name):
    while True:
        value=input(prompt).strip()
        if value:
            return value
        print(f"{field_name} cannot be empty. Please try again.")
def main():
    nmap_scanner = NmapScanner()
    nikto_scanner = NiktoScanner()
    nuclei_scanner = NucleiScanner()
    credential_scanner = CredentialScanner()

    scanner_manager = ScannerManager()
    scanner_manager.register_scanner(nmap_scanner)
    scanner_manager.register_scanner(nikto_scanner)
    scanner_manager.register_scanner(nuclei_scanner)
    scanner_manager.register_scanner(credential_scanner)

    orchestrator = ScanOrchestrator(scanner_manager)
    formatter = CLIFormatter()


    formatter.scanner_menu()
    choice = get_menu_choice("Select Scanner : ",
                             {"0","1","2","3","4","5","6"}
                             )

    if choice == "1":
        formatter.scan_menu()
        scan_choice = get_menu_choice("Select Scan Type : ",
                                      {"1","2","3","4","5"}, )
        scan_type_map = {
            "1": "quick",
            "2": "service",
            "3": "os",
            "4": "aggressive",
            "5": "full",
        }
        scan_type = scan_type_map.get(scan_choice)
        if scan_type is None:
            print("Invalid choice. Exiting...")
            return

        target = get_required_input(
            "Enter Target IP or Domain: ",
            "Target",
                                    )
        if not target:
            print("Target cannot be empty. Exiting...")
            return

        result = scanner_manager.start_scan(
            scanner_name="nmap", scan_type=scan_type, target=target
        )
        if result is None:
            print("Scan failed. Exiting...")
            return

        process_scan_result(result)
        display_finding_summary(result)
        formatter.display_summary(result)
        formatter.display_ports(result)

    elif choice == "2":
        print("Nikto selected")
        formatter.nikto_scan_menu()
        scan_choice = get_menu_choice("Select Scan Type : ",
                                       {"1","2","3","4","5"}).strip()
        scan_type_map = {
            "1": "basic",
            "2": "ssl",
            "3": "redirects",
            "4": "info",
            "5": "injection",
        }
        scan_type = scan_type_map.get(scan_choice)
        if scan_type is None:
            print("Invalid choice. Exiting...")
            return

        target = get_required_input(
            "Enter Target URL : ",
            "Target",

                                    )
        if not target:
            print("Target cannot be empty. Exiting...")
            return

        result = scanner_manager.start_scan(
            scanner_name="nikto", scan_type=scan_type, target=target
        )
        if result is None:
            print("Scan failed. Exiting...")
            return

        process_scan_result(result)
        display_finding_summary(result)
        formatter.nikto_display_summary(result)
        formatter.display_nikto_findings(result)

    elif choice == "3":
        formatter._title("NUCLEI SCAN")
        target = get_required_input(
            "Enter Target URL: ",
            "Target",
        )
        if not target:
            print("Target cannot be empty. Exiting...")
            return

        result = scanner_manager.start_scan(
            scanner_name="nuclei", scan_type="default", target=target
        )
        if result is None:
            print("Scan failed. Exiting...")
            return

        process_scan_result(result)
        display_finding_summary(result)
        formatter.display_nuclei_summary(result)

    elif choice == "4":
        formatter._title("FULL SECURITY SCAN")
        target = get_required_input(
            "Enter Target URL/IP : ",
            "Target",
            )
        if not target:
            print("Target cannot be empty. Exiting...")
            return

        scan_data = orchestrator.run_full_scan(target)
        results = scan_data["results"]
        execution_results = scan_data["execution_results"]

        aggregator = ResultAggregator()
        combined_result = aggregator.aggregate(results, target)
        combined_result["execution_results"]=execution_results
        failed_scans=sum(1 for execution in execution_results if execution.get("status")=="failed")
        total_scans=len(execution_results)
        successful_scans=sum(1 for execution in execution_results if execution.get("status")=="success")
        if total_scans==0:
            combined_result["execution_status"]="no_scanners_executed"
        elif failed_scans==0:
            combined_result["execution_status"]="success"
        elif successful_scans==0:
            combined_result["execution_status"]="failed"
        else:
            combined_result["execution_status"]="partial_success"

        combined_result["scanner_execution_summary"]={"total":total_scans,"successful":successful_scans,"failed":failed_scans}
        summarizer = FindingSummary()
        prioritised_findings = summarizer.prioritise(
            combined_result["findings"]
        )
        combined_result["findings"] = prioritised_findings
        combined_result["summary"] = summarizer.summarise(prioritised_findings)

        analysis_engine = SecurityAnalysisEngine()
        analysis_result = analysis_engine.analyze(prioritised_findings)
        analysis_formatter = SecurityAnalysisFormatter()
        analysis_output=analysis_formatter.format(analysis_result)
        combined_result["analysis"] = analysis_result
        print(analysis_output)
        process_scan_result(combined_result)
        display_finding_summary(combined_result)
        formatter.display_full_scan_summary(combined_result)

        execution_summary=combined_result["scanner_execution_summary"]
        print("\n" + "="*60)
        print("SCANNER EXECUTION SUMMARY")
        print("="*60)
        print(f"Overall status : {combined_result['execution_status']}")
        print(f"Total scanners : {execution_summary['total']}")
        print(f"Successful     : {execution_summary['successful']}")
        print(f"Failed         : {execution_summary['failed']}")
        print(f"-"*60)
        for execution in execution_results:
            print(f"{execution.get('scanner_name','Unknown')} | "
                  f"{execution.get('scan_type','Unknown')} | "
                  f"{execution.get('status','Unknown')} | "
                  f"{execution.get('duration',0)}s")
        print("="*60)

    elif choice == "5":
        scan_history = ScanHistory()
        history = scan_history.get_history()

        formatter._line("-")
        print("              SCAN HISTORY")
        formatter._line("-")
        if not history:
            print("No scan history available.")
        else:
            for scan in history:
                findings=scan.get("findings",[])
                if isinstance(findings,list):
                    finding_count=len(findings)
                else:
                    finding_count=findings
                print(
                    f"ID: {scan['id']} | "
                    f"{scan['scanner']} | "
                    f"{scan['scan_type']} | "
                    f"{scan['target']} | "
                    f"{scan['duration']} sec | "
                    f"{finding_count} findings"
                )
            print()
            compare_choice=get_menu_choice(
                "Compare two scans? (y/n): ",
                {"y","n"},
            )
            if compare_choice=="y":
                try:
                    previous_id=get_integer_input(
                        "Enter previous scan ID: ",
                        "Previous scan ID")
                    
                    current_id=get_integer_input(
                        "Enter current scan ID: ",
                        "Current scan ID",)

                    comparison=scan_history.compare_scans(previous_id,current_id)
                    formatter.display_scan_comparison(comparison)
                except ValueError as error:
                    print(f"Comparison failed: {error}")

    elif choice == "6":
        formatter._title("CREDENTIAL SECURITY SCANNER")
        hash_file = None
        wordlist = None
        mode = None
        target = None

        print("1. Hash Identification")
        print("2. Hashcat")
        print("3. John the Ripper")
        print("4. Show Cracked Passwords")
        print("5. Show credential history")

        credential_choice = get_menu_choice(
            "Select Scan Type : ",
            {"1","2","3","4","5"}
        )

        if credential_choice == "1":
            scan_type = "hash_identification"
            target = get_required_input(
                "Enter Hash Here : ",
                "Hash",)
            if not target:
                print("Hash cannot be empty. Exiting...")
                return

        elif credential_choice == "2":
            scan_type = "hashcat"
            target = "hashcat"
            hash_file = get_required_input(
                "Enter your hash file: ",
                "Hash file",)
            mode = get_required_input(
                "Enter Hashcat mode : ",
                "Hashcat mode",)
            wordlist = get_required_input(
                "Enter wordlist : ",
                "Wordlist",)
            if not hash_file or not mode or not wordlist:
                print("Hash file, mode, and wordlist cannot be empty.")
                return

        elif credential_choice == "3":
            scan_type = "john"
            target = "john"
            hash_file = get_required_input(
                "Enter Hash file : ",
                "Hash file",)
            wordlist = get_required_input(
                "Enter wordlist : ",
                "Wordlist",)
            if not hash_file or not wordlist:
                print("Hash file and wordlist cannot be empty.")
                return

        elif credential_choice == "4":
            hash_file = get_required_input(
                "Enter Hash file : ",
                "Hash file",)
            if not hash_file:
                print("Hash file cannot be empty.")
                return

            cred_scanner = scanner_manager.scanners.get("credential_scanner")
            if cred_scanner is None:
                print("Credential scanner not found.")
                return

            result = cred_scanner.show_john_cracked(hash_file)
            if result is None:
                print("Unable to retrieve cracked passwords.")
                return

            print("\n===== CRACKED PASSWORDS =====")
            print(f"Hash file : {result.get('hash_file')}")
            if result.get("cracked"):
                print(f"Hash      : {result.get('hash')}")
                print(f"Password  : {result.get('password')}")
                print("Status    : CRACKED")
            else:
                print(f"Hash      : {result.get('hash')}")
                print("Password  : Not Found")
                print("Status    : NOT CRACKED")
            return
        elif credential_choice=="5":
            print("\n==================================================")
            print("             CREDENTIAL SCAN HISTORY")
            print("====================================================")
            print("1. ALL")
            print("2. John the ripper")
            print("3. Hashcat")
            print("4. Hash Identification")
            print("5. View Scan Details")
            history_choice=get_menu_choice(
                "Select History Type: ",
                {"1","2","3","4","5"},
            )
            
            history=ScanHistory()
            records=history.get_history()
            records=[
                record for record in records
                if record.get("scanner")=="credential_scanner"
            ]
            if history_choice=="2":
                selected_type="john"
            elif history_choice=="3":
                selected_type="hashcat"
            elif history_choice=="4":
                selected_type="hash_identification"
            elif history_choice=="5":
                if not records:
                    print("No credential scan history found.")
                    return 
                print("\nAvailable credential scans:")
                for record in records:
                    print(
                        f"ID: {record.get('id')} | "
                        f"Type: {record.get('scan_type')} | "
                        f"Target: {record.get('target')} | "
                        f"Status: {record.get('status','Unknown')}"
                    )
                scan_id=get_integer_input(
                    "Enter scan history ID: ",
                    "Scan history ID"
                )
                selected_record=next((record for record in records if record.get("id")==scan_id),None)
                if selected_record is None:
                    print("No credential scan found with that ID.")
                    return 
                print("\n========== CREDENTIAL SCAN DETAILS ==========")
                for key,value in selected_record.items():
                    print(f"{key.replace('_',' ').title():<20}:{value}")
                print("="*48)
                return 
            elif history_choice=="1":
                selected_type=None
            else:
                print("Invalid history")
                return 
            if selected_type:
                records=[
                    record for record in records
                    if str(record.get("scan_type","")).strip().lower()==selected_type
                ]
            print("\n==================================================")
            print("             CREDENTIAL SCAN HISTORY")
            print("\n==================================================")
            if not records:
                print("No credential scan history found.")
                return 
            for record in records:
                if record.get("scanner")!="credential_scanner":
                    continue

                print(f"\nID      : {record.get('id')}")
                print(f"Time       : {record.get('timestamp')}")
                print(f"Type       : {record.get('scan_type')}")
                print(f"Target     : {record.get('target')}")
                print(f"Status     : {record.get('status','Unknown')}")
                print(f"Duration   : {record.get('duration','Unknown')}s") 
                print("-"*50)
            return 

        else:
            print("Invalid choice. Exiting...")
            return

        result = scanner_manager.start_scan(
            scanner_name="credential_scanner",
            scan_type=scan_type,
            target=target,
            hash_file=hash_file,
            mode=mode,
            wordlist=wordlist,
        )
        if result is None:
            print("Scan failed. Exiting...")
            return

        process_scan_result(result)

    elif choice == "0":
        print("Exiting...")
        return

    else:
        print("Invalid choice. Exiting...")


if __name__ == "__main__":
    main()