from core.result_aggregator import ResultAggregator
from core.finding_summary import FindingSummary
from reporter.txt_report import TXTReport
from reporter.json_report import JSONReport


results = [
    {
        "scanner": "Nmap",
        "scan_type": "quick",
        "target": "127.0.0.1",
        "duration": 2.5,
        "findings": [
            {
                "finding_id": "NMAP-001",
                "title": "Open HTTP Port",
                "severity": "Info",
                "description": "HTTP service detected.",
                "evidence": "80/tcp open http",
                "recommendation": "Review whether the service needs to be exposed."
            }
        ]
    },
    {
        "scanner": "Nikto",
        "scan_type": "basic",
        "target": "http://127.0.0.1:8000",
        "duration": 5.0,
        "findings": [
            {
                "finding_id": "NIKTO-001",
                "title": "Missing Security Header",
                "severity": "Medium",
                "description": "A security header is missing.",
                "evidence": "Header not present",
                "recommendation": "Configure the appropriate security header."
            }
        ]
    },
    {
        "scanner": "Nuclei",
        "scan_type": "default",
        "target": "http://127.0.0.1:8000",
        "duration": 10.0,
        "findings": [
            {
                "finding_id": "NUCLEI-001",
                "title": "Test High Finding",
                "severity": "High",
                "description": "Controlled Nuclei test finding.",
                "evidence": "Test evidence",
                "recommendation": "Apply the recommended fix."
            }
        ]
    }
]


target = "http://127.0.0.1:8000"

aggregator = ResultAggregator()
combined_result = aggregator.aggregate(results, target)

summarizer = FindingSummary()

prioritised_findings = summarizer.prioritise(
    combined_result["findings"]
)

combined_result["findings"] = prioritised_findings

combined_result["summary"] = summarizer.summarise(
    prioritised_findings
)

print("\n" + "=" * 60)
print("          SENTINALX REPORTING PIPELINE TEST")
print("=" * 60)

print(f"Scanners : {combined_result['scanners']}")
print(f"Findings : {len(combined_result['findings'])}")
print(f"Summary  : {combined_result['summary']}")

TXTReport().save_reports(combined_result)
JSONReport().save_reports(combined_result)

print("=" * 60)
print("REPORTING PIPELINE TEST COMPLETE")
print("=" * 60)