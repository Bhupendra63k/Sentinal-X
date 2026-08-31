from core.finding_manager import FindingManager


class ResultAggregator:

    def aggregate(self, results, target):

        combined_findings = []
        scanners = []
        scan_types = []
        durations = []

        finding_manager = FindingManager()

        for result in results:

            if not result:
                continue

            scanner = result.get("scanner", "Unknown")

            if scanner not in scanners:
                scanners.append(scanner)

            scan_type = result.get("scan_type", "Unknown")

            if scan_type not in scan_types:
                scan_types.append(scan_type)

            duration = result.get("duration", 0)

            try:
                durations.append(float(duration))
            except (TypeError, ValueError):
                durations.append(0)

            findings = result.get("findings", [])

            finding_manager.add_findings(findings)

        combined_findings = finding_manager.get_findings()

        return {
            "scanner": "SentinalX",
            "scan_type": "Full-security",
            "target": target,
            "scanners": scanners,
            "scan_types": scan_types,
            "duration": round(sum(durations), 2),
            "findings": combined_findings
        }
if __name__ == "__main__":

    test_results = [
        {
            "scanner": "Nmap",
            "scan_type": "quick",
            "duration": 10.5,
            "findings": [
                {
                    "finding_id": "NMAP-001",
                    "title": "Open Port",
                    "severity": "Info"
                }
            ]
        },
        {
            "scanner": "Nuclei",
            "scan_type": "default",
            "duration": 20.5,
            "findings": [
                {
                    "finding_id": "NUCLEI-001",
                    "title": "Missing Security Header",
                    "severity": "Medium"
                }
            ]
        }
    ]

    aggregator = ResultAggregator()

    result = aggregator.aggregate(
        test_results,
        "http://127.0.0.1:8000"
    )

    print(result)