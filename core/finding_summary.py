class FindingSummary:

    SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
    SEVERITY_PRIORITY = {
        "Critical": 5,
        "High": 4,
        "Medium": 3,
        "Low": 2,
        "Info": 1
    }

    def summarise(self, findings):
        summary = {
            "total": len(findings),
            "severity_counts": {
                severity: 0
                for severity in self.SEVERITIES
            }
        }

        for finding in findings:
            severity = finding.get("severity", "Info").capitalize()

            if severity not in summary["severity_counts"]:
                severity = "Info"

            summary["severity_counts"][severity] += 1

        return summary

    def prioritise(self,findings):
        return sorted(
            findings,
            key=lambda finding:self.SEVERITY_PRIORITY.get(
                finding.get("severity","Info").capitalize(),
                1
            ),
            reverse=True
    )

if __name__ == "__main__":

    findings = [
        {"severity": "Info", "title": "Information Finding"},
        {"severity": "High", "title": "High Finding"},
        {"severity": "Critical", "title": "Critical Finding"},
        {"severity": "Low", "title": "Low Finding"},
        {"severity": "Medium", "title": "Medium Finding"},
        {"severity": "High", "title": "Another High Finding"}
    ]

    summarizer = FindingSummary()

    summary = summarizer.summarise(findings)

    prioritised = summarizer.prioritise(findings)

    print("SUMMARY")
    print(summary)

    print("\nPRIORITISED FINDINGS")

    for finding in prioritised:
        print(
            f"{finding['severity']:<10} | "
            f"{finding['title']}"
        )