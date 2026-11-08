class ScanComparator:

    def compare(self,previous_findings,current_findings):
        def finding_key(finding):
            finding_id=finding.get("finding_id")
            scanner=finding.get("scanner")
            if (
                not isinstance(finding_id,str)
                or not finding_id.strip()
                or not isinstance(scanner,str)
                or not scanner.strip()
            ):
                raise ValueError(
                    "Cannot compare findings with missing or invalid "
                    "finding_id or scanner."
                )
            return (
                scanner.strip().casefold(),
                finding_id.strip().casefold()
            )
        previous_keys={
            finding_key(finding)
            for finding in previous_findings
        }
        current_keys={
            finding_key(finding)
            for finding in current_findings
        }
        new_findings=[
            finding for finding in current_findings
            if finding_key(finding) not in previous_keys
        ]
        resolved_findings=[
            finding for finding in previous_findings
            if finding_key(finding) not in current_keys
        ]
        persistent_findings=[
            finding for finding in current_findings
            if finding_key(finding) in previous_keys
        ]

        return {
            "new": new_findings,
            "resolved": resolved_findings,
            "persistent": persistent_findings,
            "summary": {
                "new": len(new_findings),
                "resolved": len(resolved_findings),
                "persistent": len(persistent_findings)
            }
        }