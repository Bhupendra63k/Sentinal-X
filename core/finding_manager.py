class FindingManager:
    def __init__(self):
        self.findings=[]

    def add_findings(self,findings):
        for finding in findings:
            if not self._is_duplicate(finding):
                self.findings.append(finding)

    def _is_duplicate(self,finding):
        new_key=self._get_finding_key(finding)
        for existing in self.findings:
            if self._get_finding_key(existing)==new_key:
                return True
        return False

    def _get_finding_key(self,finding):
        if isinstance(finding,dict):
            return(
                finding.get("scanner",""),
                finding.get("target",""),
                finding.get("finding_id",""),
            )
        return (
            finding.scanner,
            finding.target,
            finding.finding_id,
        )

    def get_findings(self):
        return self.findings

    def clear(self):
        self.findings.clear()

    def count(self):
        return len(self.findings)

    def get_by_severity(self,severity):
        results=[]
        for finding in self.findings:
            if isinstance(finding,dict):
                finding_severity=finding.get("severity"," ")
            else:
                finding_severity=finding.severity
            if finding_severity.lower()==severity.lower():
                results.append(finding)
        return results

    def severity_summary(self):
        summary={
            "Critical":0,
            "High":0,
            "Medium":0,
            "Low":0,
            "Info":0
        }
        for finding in self.findings:
            if isinstance(finding,dict):
                severity=finding.get("severity","Info")
            else:
                severity=finding.severity
            severity=severity.capitalize()
            if severity in summary:
                summary[severity]+=1
        return summary



