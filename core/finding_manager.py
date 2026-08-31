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

