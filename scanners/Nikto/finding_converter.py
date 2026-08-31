from core.finding import Finding
from core.severity_normalizer import SeverityNormalizer

class NiktoFindingConverter:
    def convert(self,result):
        findings=[]
        normalizer=SeverityNormalizer()
        target=result.get("Target",result.get("target","Unknown"))
        for index,item in enumerate(result.get("findings",[]),start=1):
            reference=item.get("reference",f"NIKTO-{index}")
            finding_id=f"NIKTO-{reference}-{index}"
            finding=Finding(
                scanner="Nikto",
                target=target,
                finding_id=finding_id,
                title="Nikto Finding",
                severity=normalizer.normalize("Info"),
                description=item.get("finding",""),
                evidence=item.get("finding",""),
                recommendation="Review and remediate the reported issue."
            )
            findings.append(finding)
        return findings