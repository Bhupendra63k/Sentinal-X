from core.finding import Finding
from core.severity_normalizer import SeverityNormalizer


class NucleiFindingConverter:
    def convert(self,results):
        findings=[]
        normalizer=SeverityNormalizer()
        for result in results:
            info=result.get("info",{})
            finding=Finding(
                scanner="Nuclei",
                target=result.get("host",result.get("matched-at","Unknown")),
                finding_id=result.get("template-id","Unknown"),
                title=info.get("name","Nuclei Finding"),
                severity=normalizer.normalize(info.get("severity", "info")),
                description=info.get("description","No description provided by nuclei."),
                evidence=result.get("matched-at",result.get("url","Unknown")),
                recommendation=info.get("remediation","Review the finding and apply the recommended security fix")
                )
            findings.append(finding)
        return findings

if __name__ == "__main__":
    sample_results = [
        {
            "template-id": "test-template",
            "host": "http://127.0.0.1:8000",
            "matched-at": "http://127.0.0.1:8000",
            "info": {
                "name": "Test Finding",
                "severity": "medium",
                "description": "This is a test Nuclei finding.",
                "remediation": "Fix the security issue."
            }
        }
    ]

    converter = NucleiFindingConverter()
    findings = converter.convert(sample_results)

    for finding in findings:
        print(finding.to_dict())