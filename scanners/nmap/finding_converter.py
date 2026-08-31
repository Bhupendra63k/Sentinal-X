from core.finding import Finding
from core.severity_normalizer import SeverityNormalizer

class NmapFindingConverter:
    def convert(self,result):
        findings=[]
        target=result.get("target","Unknown")
        normalizer=SeverityNormalizer()
        for index,port in enumerate(result.get("ports",[]),start=1):
            finding=Finding(
                scanner="Nmap",
                target=target,
                finding_id=f"NMAP-{index}",
                title="Open Port Detected",
                severity=normalizer.normalize("Info"),
                description=(f"port {port.get('port','Unknown')}/"
                            f"{port.get('service','Unknown')} is open."),
                evidence=(f"State:{port.get('state','Unknown')},"
                        f"service :{port.get('service','Unknown')}"),
                recommendation="Verify that this service is required and restrict access if it is not necessary"
                )         
            findings.append(finding)
        return findings