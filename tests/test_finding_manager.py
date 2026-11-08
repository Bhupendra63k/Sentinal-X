from core.finding import Finding
from core.finding_manager import FindingManager


manager = FindingManager()

findings = [
    Finding(
        scanner="Nuclei",
        target="http://127.0.0.1",
        finding_id="NUCLEI-001",
        title="Test Critical Finding",
        severity="Critical"
    ),

    Finding(
        scanner="Nikto",
        target="http://127.0.0.1",
        finding_id="NIKTO-001",
        title="Test Medium Finding",
        severity="Medium"
    ),

    Finding(
        scanner="Nmap",
        target="127.0.0.1",
        finding_id="NMAP-001",
        title="Test Info Finding",
        severity="Info"
    )
]

manager.add_findings(findings)

print("Total:", manager.count())

print("\nCritical Findings:")
for finding in manager.get_by_severity("Critical"):
    print(finding.to_dict())

print("\nSeverity Summary:")
print(manager.severity_summary())