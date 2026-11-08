from core.finding import Finding


class HashFindingConverter:
    def convert(self, parsed_results, target):
        findings = []
        for result in parsed_results:
            finding = Finding(
                scanner="Credential Security Scanner",
                target=target,
                finding_id=f"Hash-{result['hash_type']}",
                title=f"Possible_{result['hash_type']} hash detected",
                severity="Info",
                description=(
                    f"The supplied hash matches the pattern "
                    f"of {result['hash_type']} hash "
                ),
                evidence=(
                    f"Hash Type: {result['hash_type']},"
                    f"Hashcat: {result['hashcat']},"
                    f"John: {result['john']},"
                ),
                recommendation=(
                    f"Verify the hash type and ensure that it is not a sensitive credential. "
                    f"If it is a sensitive credential, take appropriate action to secure it."
                )
            )
            findings.append(finding)
        return findings