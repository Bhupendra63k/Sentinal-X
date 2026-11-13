import re


class TcpdumpParser:
    """Parses text-formatted tcpdump output and identifies network exposure risks."""

    def parse(self, output: str, interface: str = "any") -> list:
        findings = []
        if not isinstance(output, (str, bytes)):
            return findings

        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")

        seen_keys = set()
        unencrypted_http = []
        dns_queries = []

        for line in output.splitlines():
            clean = line.strip()
            if not clean:
                continue

            # Detect unencrypted HTTP traffic (port 80)
            if ".80 >" in clean or (">" in clean and ".80:" in clean):
                unencrypted_http.append(clean)

            # Detect standard DNS queries
            if " A? " in clean or " AAAA? " in clean:
                match = re.search(r"A{1,4}\?\s+([^\s]+)", clean)
                if match:
                    dns_queries.append(match.group(1))

        # Check for Cleartext Web Traffic
        if unencrypted_http:
            finding_id = "NET-CLEARTEXT-HTTP"
            title = "Unencrypted HTTP Traffic Observed"
            description = (
                f"Observed {len(unencrypted_http)} unencrypted HTTP packet exchanges on interface '{interface}'. "
                "Plaintext transmission allows passive eavesdropping and tampering."
            )
            findings.append({
                "id": finding_id,
                "url": f"interface://{interface}",
                "title": title,
                "severity": "Medium",
                "description": description,
                "reference": "https://owasp.org/www-community/attacks/Man-in-the-middle_attack",
            })

        # Summary of Active DNS Exposure
        if dns_queries:
            unique_domains = list(dict.fromkeys(dns_queries))[:10]
            finding_id = "NET-DNS-PLAINTEXT"
            title = "Plaintext DNS Queries Captured"
            description = (
                f"Captured unencrypted DNS resolution requests for {len(dns_queries)} queries on '{interface}'. "
                f"Sample domains: {', '.join(unique_domains)}."
            )
            findings.append({
                "id": finding_id,
                "url": f"interface://{interface}",
                "title": title,
                "severity": "Info",
                "description": description,
                "reference": "https://tools.ietf.org/html/rfc8484",
            })

        return findings


if __name__ == "__main__":
    sample = "12:00:01.123 IP 192.168.1.10.54321 > 93.184.216.34.80: Flags [P.]"
    parser = TcpdumpParser()
    print(parser.parse(sample, "eth0"))