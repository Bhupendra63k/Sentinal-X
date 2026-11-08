import json


class NucleiParser:
    """Parses Nuclei JSONL output into the standardized SentinalX finding schema."""

    def parse(self, output: str, target: str = "") -> list:
        findings = []
        if not isinstance(output, str):
            return findings

        severity_map = {
            "info": "Info",
            "low": "Low",
            "medium": "Medium",
            "high": "High",
            "critical": "Critical",
        }

        seen_keys = set()

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line or not line.startswith("{"):
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = data.get("info", {})
            template_id = data.get("template-id") or data.get("template", "NUCLEI")
            
            # Target URL or matched endpoint
            matched_url = data.get("matched-at") or data.get("host") or target
            if matched_url and not matched_url.startswith(("http://", "https://")):
                matched_url = f"https://{matched_url}"

            # Standardize severity
            raw_severity = str(info.get("severity", "info")).lower()
            severity = severity_map.get(raw_severity, "Info")

            # Finding title
            title = info.get("name") or template_id.replace("-", " ").title()

            # Description and extracted details
            description = info.get("description", "").strip()
            extracted_results = data.get("extracted-results")
            if extracted_results and isinstance(extracted_results, list):
                extracted_str = ", ".join(str(r) for r in extracted_results)
                description = f"{description} (Matches: {extracted_str})".strip()

            if not description:
                description = title

            # Reference links
            reference = None
            refs = info.get("reference")
            if isinstance(refs, list) and refs:
                reference = refs[0]
            elif isinstance(refs, str):
                reference = refs

            # Deduplication key across template, URL, and title
            dedup_key = (template_id, matched_url, title)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            findings.append({
                "id": template_id,
                "url": matched_url,
                "title": title,
                "severity": severity,
                "description": description,
                "reference": reference,
            })

        return findings


if __name__ == "__main__":
    sample = (
        '{"template-id":"deprecated-tls","matched-at":"google.com:443",'
        '"info":{"name":"Deprecated TLS Detection","severity":"info",'
        '"description":"Both TLS 1.1 and SSLv3 are deprecated.",'
        '"reference":["https://ssl-config.mozilla.org/"]},'
        '"extracted-results":["tls11"]}'
    )
    parser = NucleiParser()
    result = parser.parse(sample, "https://google.com")
    print(json.dumps(result, indent=2))