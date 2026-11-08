import re


class NiktoFindingConverter:
    def _classify_finding(self, message: str):
        msg_lower = message.lower()

        if any(term in msg_lower for term in ("command injection", "remote code execution", "sql injection")):
            return "High", "Critical Injection / RCE"

        if any(term in msg_lower for term in ("directory indexing", "directory listing")):
            return "Medium", "Directory Indexing Enabled"

        if any(term in msg_lower for term in ("backup file", "sensitive file", ".git", ".env")):
            return "Medium", "Sensitive File Exposed"

        if "suggested security header missing" in msg_lower:
            match = re.search(r"missing:\s*([a-zA-Z0-9\-]+)", message, re.IGNORECASE)
            header_name = match.group(1) if match else "Security Header"
            return "Low", f"Missing Header: {header_name}"

        if "cookie" in msg_lower:
            if "httponly" in msg_lower:
                return "Low", "Cookie Missing HttpOnly Flag"
            if "secure" in msg_lower:
                return "Low", "Cookie Missing Secure Flag"
            return "Low", "Insecure Cookie Configuration"

        if "alt-svc" in msg_lower or "link header" in msg_lower:
            return "Info", "HTTP Header Configuration Notice"

        return "Info", "Web Configuration Notice"

    def convert(self, raw_findings: list) -> list:
        structured_findings = []
        seen = set()

        for item in raw_findings:
            severity, title = self._classify_finding(item["message"])
            
            # Deduplicate strictly on exact message so distinct headers with the same ID aren't lost
            dedup_key = (item["id"], item["url"], item["message"])
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            entry = {
                "id": item["id"],
                "url": item["url"],
                "title": title,
                "severity": severity,
                "description": item["message"]
            }
            if item.get("reference"):
                entry["reference"] = item["reference"]

            structured_findings.append(entry)

        return structured_findings