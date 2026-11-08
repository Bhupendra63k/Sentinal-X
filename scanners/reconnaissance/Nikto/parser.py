import re
from datetime import datetime


class NiktoParser:
    def parse(self, output: str, target: str) -> dict:
        result = {
            "scanner": "nikto",
            "target": target,
            "ip_address": None,
            "port": None,
            "server": None,
            "start_time": None,
            "end_time": None,
            "duration": None,
            "server_notes": [],
            "raw_findings": []
        }

        if not isinstance(output, str):
            return result

        drop_phrases = (
            "nikto v",
            "target hostname:",
            "platform:",
            "no cgi directories found",
            "scan terminated:",
            "failed to check for updates",
            "0 host(s) tested",
            "1 host(s) tested"
        )

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line or not line.startswith("+"):
                continue

            clean = line.lstrip("+").strip()
            clean_lower = clean.lower()

            if any(phrase in clean_lower for phrase in drop_phrases):
                continue

            # Server & target metadata
            if clean_lower.startswith("target ip:"):
                result["ip_address"] = clean.split(":", 1)[1].strip()
            elif clean_lower.startswith("target port:"):
                result["port"] = clean.split(":", 1)[1].strip()
            elif clean_lower.startswith("server:"):
                result["server"] = clean.split(":", 1)[1].strip()
            elif clean_lower.startswith("start time:"):
                result["start_time"] = clean.split(":", 1)[1].strip().split(" (")[0]
            elif clean_lower.startswith("end time:"):
                result["end_time"] = clean.split(":", 1)[1].strip().split(" (")[0]
            
            # Non-vulnerability system notes
            elif any(k in clean_lower for k in ("ssl info:", "multiple ips found:", "server banner changed")):
                clean_note = re.sub(r"^\[\d+\]\s*(?:[^\s:]+:\s*)?", "", clean)
                if clean_note not in result["server_notes"]:
                    result["server_notes"].append(clean_note)

            # Security Findings
            else:
                item_id = "INFO"
                remainder = clean

                # 1. Extract bracketed ID if present (e.g. "[013587] ...")
                id_match = re.match(r"^\[(\d+)\]\s*(.*)$", clean)
                if id_match:
                    item_id = id_match.group(1)
                    remainder = id_match.group(2).strip()

                # 2. Extract path / URL if present before the first colon
                url = "/"
                message = remainder
                if ":" in remainder:
                    prefix, rest = remainder.split(":", 1)
                    prefix = prefix.strip()
                    # Check if prefix looks like a path or full URL
                    if prefix.startswith(("/", "http://", "https://")):
                        url = prefix
                        message = rest.strip()

                # 3. Separate reference link cleanly
                reference = None
                if ". See: " in message:
                    msg_part, ref_part = message.split(". See: ", 1)
                    message = msg_part.strip()
                    reference = ref_part.strip()

                result["raw_findings"].append({
                    "id": item_id,
                    "url": url,
                    "message": message,
                    "reference": reference
                })

        if result["start_time"] and result["end_time"]:
            try:
                t1 = datetime.strptime(result["start_time"], "%Y-%m-%d %H:%M:%S")
                t2 = datetime.strptime(result["end_time"], "%Y-%m-%d %H:%M:%S")
                result["duration"] = round((t2 - t1).total_seconds(), 2)
            except Exception:
                result["duration"] = None

        return result