import re


class Hping3Parser:
    """Parses hping3 output into metrics and exposure findings."""

    def parse(self, output: str, target: str) -> list:
        findings = []
        if not isinstance(output, (str, bytes)):
            return findings

        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")

        # Flexible regex for: "4 packets transmitted, 4 packets received, 0% packet loss"
        loss_match = re.search(
            r"(\d+)\s+packets\s+transmitted,\s+(\d+)\s+packets\s+received.*?(\d+)%\s+packet\s+loss",
            output,
            re.IGNORECASE | re.DOTALL,
        )

        # Flexible regex for RTT: "round-trip min/avg/max = 0.4/0.6/0.9 ms"
        rtt_match = re.search(
            r"round-trip\s+min/avg/max\s*=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)",
            output,
            re.IGNORECASE,
        )

        if loss_match:
            transmitted = int(loss_match.group(1))
            received = int(loss_match.group(2))
            loss_pct = int(loss_match.group(3))

            if loss_pct == 100:
                findings.append({
                    "id": "NET-HOST-UNREACHABLE",
                    "url": f"network://{target}",
                    "title": "Target Unresponsive or Filtered",
                    "severity": "Info",
                    "description": (
                        f"Target {target} dropped all {transmitted} probe packets (100% loss). "
                        "The host may be offline, non-routable, or filtered by a firewall."
                    ),
                    "reference": "https://en.wikipedia.org/wiki/Packet_loss",
                })
            elif loss_pct > 0:
                findings.append({
                    "id": "NET-PACKET-LOSS",
                    "url": f"network://{target}",
                    "title": "Intermittent Packet Loss Detected",
                    "severity": "Low",
                    "description": (
                        f"Detected {loss_pct}% packet loss ({received}/{transmitted} received) towards {target}."
                    ),
                    "reference": "https://en.wikipedia.org/wiki/Packet_loss",
                })
            else:
                avg_rtt = rtt_match.group(2) if rtt_match else "unknown"
                findings.append({
                    "id": "NET-HOST-REACHABLE",
                    "url": f"network://{target}",
                    "title": "Network Path Responsive",
                    "severity": "Info",
                    "description": (
                        f"Target {target} responded with 0% packet loss across {transmitted} probes. "
                        f"Average round-trip latency: {avg_rtt} ms."
                    ),
                    "reference": None,
                })
        else:
            # Fallback if raw text returned without standard statistics banner
            if "flags=" in output.lower() or "len=" in output.lower():
                findings.append({
                    "id": "NET-PROBE-RESPONSE",
                    "url": f"network://{target}",
                    "title": "Host Returned Probe Packets",
                    "severity": "Info",
                    "description": f"Host {target} returned live network packet responses.",
                    "reference": None,
                })

        return findings


if __name__ == "__main__":
    sample = """
HPING 127.0.0.1 (lo 127.0.0.1): icmp mode set, 28 headers + 0 data bytes
len=28 ip=127.0.0.1 ttl=64 id=123 icmp_seq=0 rtt=0.4 ms

--- 127.0.0.1 hping statistic ---
4 packets transmitted, 4 packets received, 0% packet loss
round-trip min/avg/max = 0.3/0.5/0.8 ms
"""
    parser = Hping3Parser()
    print(parser.parse(sample, "127.0.0.1"))