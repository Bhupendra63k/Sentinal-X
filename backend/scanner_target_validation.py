from backend.target_validation import validate_target
from urllib.parse import urlsplit
import ipaddress
import re

def validate_scanner_target(scanner:str,target:str) ->str:
    target=validate_target(target)
    cleaned=target.strip()
    if not cleaned:
        raise ValueError("Target cannot be empty.")
    if scanner in {"hping3","enum4linux"}:
        cleaned = re.sub(r"^https?://", "", cleaned).split("/")[0].split(":")[0]
        try:
            ipaddress.ip_address(cleaned)
            return cleaned
        except ValueError:
            domain_regex = r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
            if re.match(domain_regex,cleaned):
                return cleaned
            raise ValueError(f"Invalid host or IP target for hping3: '{target}'")
        
    if scanner == "tcpdump":
        # Allow standard interface names (e.g., eth0, wlan0, enp0s3, lo, any)
        if not re.match(r"^[a-zA-Z0-9_\-\.]{1,16}$", cleaned):
            raise ValueError(f"Invalid network interface name: '{cleaned}'")
        return cleaned
    if scanner=="nmap":
        if "://" in target:
            raise ValueError("Nmap requires an IP address or hostname, not a URL")
        return target

    if scanner == "setoolkit":
        # Supports domains/IPs (spoof audit, harvester check) as well as full URLs (QR payload)
        if "://" in cleaned:
            parsed = urlsplit(cleaned)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("Invalid URL target for setoolkit")
            return cleaned
        host_only = cleaned.split("/")[0].split(":")[0]
        try:
            ipaddress.ip_address(host_only)
            return host_only
        except ValueError:
            domain_regex = r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
            if re.match(domain_regex, host_only):
                return host_only
            raise ValueError(f"Invalid host, domain, or URL target for setoolkit: '{target}'")

    if scanner in {"nikto","nuclei","whatweb"}:
        if "://" not in target:
            target=f"https://{target}"
        parsed=urlsplit(target)
        if parsed.scheme not in {"http","https"} or not parsed.hostname:
            raise ValueError(
                "Web scanners requires a valid HTTP or HTTPS target"
            )
        return target
    raise ValueError(f"UNsupported scanner: {scanner}")