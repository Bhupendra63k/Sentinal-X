from backend.target_validation import validate_target
from urllib.parse import urlsplit

def validate_scanner_target(scanner:str,target:str) ->str:
    target=validate_target(target)
    if scanner=="nmap":
        if "://" in target:
            raise ValueError("Nmap requires an IP address or hostname, not a URL")
        return target

    if scanner in {"nikto","nuclei"}:
        if "://" not in target:
            target=f"https://{target}"
        parsed=urlsplit(target)
        if parsed.scheme not in {"http","https"} or not parsed.hostname:
            raise ValueError(
                "Web scanners requires a valid HTTP or HTTPS target"
            )
        return target
    raise ValueError(f"UNsupported scanner: {scanner}")