import ipaddress 
import re
from urllib.parse import urlsplit

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*\.?$"
)

def validate_target(value:str) -> str:
    value=value.strip()
    if not value:
        raise ValueError("Target cannot be empty.")
    if any(char.isspace() for char in value):
        raise ValueError("Target cannot contain whitespace")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    if HOSTNAME_PATTERN.fullmatch(value):
        return value
    try:
        parsed=urlsplit(value)
        if parsed.scheme not in {"http","https"} or not parsed.netloc:
            raise ValueError
        if parsed.username is not None or parsed.password is not None:
            raise ValueError
        hostname=parsed.hostname
        if not hostname:
            raise ValueError
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            if not HOSTNAME_PATTERN.fullmatch(hostname):
                raise ValueError

        _=parsed.port

        return value

    except ValueError:
        raise ValueError("Target must be a valid IP address,hostname,or HTTP/HTTPS URL") from None