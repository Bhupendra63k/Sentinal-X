from urllib.parse import urlparse
import re



class TargetNormalizer:
    def normalize(self, raw_target:str)->dict:
        target = raw_target.strip()
        if not target:
            raise ValueError("Target cannot be empty.")

        parsed_target = target
        if "://" not in parsed_target:
            parsed_target = "http://" + parsed_target

        parsed = urlparse(parsed_target)
        host = parsed.hostname
        if not host:
            raise ValueError("Invalid target:'{raw_target}'")
        clean_host = re.sub(r"[^a-zA-Z0-9.\-_]", "", host)
        
        port = parsed.port
        if port:
            web_target = f"{parsed.scheme}://{host}:{port}"
        else:
            web_target = f"{parsed.scheme}://{host}"

        return {
            "original": target,
            "host_target":clean_host,
            "nmap_target": host,
            "web_target": web_target,
        }


if __name__ == "__main__":
    normalizer = TargetNormalizer()

    test_targets = [
        "127.0.0.1",
        "127.0.0.1:8000",
        "http://127.0.0.1:8000/api/v1",
        "https://example.com/login?redirect=true",
        "example.com",
    ]

    for target in test_targets:
        result = normalizer.normalize(target)
        print(f"\nInput: {target}")
        print(f"Host : {result['host_target']}")
        print(f"Nmap : {result['nmap_target']}")
        print(f"Web  : {result['web_target']}")