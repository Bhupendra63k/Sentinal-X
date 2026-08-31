from urllib.parse import urlparse


class TargetNormalizer:
    def normalize(self, target):
        target = target.strip()
        if not target:
            raise ValueError("Target cannot be empty.")

        parsed_target = target
        if "://" not in parsed_target:
            parsed_target = "http://" + parsed_target

        parsed = urlparse(parsed_target)
        host = parsed.hostname
        if not host:
            raise ValueError("INVALID TARGET.")

        port = parsed.port
        if port:
            web_target = f"{parsed.scheme}://{host}:{port}"
        else:
            web_target = f"{parsed.scheme}://{host}"

        return {
            "original": target,
            "nmap_target": host,
            "web_target": web_target,
        }


if __name__ == "__main__":
    normalizer = TargetNormalizer()

    test_targets = [
        "127.0.0.1",
        "127.0.0.1:8000",
        "http://127.0.0.1:8000",
        "https://example.com",
        "example.com",
    ]

    for target in test_targets:
        result = normalizer.normalize(target)
        print(f"\nInput: {target}")
        print(f"Nmap : {result['nmap_target']}")
        print(f"Web  : {result['web_target']}")