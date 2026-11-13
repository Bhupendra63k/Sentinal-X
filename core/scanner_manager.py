from typing import Dict, Any, List


class ScannerManager:
    def __init__(self):
        self.scanners: Dict[str, Any] = {}

    def register_scanner(self, scanner_instance) -> None:
        self.scanners[scanner_instance.name] = scanner_instance

    def start_scan(self, scanner_name: str, scan_type: str, target: str, **kwargs) -> dict:
        if scanner_name not in self.scanners:
            raise ValueError(f"Scanner '{scanner_name}' is not registered.")
        return self.scanners[scanner_name].scan(scan_type, target, **kwargs)

    def get_all_metadata(self) -> List[dict]:
        # Default metadata mapping for legacy scanners that don't yet inherit BaseScanner
        legacy_defaults = {
            "hping3": ("network", "Active Layer 3/4 packet probing and reachability checks", "host", True, 10, "icmp_ping"),
            "tcpdump": ("network", "Passive network packet capture and traffic inspection", "host", False, 15, "quick_capture"),
            "nmap": ("reconnaissance", "Network discovery, open port scanning, and service enumeration", "host", True, 20, "quick"),
            "nikto": ("reconnaissance", "Web server misconfiguration and header security auditing", "web", True, 30, "basic"),
            "nuclei": ("reconnaissance", "Fast template-based CVE and vulnerability scanning", "web", True, 40, "default"),
            "credential_scanner": ("credential_security", "Hash identification and offline password auditing", "file", False, 90, "hash_identification"),
        }

        metadata = []
        for name, scanner in self.scanners.items():
            if hasattr(scanner, "get_metadata"):
                metadata.append(scanner.get_metadata())
            else:
                cat, desc, t_type, in_pipe, order, _ = legacy_defaults.get(
                    name, ("general", "", "host", False, 99, "")
                )
                metadata.append({
                    "name": name,
                    "category": getattr(scanner, "category", cat),
                    "description": getattr(scanner, "description", desc),
                    "target_type": getattr(scanner, "target_type", t_type),
                    "scan_types": list(getattr(scanner, "scan_commands", {}).keys()),
                    "include_in_pipeline": getattr(scanner, "include_in_pipeline", in_pipe),
                    "pipeline_order": getattr(scanner, "pipeline_order", order),
                })
        return metadata

    def get_pipeline_scanners(self) -> List[tuple]:
        """Returns sorted list of (scanner_instance, default_scan_type, target_type) for full scans."""
        legacy_pipeline = {
            "hping3": (10, "icmp_ping", "host"),
            "nmap": (20, "quick", "host"),
            "nikto": (30, "basic", "web"),
            "nuclei": (40, "default", "web"),
        }

        pipeline = []
        for name, scanner in self.scanners.items():
            if hasattr(scanner, "include_in_pipeline"):
                if scanner.include_in_pipeline:
                    scan_type = scanner.default_pipeline_scan or list(scanner.scan_commands.keys())[0]
                    pipeline.append((scanner.pipeline_order, scanner, scan_type, scanner.target_type))
            elif name in legacy_pipeline:
                order, scan_type, t_type = legacy_pipeline[name]
                pipeline.append((order, scanner, scan_type, t_type))

        pipeline.sort(key=lambda item: item[0])
        return [(item[1], item[2], item[3]) for item in pipeline]