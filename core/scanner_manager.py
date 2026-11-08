from scanners.reconnaissance.nmap.nmap_scanner import NmapScanner
import uuid

class ScannerManager:
    """Scanner Manager class to manage scanner operations"""
    def __init__(self):
        self.scanners={}
    
    def register_scanner(self,scanner):
        """Register scanners to the scanner manager"""
        self.scanners[scanner.name]=scanner
        #print(f"Scanner {scanner.name} registered to the scanner manager")
    
    def start_scan(self,scanner_name,scan_type,target,hash_file=None,mode=None,wordlist=None):
        """Start scan using registered scanner"""
        scanner=self.scanners.get(scanner_name)
        if scanner is None:
            raise ValueError(
                f"Scanner '{scanner_name} is not registered."
            )
            return
        try:
            if scanner_name=="credential_scanner":
                result=scanner.scan(scan_type,target,hash_file=hash_file,mode=mode,wordlist=wordlist)
            else:
                result=scanner.scan(scan_type,target)
        except Exception:
            raise
        if isinstance(result,dict):
            result.setdefault("scan_id",str(uuid.uuid4()))
        return result
    
