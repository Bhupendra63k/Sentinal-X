from scanners.nmap.nmap_scanner import NmapScanner

class ScannerManager:
    """Scanner Manager class to manage scanner operations"""
    def __init__(self):
        self.scanners={}
    
    def register_scanner(self,scanner):
        """Register scanners to the scanner manager"""
        self.scanners[scanner.name]=scanner
        #print(f"Scanner {scanner.name} registered to the scanner manager")
    
    def start_scan(self,scanner_name,scan_type,target):
        """Start scan using registered scanner"""
        scanner=self.scanners.get(scanner_name)
        if scanner is None:
            print(f"scanner {scanner_name} not found")
            return 
        return scanner.scan(scan_type,target)
    
