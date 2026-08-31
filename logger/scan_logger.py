from datetime import datetime

class ScanLogger:
    """Class to log scan results."""
    def log_scan(self,result):
        scanner=result.get("scanner","Unknown")
        scan_type=result.get("scan_type",result.get("friendly_scan_type","Unknown"))
        status=result.get("host_status","completed")
        target=result.get("target","Unknown")
        duration=result.get("duration","Unknown")

        with open("logs/sentinalx.log","a") as f:
            f.write("=" * 60 + "\n")
            f.write(f"Time      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scanner   : {scanner}\n")
            f.write(f"Scan Type : {scan_type}\n")
            f.write(f"Target    : {target}\n")
            f.write(f"Status    : {status}\n")
            f.write(f"Duration  : {duration} sec\n")
            f.write("=" * 60 + "\n\n")
            