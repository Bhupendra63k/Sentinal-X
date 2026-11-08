import json
import os
import threading
import logging
import tempfile
from datetime import datetime
from core.scan_comparator import ScanComparator

_HISTORY_LOCK=threading.Lock()
logger=logging.getLogger(__name__)
class ScanHistory:
    def __init__(self):
        self.history_dir="history"
        self.history_file=os.path.join(self.history_dir,"scan_history.json")
        os.makedirs(self.history_dir,exist_ok=True)

    def save_scan(self,result):
        with _HISTORY_LOCK:
            self._save_scan_locked(result)

    def _save_scan_locked(self,result):
        if not isinstance(result,dict):
            raise ValueError("Cannot save scan history: result must be a dictionary.")
        history=[]
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file,"r",encoding="utf-8") as f:
                    history=json.load(f)
            except json.JSONDecodeError:
                logger.error("Cannot save scan: history JSON is corrupted. "
                             "Original history file preserved.")
                raise ValueError(
                    "Cannot save scan because the history file is corrupted."
                )
            except OSError:
                logger.exception("Unable to read scan history for saving.")
                raise 
            if not isinstance(history,list):
                raise ValueError("Cannot save scan because the history structure is invalid.")
        scan_type=result.get("scan_type",result.get("friendly_scan_type","Unknown"),)
        target=result.get("target",result.get("Target","Unknown"))
        findings=result.get("findings",[])
        status=result.get("status")
        if result.get("scanner")=="credential_scanner":
            credential_result=None
            if result.get("scan_type")=="john":
                credential_result=result.get("john_result")
            elif result.get("scan_type")=="hashcat":
                credential_result=result.get("hashcat_result")
            if isinstance(credential_result,dict):
                nested_status=credential_result.get("status")
                normalized_status=(str(status).strip().upper() if status is not None else "")
                if normalized_status not in {"FAILED","ERROR"} and nested_status:
                    status=nested_status
        existing_ids=[record.get("id") for record in history if isinstance(record,dict) and isinstance(record.get("id"),int) and not isinstance(record.get("id"),bool)]
        history_entry={
            "id":max(existing_ids,default=0)+1,
            "scan_id":result.get("scan_id"),
            "timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scanner":result.get("scanner","Unknown"),
            "scan_type":scan_type,
            "target":target,
            "duration":result.get("duration","Unknown"),
            "findings":findings,
            "status":status,
            "error":result.get("error"),
        }
        history.append(history_entry)
        self.write_history_atomically(history)
            

    def get_history(self):
        if not os.path.exists(self.history_file):
            return []
        try:
            with open(self.history_file,"r",encoding="utf-8") as f:
                history=json.load(f)
        except (json.JSONDecodeError):
            logger.exception("Scan history contains invalid JSON;original file preserved.")
            return []
        except OSError:
            logger.exception("Unable to read scan history.")
            return []
        if not isinstance(history,list):
            return []
        return self._validate_history_records(history)

    def get_scan_by_uuid(self,scan_id):
        history=self.get_history()
        return next((scan for scan in history if scan.get("scan_id")==scan_id),None)

    def write_history_atomically(self,history):
        directory=os.path.dirname(os.path.abspath(self.history_file))
        temp_path=None
        try:
            with tempfile.NamedTemporaryFile(mode="w",encoding="utf-8",dir=directory,delete=False,suffix=".tmp",) as temp_file:
                temp_path=temp_file.name
                json.dump(history,temp_file,indent=4)
                temp_file.flush()
                os.fsync(temp_file.fileno())
            os.replace(temp_path,self.history_file)
        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
    def _validate_history_records(self,history):
        valid_records=[]
        for index,record in enumerate(history):
            if not isinstance(record,dict):
                logger.warning("Malformed scan-history record at index %s; "
                               "record preserved in the history file.",index,)
                continue
            valid_records.append(record)
        return valid_records
                
    def compare_scans(self,previous_id,current_id):
        history=self.get_history()
        previous_scan=next((scan for scan in history if scan.get("id")==previous_id),None)
        current_scan=next((scan for scan in history if scan.get("id")==current_id),None)
        if previous_scan is None:
            raise ValueError("Previous scan not found")
        if current_scan is None:
            raise ValueError("Current scan not found")
        comparison_fields=("scanner","scan_type","target")
        for field in comparison_fields:
            previous_value=previous_scan.get(field)
            current_value=current_scan.get(field)
            if (
                not isinstance(previous_value,str)
                or not previous_value.strip()
                or not isinstance(current_value,str)
                or not current_value.strip()
            ):
                raise ValueError(
                    f"Cannot compare scans: missing or invalid {field}."
                )
            if previous_value.strip().casefold()!=current_value.strip().casefold():
                raise ValueError(
                    f"Cannot compare scans with differet {field} values."
                )
        previous_findings=previous_scan.get("findings",[])
        current_findings=current_scan.get("findings",[])
        if not isinstance(previous_findings,list):
            raise ValueError(
                "Previous scan does not contain detailed findings. "
                "Run a new scan before comparing."
            )
        if not isinstance(current_findings,list):
            raise ValueError(
                "Current scan does not contain detailed findings. "
                "Run a new scan before comparing." 
            )
        if not all(isinstance(item,dict) for item in previous_findings):
            raise ValueError("Previous scan contains malformed findings and cannot be compared.")
        if not all(isinstance(item,dict) for item in current_findings):
            raise ValueError("Current scan contains malformed findings and cannot be compared.")
        
        comparator=ScanComparator()
        return comparator.compare(previous_findings,current_findings)
        