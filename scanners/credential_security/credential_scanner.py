import logging
from pathlib import Path
import pwd
import time
import uuid
import re
from datetime import datetime,timezone
from .finding_converter import HashFindingConverter
from .identifier import HashIdentifier
from .parser import HashParser
from .hashcat.hashcat_parser import HashcatParser
from .hashcat.hashcat_runner import HashcatRunner
from .john.john_parser import JohnParser
from .john.john_runner import JohnRunner

MAX_HASH_FILE_SIZE = 10 * 1024 * 1024
MAX_WORDLIST_SIZE = 2 * 1024 * 1024 * 1024
logger=logging.getLogger(__name__)

class CredentialScanner:
    def __init__(self):
        self.name = "credential_scanner"
        self.identifier = HashIdentifier
        self.parser = HashParser()
        self.converter = HashFindingConverter()
        self.hashcat_runner = HashcatRunner()
        self.hashcat_parser = HashcatParser()
        self.john_parser = JohnParser()
        self.john_runner = JohnRunner()

    def _validate_input_files(self, hash_file, wordlist):
        file_limits = (("Hash file", hash_file, MAX_HASH_FILE_SIZE),("Wordlist", wordlist, MAX_WORDLIST_SIZE),)

        for label, file_path, _ in file_limits:
            if not file_path:
                return f"{label} is required."
        try:
            if Path(hash_file).resolve() == Path(wordlist).resolve():
                return "Hash file and wordlist must be different files."
        except (OSError, ValueError):
            return "Invalid input file path."

        for label, file_path, max_size in file_limits:
            path = Path(file_path)

            if not path.is_file():
                return f"{label} does not exist or is not a file."

            try:
                with path.open("rb") as file:
                    file.read(1)

                if path.stat().st_size > max_size:
                    limit_mb = max_size / (1024 * 1024)
                    return (
                        f"{label} exceeds the maximum size "
                        f"of {limit_mb:g} MB."
                    )

            except (OSError, ValueError):
                return f"{label} cannot be read."

        return None

    def _format_lines(self,text):
        if not isinstance(text, str):
            return []
        return [line.strip() for line in text.splitlines() if line.strip()]

    def _john_all_hashes_cracked(self,show_stdout):
        if not isinstance(show_stdout, str):
            return False
        summary=re.search(r"(\d+)\s+password hashes? cracked,\s*(\d+)\s+left",show_stdout,re.IGNORECASE)
        if not summary:
            return False
        cracked_count = int(summary.group(1))
        remaining_count = int(summary.group(2))
        return cracked_count > 0 and remaining_count == 0
    

    def scan(self, scan_type, target, hash_file=None, mode=None, wordlist=None):
        scan_timestamp = datetime.now(timezone.utc).isoformat()
        scan_id = str(uuid.uuid4())
        valid_scan_types = {
            "hash_identification",
            "hashcat",
            "john",
        }

        if scan_type not in valid_scan_types:
            return {
                "scanner": self.name,
                "scan_type": scan_type,
                "target": target,
                "status": "FAILED",
                "findings": [],
                "hashcat_result": None,
                "john_result": None,
                "duration": "Unknown",
                "scan_id": scan_id,
                "timestamp": scan_timestamp,
                "error": f"Unsupported scan type: {scan_type}",
            }

        findings = []
        hashcat_result = None
        john_result = None
        scan_status = "COMPLETED"
        duration = "Unknown"
        scan_error = None

        if scan_type in {"hashcat", "john"}:
            validation_error = self._validate_input_files(
                hash_file,
                wordlist,
            )

            if validation_error:
                error_result = {
                    "tool": scan_type,
                    "return_code": -1,
                    "cracked": False,
                    "password": None,
                    "stdout": "",
                    "stderr": validation_error,
                    "status": "FAILED",
                }

                return {
                    "scanner": self.name,
                    "scan_type": scan_type,
                    "target": target,
                    "status": "FAILED",
                    "findings": [],
                    "hashcat_result": (
                        error_result if scan_type == "hashcat" else None
                    ),
                    "john_result": (
                        error_result if scan_type == "john" else None
                    ),
                    "duration": "Unknown",
                    "scan_id": scan_id,
                    "timestamp": scan_timestamp,
                    "error": validation_error,
                }

        try:
            if scan_type == "hash_identification":
                start_time = time.time()
                identifier = self.identifier(target)
                hashes = identifier.identify()
                parsed_results = self.parser.parse(hashes)
                findings = self.converter.convert(parsed_results, target)
                duration = round(time.time() - start_time, 2)
            elif scan_type == "hashcat":
                start_time = time.time()
                raw_result = self.hashcat_runner.run(hash_file, mode, wordlist)
                duration = round(time.time() - start_time, 2)
                hashcat_result = self.hashcat_parser.parse(raw_result)
                hashcat_result["duration"] = duration
                if hashcat_result.get("return_code", -1) != 0:
                    hashcat_result["status"] = "FAILED"
                    scan_status = "FAILED"
                elif hashcat_result.get("cracked"):
                    hashcat_result["status"] = "CRACKED"
                else:
                    hashcat_result["status"] = "NOT CRACKED"
            elif scan_type == "john":
                start_time = time.time()
                already_cracked=False
                precheck_result=None
                try:
                    precheck_result=self.john_runner.show_cracked(hash_file)
                    if (isinstance(precheck_result,dict) and precheck_result.get("return_code",-1)==0 and self._john_all_hashes_cracked(precheck_result.get("stdout",""))):
                        already_cracked=True
                except Exception as ex:
                    logger.warning("potfile precheck failed with exception,falling back to standard run: %s",ex)
                    already_cracked=False
                if already_cracked and isinstance (precheck_result,dict):
                    raw_result={
                        "tool":"john",
                        "return_code":0,
                        "stdout":"",
                        "stderr":precheck_result.get("stderr",""),
                        "show_stdout":precheck_result.get("stdout",""),
                        "hash_file":precheck_result.get("hash_file",hash_file)
                    }
                else:
                    raw_result = self.john_runner.run(hash_file, wordlist)
                    if raw_result.get("return_code",-1)==0:
                        try:
                            show_result=self.john_runner.show_cracked(hash_file)
                            if show_result.get("return_code",-1)==0:
                               raw_result["show_stdout"]=show_result.get("stdout","")
                               raw_result["hash_file"]=show_result.get("hash_file",hash_file)
                            else:
                                logger.warning(
                                "John completed, but retrieving cracked "
                                "results failed: %s",
                                show_result.get("stderr","Unknown error"),
                            )
                        except Exception:
                            logger.exception(
                        "John completed, but retrieving cracked "
                        "results failed."
                    )
                duration=round(time.time() - start_time, 2)
                parsed_john=self.john_parser.parse(raw_result)
                if raw_result.get("return_code", -1) != 0:
                    status_str = "FAILED"
                    scan_status = "FAILED"
                elif already_cracked:
                    status_str="ALREADY CRACKED"
                elif parsed_john.get("cracked"):
                    status_str="CRACKED"
                else:
                    status_str="NOT CRACKED"
                all_cracked=parsed_john.get("cracked_passwords",[])
                findings=[]
                if all_cracked:
                    findings.append({
                        "severity":"HIGH",
                        "title":"Weak Credential Recovered",
                        "description":f"{len(all_cracked)} weak credential(s) were recovered from the hash file.",
                        "total_cracked":len(all_cracked),

                    })
                total=parsed_john.get("total_hashes",0)
                cracked=parsed_john.get("cracked_count",0)
                rate_str=f"{(cracked/total*100):.1f}%" if total>0 else "0.0%"
                scan_summary={
                    "status":status_str,
                    "total_hashes":total,
                    "cracked_hashes":cracked,
                    "remaining_hashes": parsed_john.get("remaining_count",0),
                    "success_rate":rate_str,
                }
                john_result={
                    "hash_file":parsed_john.get("hash_file"),
                }
                scan_diagnostic={
                    "stdout":self._format_lines(raw_result.get("stdout","")),
                    "show_stdout":self._format_lines(raw_result.get("show_stdout","")),
                    "stderr":self._format_lines(raw_result.get("stderr","")),
                }
                recovered_passwords=all_cracked

        except Exception:
            logger.exception("Credential scan failed unexpectedly.")
            scan_status = "FAILED"
            scan_error = "Credential scan failed unexpectedly."
            if "start_time" in locals():
                duration = round(time.time() - start_time, 2)
            error_result = {
                "tool": scan_type,
                "return_code": -1,
                "cracked": False,
                "password": None,
                "stdout": "",
                "stderr": scan_error,
                "status": "FAILED",
            }
            if scan_type == "hashcat":
                error_result["duration"] = duration
                hashcat_result = error_result
            elif scan_type == "john":
                error_result["duration"] = duration
                john_result = error_result

        return {
            "scan_id": scan_id,
            "scanner": scan_type,
            "status": scan_status,
            "duration": duration,
            "timestamp": scan_timestamp,
            "summary": scan_summary if "scan_summary" in locals() else None,
            "cracked_passwords": recovered_passwords if "recovered_passwords" in locals() else [],
            "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in findings],
            "hashcat_result": hashcat_result,
            "john_result": john_result,
            "diagnostic": scan_diagnostic if "scan_diagnostic" in locals() else None,
            "error": scan_error,
        }

    def show_john_cracked(self, hash_file):
        result = self.john_runner.show_cracked(hash_file)
        return self.john_parser.parse(result)
