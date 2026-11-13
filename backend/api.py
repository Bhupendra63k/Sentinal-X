import logging
import os
from pathlib import Path
import secrets
import uuid
from uuid import UUID
from scanners.reconnaissance.whatweb.whatweb_scanner import WhatwebScanner
from scanners.enumeration.enum4linux.enum4linux_scanner import Enum4linuxScanner
from scanners.social_engineering.setoolkit.set_scanner import SetoolkitScanner

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from backend.db import get_db, init_db
from backend.scan_repository import ScanRepository
from backend.scanner_registry import get_scanner_metadata
from backend.scanner_target_validation import validate_scanner_target
from backend.schemas import CredentialScanRequest, FullScanRequest, ScanRequest
from core.scan_orchestrator import ScanOrchestrator
from core.scanner_manager import ScannerManager
from core.target_normalizer import TargetNormalizer
from history.scan_history import ScanHistory
from scanners.credential_security.credential_scanner import CredentialScanner
from scanners.network.hping3.hping3_scanner import Hping3Scanner
from scanners.network.tcpdump.tcpdump_scanner import TcpdumpScanner
from scanners.reconnaissance.Nikto.nikto_scanner import NiktoScanner
from scanners.reconnaissance.nmap.nmap_scanner import NmapScanner
from scanners.reconnaissance.nuclei.nuclei_scanner import NucleiScanner

# ---------------------------------------------------------
# Logging & Configuration
# ---------------------------------------------------------
logger = logging.getLogger(__name__)

CREDENTIAL_INPUT_DIR = (
    Path(__file__).resolve().parents[1] / "data" / "credential_inputs"
)


# ---------------------------------------------------------
# Security & Dependencies
# ---------------------------------------------------------
def require_api_key(
    api_key: str | None = Header(default=None, alias="X-API-KEY"),
) -> None:
    expected_key = os.getenv("SENTINALX_API_KEY")
    if not expected_key:
        raise HTTPException(
            status_code=503,
            detail="API authentication is not configured.",
        )
    if not api_key or not secrets.compare_digest(api_key, expected_key):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key.",
        )


def validate_credential_input_path(file_path: str | None, label: str) -> str | None:
    if file_path is None:
        return None

    CREDENTIAL_INPUT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        resolved_path = Path(file_path).resolve()
        allowed_directory = CREDENTIAL_INPUT_DIR.resolve()

        if not resolved_path.is_relative_to(allowed_directory):
            raise HTTPException(
                status_code=400,
                detail=f"{label} must be inside the credential input directory.",
            )
        return str(resolved_path)
    except (OSError, ValueError, RuntimeError):
        raise HTTPException(status_code=400, detail=f"Invalid {label} path.")


# ---------------------------------------------------------
# App Initialization & Registry Setup
# ---------------------------------------------------------
app = FastAPI(
    title="SentinalX API",
    version="1.0.0",
    description="API for the SentinalX Modular Security Scanning Framework",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    init_db()

scanner_manager = ScannerManager()
scanner_manager.register_scanner(NmapScanner())
scanner_manager.register_scanner(NiktoScanner())
scanner_manager.register_scanner(NucleiScanner())
scanner_manager.register_scanner(CredentialScanner())
scanner_manager.register_scanner(TcpdumpScanner())
scanner_manager.register_scanner(Hping3Scanner())
scanner_manager.register_scanner(WhatwebScanner())
scanner_manager.register_scanner(Enum4linuxScanner())
scanner_manager.register_scanner(SetoolkitScanner())

orchestrator = ScanOrchestrator(scanner_manager)
scan_history = ScanHistory()


# ---------------------------------------------------------
# Scanner Metadata Endpoints
# ---------------------------------------------------------
@app.get("/api/v1/scanners")
def get_scanners():
    return {"scanners": scanner_manager.get_all_metadata()}


# ---------------------------------------------------------
# Scan Execution Endpoints
# ---------------------------------------------------------
@app.post("/api/v1/scans", dependencies=[Depends(require_api_key)])
def start_scan(request: ScanRequest):
    if request.scanner not in scanner_manager.scanners:
        raise HTTPException(
            status_code=404, detail=f"Scanner '{request.scanner}' not found"
        )
    if request.scanner == "credential_scanner":
        raise HTTPException(
            status_code=400,
            detail="Use /api/v1/credential-scans for credential scanning.",
        )

    scanner_metadata = scanner_manager.get_all_metadata()
    scanner_info = next(
        (s for s in scanner_metadata if s["name"] == request.scanner), None
    )

    if scanner_info is None or request.scan_type not in scanner_info["scan_types"]:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scan type '{request.scan_type}' for scanner '{request.scanner}'",
        )

    try:
        validated_target = validate_scanner_target(request.scanner, request.target)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        result = scanner_manager.start_scan(
            request.scanner, request.scan_type, validated_target
        )
        if not isinstance(result, dict):
            failure_result = {
                "scan_id": str(uuid.uuid4()),
                "scanner": request.scanner,
                "scan_type": request.scan_type,
                "target": validated_target,
                "status": "FAILED",
                "findings": [],
                "error": "Scanner returned no valid result.",
            }
            scan_history.save_scan(failure_result)
            return {
                "scanner": request.scanner,
                "scan_type": request.scan_type,
                "target": request.target,
                "result": failure_result,
            }

        history_result = dict(result)
        history_result.setdefault("scanner", request.scanner)
        history_result.setdefault("scan_type", request.scan_type)
        history_result.setdefault("target", validated_target)
        scan_history.save_scan(history_result)

        return {
            "scanner": request.scanner,
            "scan_type": request.scan_type,
            "target": request.target,
            "result": result,
        }
    except Exception:
        logger.exception("Individual scan execution failed")
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while executing this scan.",
        )


@app.post("/api/v1/scans/full", dependencies=[Depends(require_api_key)])
def start_full_scan(request: FullScanRequest, db: Session = Depends(get_db)):
    try:
        targets = TargetNormalizer().normalize(request.target)
        host_target = validate_scanner_target("hping3", targets.get("host_target") or targets.get("nmap_target"))
        nmap_target = validate_scanner_target("nmap", targets.get("nmap_target") or targets.get("host_target"))
        web_target = validate_scanner_target("nikto", targets.get("web_target"))
        validate_scanner_target("nuclei", web_target)

        validated_targets = {
            "host_target": host_target,
            "nmap_target": nmap_target,
            "web_target": web_target,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        result = orchestrator.run_full_scan(
            request.target, validated_targets=validated_targets
        )

        # 1. Save execution results to legacy flat-file history
        for execution in result.get("execution_results", []):
            scanner_result = execution.get("result")
            if isinstance(scanner_result, dict):
                history_result = dict(scanner_result)
                history_result["scanner"] = execution.get("scanner_name", "Unknown")
                history_result["scan_type"] = execution.get("scan_type", "Unknown")
                history_result["target"] = execution.get("target", request.target)
                history_result["duration"] = execution.get("duration", 0.0)
                history_result["status"] = execution.get("status", "Unknown")
                history_result["error"] = execution.get("error")
                scan_history.save_scan(history_result)

        # 2. Persist relational record to SQLite
        db_record = ScanRepository.create_pipeline_scan(db, request.target, result)

        return {
            "scan_id": db_record.id,
            "target": request.target,
            "result": result,
        }
    except Exception:
        logger.exception("Full scan execution failed")
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while executing the full scan.",
        )


@app.post("/api/v1/credential-scans", dependencies=[Depends(require_api_key)])
def start_credential_scan(request: CredentialScanRequest):
    valid_scan_types = {"hash_identification", "hashcat", "john"}
    if request.scan_type not in valid_scan_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid credential scan type: {request.scan_type}",
        )

    if request.scan_type == "hashcat":
        if not request.hash_file or not request.wordlist or request.mode is None:
            raise HTTPException(
                status_code=400,
                detail="Hashcat requires hash_file, mode, and wordlist.",
            )

    if request.scan_type == "john":
        if not request.hash_file or not request.wordlist:
            raise HTTPException(
                status_code=400, detail="John requires hash_file and wordlist."
            )

    hash_file = None
    wordlist = None
    if request.scan_type in {"hashcat", "john"}:
        hash_file = validate_credential_input_path(request.hash_file, "Hash file")
        wordlist = validate_credential_input_path(request.wordlist, "wordlist")

    try:
        result = orchestrator.run_credential_scan(
            scan_type=request.scan_type,
            target=request.target,
            hash_file=hash_file,
            wordlist=wordlist,
            mode=request.mode,
        )
        if not isinstance(result, dict):
            result = {
                "scanner": "credential_scanner",
                "scan_type": request.scan_type,
                "target": request.target,
                "status": "FAILED",
                "findings": [],
                "error": "Credential scanner returned no valid result.",
            }
        scan_history.save_scan(result)
        return {
            "scanner": "credential_scanner",
            "scan_type": request.scan_type,
            "target": request.target,
            "result": result,
        }
    except Exception:
        logger.exception("Credential scan execution failed")
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while executing credential scan.",
        )


# ---------------------------------------------------------
# Scan History & Database Query Endpoints
# ---------------------------------------------------------
@app.get("/api/v1/history", dependencies=[Depends(require_api_key)])
def get_scan_history(db: Session = Depends(get_db)):
    scans = ScanRepository.get_all_scans(db)
    return [
        {
            "id": s.id,
            "target": s.target,
            "scan_type": s.scan_type,
            "status": s.status,
            "duration": s.total_duration,
            "created_at": s.created_at.isoformat(),
            "findings_count": len(s.findings),
        }
        for s in scans
    ]


@app.get("/api/v1/history/db/{scan_id}", dependencies=[Depends(require_api_key)])
def get_db_scan_details(scan_id: str, db: Session = Depends(get_db)):
    scan = ScanRepository.get_scan_by_id(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found in database.")

    return {
        "id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "total_duration": scan.total_duration,
        "created_at": scan.created_at.isoformat(),
        "executions": [
            {
                "scanner": e.scanner_name,
                "type": e.scan_type,
                "status": e.status,
                "duration": e.duration,
                "error": e.error,
            }
            for e in scan.executions
        ],
        "findings": [
            {
                "id": f.finding_id,
                "scanner": f.scanner_name,
                "title": f.title,
                "severity": f.severity,
                "url": f.url,
                "description": f.description,
                "reference": f.reference,
            }
            for f in scan.findings
        ],
    }


@app.get("/api/v1/history/compare", dependencies=[Depends(require_api_key)])
def compare_scan_history(previous_id: int, current_id: int):
    try:
        comparison = scan_history.compare_scans(previous_id, current_id)
        return {
            "previous_id": previous_id,
            "current_id": current_id,
            "comparison": comparison,
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception:
        logger.exception("Scan history comparison failed")
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while comparing scans.",
        )


@app.get("/api/v1/history/uuid/{scan_id}", dependencies=[Depends(require_api_key)])
def get_scan_history_by_uuid(scan_id: str):
    try:
        validated_uuid = str(UUID(scan_id))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan UUID format.")

    scan = scan_history.get_scan_by_uuid(validated_uuid)
    if scan is None:
        raise HTTPException(
            status_code=404, detail=f"Scan with UUID {scan_id} not found."
        )
    return {"scan": scan}