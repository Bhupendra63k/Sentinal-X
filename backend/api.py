import logging
import os
from pathlib import Path
import secrets
import uuid
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from backend.scanner_registry import get_scanner_metadata
from backend.scanner_target_validation import validate_scanner_target
from backend.schemas import CredentialScanRequest, FullScanRequest, ScanRequest
from core.scan_orchestrator import ScanOrchestrator
from core.scanner_manager import ScannerManager
from core.target_normalizer import TargetNormalizer
from history.scan_history import ScanHistory
from scanners.credential_security.credential_scanner import CredentialScanner
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
            detail="API authentication is not configured on server.",
        )
    if not api_key or not secrets.compare_digest(api_key, expected_key):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key.",
        )


def validate_credential_input_path(file_path: str | None, label: str) -> str | None:
    """Validates that a credential file resides safely within the allowed directory."""
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

# CORS configuration allowing local dev frontends
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

scanner_manager = ScannerManager()
scanner_manager.register_scanner(NmapScanner())
scanner_manager.register_scanner(NiktoScanner())
scanner_manager.register_scanner(NucleiScanner())
scanner_manager.register_scanner(CredentialScanner())

orchestrator = ScanOrchestrator(scanner_manager)
scan_history = ScanHistory()


# ---------------------------------------------------------
# Scanner Metadata Endpoints
# ---------------------------------------------------------
@app.get("/api/v1/scanners")
def get_scanners():
    return {"scanners": get_scanner_metadata()}


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

    scanner_metadata = get_scanner_metadata()
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
                "error": (
                    "Scanner returned no valid result. "
                    "Check whether the tool is installed and available."
                ),
            }
            scan_history.save_scan(failure_result)
            return failure_result

        result.setdefault("scanner", request.scanner)
        result.setdefault("scan_type", request.scan_type)
        result.setdefault("target", validated_target)
        scan_history.save_scan(dict(result))
        return result
    except Exception:
        logger.exception("Individual scan execution failed")
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while executing this scan.",
        )


@app.post("/api/v1/scans/full", dependencies=[Depends(require_api_key)])
def start_full_scan(request: FullScanRequest):
    try:
        targets = TargetNormalizer().normalize(request.target)
        nmap_target = validate_scanner_target("nmap", targets["nmap_target"])
        web_target = validate_scanner_target("nikto", targets["web_target"])
        validate_scanner_target("nuclei", web_target)
        validate_targets = {
            "nmap_target": nmap_target,
            "web_target": web_target,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        result = orchestrator.run_full_scan(
            request.target, validated_targets=validate_targets
        )
        for execution in result.get("execution_results", []):
            scanner_result = execution.get("result")
            if isinstance(scanner_result, dict):
                history_result = dict(scanner_result)
                history_result["scanner"] = execution.get(
                    "scanner_name", history_result.get("scanner", "Unknown")
                )
                history_result["scan_type"] = execution.get(
                    "scan_type", history_result.get("scan_type", "Unknown")
                )
                history_result["target"] = execution.get(
                    "target", history_result.get("target", request.target)
                )
                history_result["duration"] = execution.get(
                    "duration", history_result.get("duration", "Unknown")
                )
                history_result["status"] = execution.get(
                    "status", history_result.get("status", "Unknown")
                )
                history_result["error"] = execution.get(
                    "error", history_result.get("error")
                )
                scan_history.save_scan(history_result)
            else:
                scan_history.save_scan({
                    "scanner": execution.get("scanner_name", "Unknown"),
                    "scan_type": execution.get("scan_type", "Unknown"),
                    "target": execution.get("target", request.target),
                    "duration": execution.get("duration", "Unknown"),
                    "status": execution.get("status", "failed"),
                    "findings": [],
                    "error": execution.get("error"),
                })
        return {"target": request.target, "result": result}
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
        logger.info(
            "Credential scan completed: scan_id=%s scan_type=%s status=%s",
            result.get("scan_id"),
            request.scan_type,
            result.get("status"),
        )
        return {
            "scanner": "credential_scanner",
            "scan_type": request.scan_type,
            "target": request.target,
            "result": result,
        }
    except Exception:
        logger.exception(
            "Credential scan execution failed: scan_type=%s", request.scan_type
        )
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while executing credential scan.",
        )


# ---------------------------------------------------------
# Scan History Endpoints
# ---------------------------------------------------------
@app.get("/api/v1/history", dependencies=[Depends(require_api_key)])
def get_scan_history():
    try:
        history = scan_history.get_history()
        return {"history": history}
    except Exception:
        logger.exception("Failed to retrieve scan history")
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while retrieving scan history.",
        )


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


@app.get("/api/v1/history/{scan_id}", dependencies=[Depends(require_api_key)])
def get_scan_history_by_scan_id(scan_id: int):
    try:
        history = scan_history.get_history()
        scan = next((s for s in history if s.get("id") == scan_id), None)
        if scan is None:
            raise HTTPException(
                status_code=404, detail=f"Scan with ID {scan_id} not found."
            )
        return {"scan": scan}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to retrieve scan by ID")
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while retrieving the scan.",
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
