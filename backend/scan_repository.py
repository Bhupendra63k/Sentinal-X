import uuid
from typing import List,Optional
import uuid
from typing import List, Optional
from sqlalchemy.orm import Session
from backend.db import ScanRecord, ExecutionRecord, FindingRecord


class ScanRepository:

    @staticmethod
    def create_pipeline_scan(db: Session, target: str, pipeline_result: dict) -> ScanRecord:
        scan_id = str(uuid.uuid4())
        record = ScanRecord(
            id=scan_id,
            target=target,
            scan_type="pipeline",
            status=pipeline_result.get("status", "COMPLETED"),
            total_duration=pipeline_result.get("total_duration", 0.0),
        )
        db.add(record)

        # Record each scanner execution
        for exec_data in pipeline_result.get("execution_results", []):
            execution = ExecutionRecord(
                scan_id=scan_id,
                scanner_name=exec_data.get("scanner_name"),
                scan_type=exec_data.get("scan_type"),
                target=exec_data.get("target"),
                status=exec_data.get("status"),
                duration=exec_data.get("duration", 0.0),
                error=exec_data.get("error"),
            )
            db.add(execution)

        # Record all findings
        # Record all findings
        for f in pipeline_result.get("findings", []):
            scanner_name = f.get("scanner") or f.get("scanner_name") or "pipeline"
            raw_id = f.get("id") or f.get("finding_id") or f.get("title") or "GENERIC-FINDING"
            # Format clean fallback if ID is missing (e.g., NMAP-PORT-22 or NMAP-FINDING)
            clean_finding_id = str(raw_id).strip().replace(" ", "-").upper()

            finding = FindingRecord(
                scan_id=scan_id,
                scanner_name=scanner_name,
                finding_id=clean_finding_id,
                url=f.get("url"),
                title=f.get("title") or "Security Finding",
                severity=f.get("severity", "Info"),
                description=f.get("description"),
                reference=f.get("reference"),
            )
            db.add(finding)

        db.commit()
        db.refresh(record)
        return record

    @staticmethod
    def get_all_scans(db: Session, limit: int = 50) -> List[ScanRecord]:
        return db.query(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(limit).all()

    @staticmethod
    def get_scan_by_id(db: Session, scan_id: str) -> Optional[ScanRecord]:
        return db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()