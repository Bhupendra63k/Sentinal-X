import datetime
from sqlalchemy import create_engine, Column, String, Integer, Float, Text, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DATABASE_URL = "sqlite:///./sentinalx.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ScanRecord(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, index=True)
    target = Column(String, index=True, nullable=False)
    scan_type = Column(String, nullable=False)  # "single" or "pipeline"
    status = Column(String, default="PENDING")
    total_duration = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    executions = relationship("ExecutionRecord", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("FindingRecord", back_populates="scan", cascade="all, delete-orphan")


class ExecutionRecord(Base):
    __tablename__ = "scanner_executions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    scanner_name = Column(String, nullable=False)
    scan_type = Column(String, nullable=False)
    target = Column(String, nullable=False)
    status = Column(String, nullable=False)
    duration = Column(Float, default=0.0)
    error = Column(Text, nullable=True)

    scan = relationship("ScanRecord", back_populates="executions")


class FindingRecord(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    scanner_name = Column(String, nullable=False)
    finding_id = Column(String, index=True, nullable=True)  # Set to nullable=True
    url = Column(String, nullable=True)
    title = Column(String, nullable=False)
    severity = Column(String, index=True, nullable=False)
    description = Column(Text, nullable=True)
    reference = Column(Text, nullable=True)

    scan = relationship("ScanRecord", back_populates="findings")

def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()