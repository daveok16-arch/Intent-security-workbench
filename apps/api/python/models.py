"""
SQLAlchemy Domain Models for Intent Security Workbench
Phase 0 Foundational Architecture
"""

from datetime import datetime
import enum
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, Integer, JSON, Enum as SQLEnum
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class FindingStatusEnum(str, enum.Enum):
    CANDIDATE = "CANDIDATE"
    ANALYZING = "ANALYZING"
    VERIFICATION_REQUIRED = "VERIFICATION_REQUIRED"
    TESTING = "TESTING"
    REPRODUCED = "REPRODUCED"
    VALIDATED = "VALIDATED"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"

class JobStatusEnum(str, enum.Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

class InvestigationStatusEnum(str, enum.Enum):
    CREATED = "CREATED"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    ARCHIVED = "ARCHIVED"

class SourceAcquisitionStatusEnum(str, enum.Enum):
    SOURCE_NOT_ACQUIRED = "SOURCE_NOT_ACQUIRED"
    SOURCE_ACQUIRED = "SOURCE_ACQUIRED"
    SOURCE_ACQUISITION_FAILED = "SOURCE_ACQUISITION_FAILED"

class Program(Base):
    __tablename__ = "programs"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    platform = Column(String(64), nullable=False)
    external_identifier = Column(String(255), nullable=True)
    scope = Column(JSON, default=list)
    exclusions = Column(JSON, default=list)
    bounty_policy = Column(Text, nullable=True)
    disclosure_policy = Column(Text, nullable=True)
    technology = Column(JSON, default=list)
    metadata_json = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    targets = relationship("Target", back_populates="program", cascade="all, delete-orphan")
    investigations = relationship("Investigation", back_populates="program", cascade="all, delete-orphan")

class Target(Base):
    __tablename__ = "targets"

    id = Column(String(64), primary_key=True, index=True)
    program_id = Column(String(64), ForeignKey("programs.id"), nullable=False)
    name = Column(String(255), nullable=False)
    target_type = Column(String(64), nullable=False)
    ecosystem = Column(String(64), nullable=False)
    repository_url = Column(String(512), nullable=True)
    commit_hash = Column(String(64), nullable=True)
    source_hash = Column(String(64), nullable=True)
    source_acquisition_status = Column(SQLEnum(SourceAcquisitionStatusEnum), default=SourceAcquisitionStatusEnum.SOURCE_NOT_ACQUIRED)
    deployment_information = Column(JSON, default=dict)
    metadata_json = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    program = relationship("Program", back_populates="targets")
    investigations = relationship("Investigation", back_populates="target")

class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(String(64), primary_key=True, index=True)
    program_id = Column(String(64), ForeignKey("programs.id"), nullable=False)
    target_id = Column(String(64), ForeignKey("targets.id"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(SQLEnum(InvestigationStatusEnum), default=InvestigationStatusEnum.CREATED)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    program = relationship("Program", back_populates="investigations")
    target = relationship("Target", back_populates="investigations")
    jobs = relationship("AnalysisJob", back_populates="investigation", cascade="all, delete-orphan")
    evidence_artifacts = relationship("EvidenceArtifact", back_populates="investigation", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="investigation", cascade="all, delete-orphan")

class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.id"), nullable=False)
    target_id = Column(String(64), ForeignKey("targets.id"), nullable=True)
    engine = Column(String(128), nullable=False)
    operation = Column(String(128), nullable=False)
    status = Column(SQLEnum(JobStatusEnum), default=JobStatusEnum.QUEUED)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    exit_code = Column(Integer, nullable=True)
    stdout_artifact_id = Column(String(64), nullable=True)
    stderr_artifact_id = Column(String(64), nullable=True)
    error = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=2)
    metadata_json = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    investigation = relationship("Investigation", back_populates="jobs")

class EvidenceArtifact(Base):
    __tablename__ = "evidence_artifacts"

    id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.id"), nullable=False)
    target_id = Column(String(64), ForeignKey("targets.id"), nullable=True)
    artifact_type = Column(String(64), nullable=False)
    producer = Column(String(128), nullable=False)
    producer_version = Column(String(64), nullable=False)
    command = Column(Text, nullable=False)
    target_hash = Column(String(64), nullable=True)
    sha256 = Column(String(64), nullable=False)
    byte_size = Column(Integer, nullable=False)
    path_or_reference = Column(String(512), nullable=False)
    content_preview = Column(Text, nullable=True)
    metadata_json = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)

    investigation = relationship("Investigation", back_populates="evidence_artifacts")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.id"), nullable=False)
    target_id = Column(String(64), ForeignKey("targets.id"), nullable=False)
    title = Column(String(255), nullable=False)
    category = Column(String(128), nullable=False)
    severity = Column(String(32), nullable=False)
    status = Column(SQLEnum(FindingStatusEnum), default=FindingStatusEnum.CANDIDATE)
    confidence = Column(String(32), default="UNVERIFIED")
    evidence_artifact_ids = Column(JSON, default=list)
    reproduction_steps = Column(Text, nullable=True)
    mitigation_notes = Column(Text, nullable=True)
    state_history = Column(JSON, default=list)
    metadata_json = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    investigation = relationship("Investigation", back_populates="findings")
