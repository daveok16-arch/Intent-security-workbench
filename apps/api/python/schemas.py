"""
Pydantic Schemas for Intent Security Workbench
Phase 0 Foundational Architecture
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class ProgramBase(BaseModel):
    name: str
    platform: str
    external_identifier: Optional[str] = None
    scope: List[str] = []
    exclusions: List[str] = []
    bounty_policy: Optional[str] = None
    disclosure_policy: Optional[str] = None
    technology: List[str] = []
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ProgramCreate(ProgramBase):
    pass

class ProgramResponse(ProgramBase):
    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class TargetBase(BaseModel):
    program_id: str
    name: str
    target_type: str
    ecosystem: str
    repository_url: Optional[str] = None
    commit_hash: Optional[str] = None
    source_hash: Optional[str] = None
    source_acquisition_status: str = "SOURCE_NOT_ACQUIRED"
    deployment_information: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class TargetCreate(TargetBase):
    pass

class TargetResponse(TargetBase):
    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class InvestigationBase(BaseModel):
    program_id: str
    target_id: str
    title: str
    description: Optional[str] = None
    status: str = "CREATED"

class InvestigationCreate(InvestigationBase):
    pass

class InvestigationResponse(InvestigationBase):
    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class JobCreate(BaseModel):
    investigation_id: str
    target_id: str
    engine: str
    operation: str
    max_retries: int = 2
    metadata: Dict[str, Any] = Field(default_factory=dict)

class JobResponse(BaseModel):
    id: str
    investigation_id: str
    target_id: Optional[str]
    engine: str
    operation: str
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    exit_code: Optional[int]
    stdout_artifact_id: Optional[str]
    stderr_artifact_id: Optional[str]
    error: Optional[str]
    retry_count: int
    max_retries: int
    metadata: Dict[str, Any]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class EvidenceArtifactCreate(BaseModel):
    investigation_id: str
    target_id: Optional[str] = None
    artifact_type: str
    producer: str
    producer_version: str
    command: str
    target_hash: Optional[str] = None
    content: str
    path_or_reference: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

class EvidenceArtifactResponse(BaseModel):
    id: str
    investigation_id: str
    target_id: Optional[str]
    artifact_type: str
    producer: str
    producer_version: str
    command: str
    target_hash: Optional[str]
    sha256: str
    byte_size: int
    path_or_reference: str
    content_preview: Optional[str]
    metadata: Dict[str, Any]
    created_at: datetime

    class Config:
        from_attributes = True

class FindingCreate(BaseModel):
    investigation_id: str
    target_id: str
    title: str
    category: str
    severity: str
    confidence: str = "UNVERIFIED"
    evidence_artifact_ids: List[str] = []
    reproduction_steps: Optional[str] = None
    mitigation_notes: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class FindingTransitionRequest(BaseModel):
    target_status: str
    reason: str
    actor: str = "security-researcher"

class FindingResponse(BaseModel):
    id: str
    investigation_id: str
    target_id: str
    title: str
    category: str
    severity: str
    status: str
    confidence: str
    evidence_artifact_ids: List[str]
    reproduction_steps: Optional[str]
    mitigation_notes: Optional[str]
    state_history: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
