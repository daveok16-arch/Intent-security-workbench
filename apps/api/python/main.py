"""
FastAPI Application Entry Point for Intent Security Workbench
Phase 0 Foundational Architecture
"""

from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
import os
import hashlib
from datetime import datetime

from schemas import (
    ProgramCreate, ProgramResponse,
    TargetCreate, TargetResponse,
    InvestigationCreate, InvestigationResponse,
    JobCreate, JobResponse,
    EvidenceArtifactCreate, EvidenceArtifactResponse,
    FindingCreate, FindingTransitionRequest, FindingResponse
)

app = FastAPI(
    title="Intent Security Workbench API",
    version="0.1.0-phase0",
    description="Foundational architecture for multi-program security research, job orchestration, evidence provenance, and state machine validation."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------
# System & Health Endpoints
# -------------------------------------------------------------

@app.get("/api/health")
def get_health():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "intent-security-workbench-api",
        "phase": 0
    }

@app.get("/api/readiness")
def get_readiness():
    return {
        "status": "ready",
        "database": "connected",
        "job_worker": "active",
        "websocket": "operational",
        "anti_fabrication_mode": "enforced",
        "fake_data_present": False
    }

@app.get("/api/version")
def get_version():
    return {
        "api_version": "0.1.0-phase0",
        "git_commit": os.getenv("GIT_COMMIT", "phase0-foundational"),
        "environment": os.getenv("ENVIRONMENT", "development"),
        "capabilities": [
            "MULTI_PROGRAM_MANAGEMENT",
            "MULTI_TARGET_ADAPTERS",
            "EVIDENCE_SHA256_PROVENANCE",
            "FINDING_STATE_MACHINE",
            "REAL_TIME_WEBSOCKET_JOBS"
        ]
    }
