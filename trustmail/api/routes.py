"""
TrustMail: REST API Endpoints.
Provides routes for intake, multi-dimensional assessment, incident management,
human-in-the-loop review triage, and evidence verification.
"""

import uuid
import logging
from typing import Any, Dict, Optional
from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, Field

from trustmail.config import MAX_INPUT_BYTES
from trustmail.parser import parse_email_defensively
from trustmail.analyzer.evaluator import evaluate_email
from trustmail.analyzer.models import AssessmentResult
from trustmail.storage import store_evidence, verify_stored_evidence_integrity
from trustmail.db import (
    save_incident,
    get_incident,
    list_incidents,
    update_review_status,
    log_audit_event,
)

router = APIRouter(prefix="/api", tags=["trustmail"])
logger = logging.getLogger(__name__)


async def read_limited_upload(file: UploadFile) -> bytes:
    """Read at most the configured limit plus one byte before rejecting."""
    chunks = []
    total = 0
    while total <= MAX_INPUT_BYTES:
        chunk = await file.read(min(64 * 1024, MAX_INPUT_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    if total > MAX_INPUT_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Uploaded file exceeds configured limit of {MAX_INPUT_BYTES} bytes (1 MB).",
        )
    return b"".join(chunks)


class AnalyzeTextRequest(BaseModel):
    raw_email: str = Field(..., description="Raw RFC 5322 email string")
    retain_evidence: bool = Field(False, description="Explicit opt-in to retain raw bytes on disk")


class ReviewUpdateRequest(BaseModel):
    status: str = Field(..., description="PENDING, UNDER_REVIEW, ESCALATED, DISMISSED, CONFIRMED_THREAT")
    notes: str = Field("", description="Analyst review rationale and notes")


@router.post("/analyze", response_model=AssessmentResult)
async def analyze_email_text(payload: AnalyzeTextRequest):
    """
    Intake endpoint for raw email text submissions.
    Enforces the 1 MB size limit, parses defensively, and returns the multi-dimensional assessment.
    """
    raw_bytes = payload.raw_email.encode("utf-8", errors="replace")
    if len(raw_bytes) > MAX_INPUT_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Message size ({len(raw_bytes)} bytes) exceeds configured limit of {MAX_INPUT_BYTES} bytes (1 MB).",
        )

    incident_id = str(uuid.uuid4())

    try:
        parsed = parse_email_defensively(raw_bytes)
        assessment = evaluate_email(parsed, incident_id=incident_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email input is invalid or exceeds supported limits.")
    except Exception:
        logger.error("Email analysis failed internally")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Email analysis failed due to an internal error.",
        )

    # Manage evidence retention
    evidence_path_str: Optional[str] = None
    if payload.retain_evidence:
        saved_path = store_evidence(raw_bytes, assessment.evidence_hash)
        evidence_path_str = str(saved_path)

    # Save to SQLite database
    save_incident(
        incident_id=incident_id,
        evidence_hash=assessment.evidence_hash,
        byte_size=assessment.byte_size,
        claimed_sender=assessment.claimed_identity.address or "Unknown",
        subject=parsed.subject or "(No Subject)",
        ial_level=assessment.identity_assurance.level,
        mal_level=assessment.message_authenticity.level,
        tsr_level=assessment.threat_assessment.level,
        sti_level=assessment.sender_trust.level,
        human_review_required=assessment.human_review_required,
        human_review_status=assessment.human_review_status,
        assessment_dict=assessment.model_dump(),
        evidence_retained=payload.retain_evidence,
        evidence_path=evidence_path_str,
    )

    return assessment


@router.post("/analyze-file", response_model=AssessmentResult)
async def analyze_email_file(
    file: UploadFile = File(...),
    retain_evidence: bool = Form(False),
):
    """
    Intake endpoint for uploaded .eml files.
    Enforces streaming size validation up to 1 MB.
    """
    raw_bytes = await read_limited_upload(file)

    incident_id = str(uuid.uuid4())

    try:
        parsed = parse_email_defensively(raw_bytes)
        assessment = evaluate_email(parsed, incident_id=incident_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email input is invalid or exceeds supported limits.")
    except Exception:
        logger.error("Uploaded email analysis failed internally")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Email analysis failed due to an internal error.",
        )

    evidence_path_str: Optional[str] = None
    if retain_evidence:
        saved_path = store_evidence(raw_bytes, assessment.evidence_hash)
        evidence_path_str = str(saved_path)

    save_incident(
        incident_id=incident_id,
        evidence_hash=assessment.evidence_hash,
        byte_size=assessment.byte_size,
        claimed_sender=assessment.claimed_identity.address or "Unknown",
        subject=parsed.subject or "(No Subject)",
        ial_level=assessment.identity_assurance.level,
        mal_level=assessment.message_authenticity.level,
        tsr_level=assessment.threat_assessment.level,
        sti_level=assessment.sender_trust.level,
        human_review_required=assessment.human_review_required,
        human_review_status=assessment.human_review_status,
        assessment_dict=assessment.model_dump(),
        evidence_retained=retain_evidence,
        evidence_path=evidence_path_str,
    )

    return assessment


@router.get("/incidents")
async def get_all_incidents(limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
    """Lists incidents with pagination."""
    return list_incidents(limit=limit, offset=offset)


@router.get("/incidents/{incident_id}")
async def get_single_incident(incident_id: str):
    """Retrieves full incident metadata, structured assessment, and audit trail."""
    record = get_incident(incident_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")
    return record


@router.patch("/incidents/{incident_id}/review")
async def update_incident_review(incident_id: str, payload: ReviewUpdateRequest):
    """Updates the human review status and analyst notes."""
    try:
        updated = update_review_status(incident_id, payload.status, payload.notes)
        if not updated:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")
        return {"status": "SUCCESS", "incident_id": incident_id, "new_status": payload.status}
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))


@router.post("/incidents/{incident_id}/verify-evidence")
async def verify_incident_evidence(incident_id: str):
    """
    Verifies cryptographic integrity of the retained original bytes.
    Demonstrates local tamper detection.
    """
    record = get_incident(incident_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")

    res = verify_stored_evidence_integrity(
        expected_hash=record["evidence_hash"],
        evidence_path_str=record.get("evidence_path"),
    )

    log_audit_event(
        incident_id=incident_id,
        event_type="EVIDENCE_INTEGRITY_VERIFICATION_ATTEMPT",
        details=res,
    )

    return res
