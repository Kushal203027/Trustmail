"""
TrustMail: Database and Audit Logging Module.
Implements SQLite storage for incident metadata and audit events using parameterized queries.
"""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from trustmail.config import DATABASE_PATH


def get_db_connection() -> sqlite3.Connection:
    """Creates a connection to the SQLite database with row factory enabled."""
    conn = sqlite3.connect(str(DATABASE_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initializes SQLite schema for incidents and audit trail."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Incidents table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                evidence_hash TEXT NOT NULL,
                byte_size INTEGER NOT NULL,
                claimed_sender TEXT,
                subject TEXT,
                ial_level TEXT NOT NULL,
                mal_level TEXT NOT NULL,
                tsr_level TEXT NOT NULL,
                sti_level TEXT NOT NULL,
                human_review_required INTEGER NOT NULL,
                human_review_status TEXT NOT NULL,
                analyst_notes TEXT,
                assessment_json TEXT NOT NULL,
                evidence_retained INTEGER NOT NULL DEFAULT 0,
                evidence_path TEXT
            )
        """)

        # Audit events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT NOT NULL,
                FOREIGN KEY(incident_id) REFERENCES incidents(id)
            )
        """)

        # Index for evidence hash lookup
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_incidents_hash ON incidents(evidence_hash)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_incident ON audit_events(incident_id)
        """)
        conn.commit()


def log_audit_event(incident_id: str, event_type: str, details: Dict[str, Any]) -> str:
    """Logs an audit event with ISO8601 UTC timestamp and unique event ID."""
    event_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc).isoformat()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_events (id, incident_id, timestamp, event_type, details)
            VALUES (?, ?, ?, ?, ?)
            """,
            (event_id, incident_id, ts, event_type, json.dumps(details)),
        )
        conn.commit()
    return event_id


def save_incident(
    incident_id: str,
    evidence_hash: str,
    byte_size: int,
    claimed_sender: str,
    subject: str,
    ial_level: str,
    mal_level: str,
    tsr_level: str,
    sti_level: str,
    human_review_required: bool,
    human_review_status: str,
    assessment_dict: Dict[str, Any],
    evidence_retained: bool = False,
    evidence_path: Optional[str] = None,
) -> str:
    """Saves a new incident record and records initial audit events."""
    now_ts = datetime.now(timezone.utc).isoformat()
    assessment_json = json.dumps(assessment_dict)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO incidents (
                id, created_at, evidence_hash, byte_size, claimed_sender, subject,
                ial_level, mal_level, tsr_level, sti_level,
                human_review_required, human_review_status, analyst_notes,
                assessment_json, evidence_retained, evidence_path
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                now_ts,
                evidence_hash,
                byte_size,
                claimed_sender,
                subject,
                ial_level,
                mal_level,
                tsr_level,
                sti_level,
                1 if human_review_required else 0,
                human_review_status,
                "",
                assessment_json,
                1 if evidence_retained else 0,
                evidence_path,
            ),
        )
        conn.commit()

    # Log audit event for intake and assessment
    log_audit_event(
        incident_id=incident_id,
        event_type="INTAKE_ASSESSMENT_COMPLETED",
        details={
            "evidence_hash": evidence_hash,
            "byte_size": byte_size,
            "tsr_level": tsr_level,
            "human_review_required": human_review_required,
            "evidence_retained": evidence_retained,
        },
    )

    if evidence_retained:
        log_audit_event(
            incident_id=incident_id,
            event_type="EVIDENCE_BYTES_RETAINED",
            details={
                "storage_path": evidence_path,
                "retention_policy": "Explicit user consent; stored in local protected directory.",
            },
        )
    else:
        log_audit_event(
            incident_id=incident_id,
            event_type="EVIDENCE_BYTES_DISCARDED",
            details={
                "retention_policy": "Default privacy mode; raw byte content discarded immediately post-assessment.",
            },
        )

    return incident_id


def get_incident(incident_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves an incident by its ID, including parsed assessment and audit events."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        row = cursor.fetchone()
        if not row:
            return None

        incident = dict(row)
        incident["assessment"] = json.loads(incident["assessment_json"])
        # Ensure embedded assessment reflects current review state and notes
        incident["assessment"]["human_review_status"] = incident["human_review_status"]
        incident["assessment"]["analyst_notes"] = incident["analyst_notes"] or ""

        cursor.execute(
            "SELECT * FROM audit_events WHERE incident_id = ? ORDER BY timestamp ASC",
            (incident_id,),
        )
        incident["audit_events"] = [
            {
                "id": a["id"],
                "timestamp": a["timestamp"],
                "event_type": a["event_type"],
                "details": json.loads(a["details"]),
            }
            for a in cursor.fetchall()
        ]

        return incident


def list_incidents(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    """Lists recent incidents with pagination."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, created_at, evidence_hash, byte_size, claimed_sender, subject,
                   ial_level, mal_level, tsr_level, sti_level,
                   human_review_required, human_review_status, evidence_retained
            FROM incidents
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
        return [dict(row) for row in cursor.fetchall()]


def update_review_status(incident_id: str, new_status: str, analyst_notes: str) -> bool:
    """Updates the human review status and notes for an incident."""
    allowed_statuses = {"PENDING", "UNDER_REVIEW", "ESCALATED", "DISMISSED", "CONFIRMED_THREAT"}
    if new_status not in allowed_statuses:
        raise ValueError(f"Invalid status '{new_status}'. Must be one of {allowed_statuses}")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE incidents
            SET human_review_status = ?, analyst_notes = ?
            WHERE id = ?
            """,
            (new_status, analyst_notes, incident_id),
        )
        if cursor.rowcount == 0:
            return False
        conn.commit()

    log_audit_event(
        incident_id=incident_id,
        event_type="REVIEW_STATUS_UPDATED",
        details={
            "new_status": new_status,
            "analyst_notes": analyst_notes,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    return True
