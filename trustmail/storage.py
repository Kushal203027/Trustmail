"""
TrustMail: Evidence Storage and Integrity Verification.
Calculates SHA-256 hashes over exact raw input bytes and manages optional explicit retention.
"""

import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from trustmail.config import EVIDENCE_DIR


def calculate_evidence_hash(raw_bytes: bytes) -> str:
    """
    Computes a cryptographic SHA-256 digest over the exact original bytes.
    Note: A cryptographic hash alone does NOT constitute a complete chain of custody;
    it serves strictly as a mathematical integrity check at the time of intake.
    """
    return hashlib.sha256(raw_bytes).hexdigest()


def store_evidence(raw_bytes: bytes, evidence_hash: str) -> Path:
    """
    Persists raw original bytes to the protected evidence directory.
    Invoked ONLY when the user explicitly enables evidence retention.
    """
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    target_path = EVIDENCE_DIR / f"{evidence_hash}.eml"
    target_path.write_bytes(raw_bytes)
    return target_path


def read_retained_evidence(evidence_path_str: str) -> Optional[bytes]:
    """Reads retained evidence bytes if the file exists on disk."""
    path = Path(evidence_path_str)
    if path.exists() and path.is_file():
        return path.read_bytes()
    return None


def verify_stored_evidence_integrity(expected_hash: str, evidence_path_str: Optional[str]) -> Dict[str, Any]:
    """
    Recomputes SHA-256 over the retained raw bytes and validates against the recorded hash.
    Demonstrates tamper detection.
    """
    if not evidence_path_str:
        return {
            "status": "NOT_RETAINED",
            "matches": None,
            "message": "Raw message bytes were not retained (default privacy policy). Integrity verified only at intake.",
        }

    evidence_bytes = read_retained_evidence(evidence_path_str)
    if evidence_bytes is None:
        return {
            "status": "FILE_MISSING",
            "matches": False,
            "message": "Retained evidence file could not be found on disk.",
        }

    recomputed_hash = calculate_evidence_hash(evidence_bytes)
    if recomputed_hash == expected_hash:
        return {
            "status": "VERIFIED",
            "matches": True,
            "expected_hash": expected_hash,
            "recomputed_hash": recomputed_hash,
            "message": "Cryptographic integrity verified: on-disk byte sequence matches the intake SHA-256 digest.",
        }
    else:
        return {
            "status": "TAMPER_DETECTED",
            "matches": False,
            "expected_hash": expected_hash,
            "recomputed_hash": recomputed_hash,
            "message": "INTEGRITY VIOLATION DETECTED: on-disk bytes have been altered or corrupted since intake.",
        }
