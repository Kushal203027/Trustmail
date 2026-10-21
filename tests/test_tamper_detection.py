"""
TrustMail Test Suite: Evidence Tamper Detection.
Verifies that modifying retained evidence bytes on disk triggers cryptographic tamper detection.
"""

from pathlib import Path
from trustmail.storage import (
    calculate_evidence_hash,
    store_evidence,
    verify_stored_evidence_integrity,
)


def test_tamper_detection_on_modified_evidence(tmp_path):
    """
    Simulates storing evidence, mutating one byte on disk, and validating
    that verify_stored_evidence_integrity reports TAMPER_DETECTED.
    """
    original_bytes = b"From: integrity@check.org\r\nSubject: Critical Data\r\n\r\nApproved: False"
    original_hash = calculate_evidence_hash(original_bytes)

    # Store evidence
    target_path = store_evidence(original_bytes, original_hash)
    assert target_path.exists()

    # Initial verification should pass
    initial_check = verify_stored_evidence_integrity(original_hash, str(target_path))
    assert initial_check["status"] == "VERIFIED"
    assert initial_check["matches"] is True

    # Tamper with the file on disk
    tampered_bytes = b"From: integrity@check.org\r\nSubject: Critical Data\r\n\r\nApproved: True!"
    target_path.write_bytes(tampered_bytes)

    # Re-verify -> Must detect tamper
    tamper_check = verify_stored_evidence_integrity(original_hash, str(target_path))
    assert tamper_check["status"] == "TAMPER_DETECTED"
    assert tamper_check["matches"] is False
    assert tamper_check["expected_hash"] == original_hash
    assert tamper_check["recomputed_hash"] != original_hash


def test_tamper_verification_when_not_retained():
    """Confirms that when evidence was not retained, verification reports NOT_RETAINED."""
    check = verify_stored_evidence_integrity("abcd" * 16, None)
    assert check["status"] == "NOT_RETAINED"
    assert check["matches"] is None
