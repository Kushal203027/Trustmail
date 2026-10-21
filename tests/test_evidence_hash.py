"""
TrustMail Test Suite: Evidence Hash Consistency.
Validates SHA-256 calculation over exact original bytes and hash reproducibility.
"""

import hashlib
from trustmail.storage import calculate_evidence_hash
from trustmail.parser import parse_email_defensively


def test_hash_consistency_over_identical_bytes():
    """Confirms that identical raw inputs consistently yield the identical SHA-256 digest."""
    data = b"From: test@domain.com\r\nSubject: Consistent\r\n\r\nMessage payload."

    hash_1 = calculate_evidence_hash(data)
    hash_2 = calculate_evidence_hash(data)
    expected = hashlib.sha256(data).hexdigest()

    assert hash_1 == hash_2 == expected

    parsed_1 = parse_email_defensively(data)
    parsed_2 = parse_email_defensively(data)

    assert parsed_1.raw_hash == parsed_2.raw_hash == expected


def test_hash_sensitivity_to_single_byte_mutation():
    """Confirms that a single-bit or single-byte modification changes the evidence digest completely."""
    original = b"From: user@domain.com\r\nSubject: Invoice #100\r\n\r\nAmount: $1000"
    tampered = b"From: user@domain.com\r\nSubject: Invoice #100\r\n\r\nAmount: $9000"

    hash_orig = calculate_evidence_hash(original)
    hash_tamp = calculate_evidence_hash(tampered)

    assert hash_orig != hash_tamp
