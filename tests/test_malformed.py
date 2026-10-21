"""
TrustMail Test Suite: Malformed Email Handling.
Verifies that the parser and analyzer handle malformed, conflicting, or hostile syntax safely.
"""

from trustmail.parser import parse_email_defensively
from trustmail.analyzer.evaluator import evaluate_email


def test_missing_from_header():
    """Validates behavior when an email completely lacks a From: header."""
    raw = b"To: recipient@example.com\r\nSubject: No Sender\r\n\r\nMessage body."
    parsed = parse_email_defensively(raw)
    assessment = evaluate_email(parsed)

    assert any("missing required 'from:'" in w.lower() for w in parsed.parser_warnings)
    # Identity finding should reflect unparseable sender
    assert any(f.id == "ALERT-ID-MISSING-FROM" for f in assessment.findings)


def test_multiple_from_headers_detected():
    """Validates that duplicate/conflicting From: headers (RFC 5322 violation) are flagged as Critical."""
    raw = (
        b"From: \"Real Admin\" <admin@company.com>\r\n"
        b"From: \"Attacker\" <attacker@evil.org>\r\n"
        b"To: victim@company.com\r\n"
        b"Subject: Dual From Attack\r\n\r\n"
        b"Testing multiple from header injection."
    )
    parsed = parse_email_defensively(raw)
    assessment = evaluate_email(parsed)

    assert len(parsed.from_headers) == 2
    assert any("contains 2 'from:' headers" in w.lower() for w in parsed.parser_warnings)
    # Must flag critical threat indicator for header injection
    assert any(f.id == "ALERT-THREAT-HEADER-INJECTION" for f in assessment.findings)
    assert assessment.threat_assessment.level == "CRITICAL"
    assert assessment.human_review_required is True


def test_missing_date_and_message_id():
    """Verifies that missing Date and Message-ID are flagged without crashing."""
    raw = b"From: user@example.com\r\nTo: other@example.com\r\nSubject: Test\r\n\r\nBody text."
    parsed = parse_email_defensively(raw)
    assert any("Message-ID" in w for w in parsed.parser_warnings)
    assert any("Date" in w for w in parsed.parser_warnings)


def test_binary_garbage_and_invalid_encoding():
    """Verifies that non-ASCII binary garbage is decoded without throwing uncaught exceptions."""
    raw = b"\xff\xfe\x00\x00Random binary garbage\x80\x90\xaa\xbb\xcc"
    parsed = parse_email_defensively(raw)
    assert parsed.byte_size == len(raw)
    assert len(parsed.raw_hash) == 64
    assessment = evaluate_email(parsed)
    assert assessment.incident_id is not None
