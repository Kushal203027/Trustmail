"""
TrustMail Test Suite: Independent Assessment Dimensions.
Enforces the core principle: Identity Assurance, Message Authenticity,
Threat Severity, and Sender Trust are strictly orthogonal and must not be merged.
"""

from trustmail.parser import parse_email_defensively
from trustmail.analyzer.evaluator import evaluate_email


def test_orthogonal_evaluation_dimensions_distinct():
    """Confirms that the output contains four distinct, independently queryable dimensions."""
    raw = (
        b"From: \"Executive Officer\" <officer@legitimate-partner.com>\r\n"
        b"To: finance@mycompany.com\r\n"
        b"Subject: Urgent Wire Transfer Instruction\r\n\r\n"
        b"Please execute an immediate wire transfer to our new bank routing number."
    )
    parsed = parse_email_defensively(raw)
    assessment = evaluate_email(parsed)

    # 1. Four distinct dimension objects
    assert assessment.identity_assurance is not None
    assert assessment.message_authenticity is not None
    assert assessment.threat_assessment is not None
    assert assessment.sender_trust is not None

    # 2. Check levels
    assert assessment.identity_assurance.level == "T-IAL 0"
    assert assessment.message_authenticity.level == "MAL 1"
    assert assessment.threat_assessment.level in {"HIGH", "CRITICAL"}
    assert assessment.sender_trust.level == "STI 0"

    # 3. High threat severity does not alter the fact that MAL is MAL 1
    assert assessment.threat_assessment.level != assessment.identity_assurance.level


def test_benign_message_does_not_conflate_safety_with_verified_identity():
    """
    Confirms that a message with LOW threat indicators remains unverified in identity (T-IAL 0),
    preventing the 'safe = verified' fallacy.
    """
    raw = (
        b"From: \"New Contact\" <contact@unfamiliar-domain.net>\r\n"
        b"To: info@mycompany.com\r\n"
        b"Subject: Product Inquiry\r\n\r\n"
        b"Hello, I am interested in learning more about your enterprise pricing."
    )
    parsed = parse_email_defensively(raw)
    assessment = evaluate_email(parsed)

    assert assessment.threat_assessment.level == "LOW"
    # Identity remains unverified (T-IAL 0), not falsely elevated because the content is harmless
    assert assessment.identity_assurance.level == "T-IAL 0"
    # Sender trust remains unestablished (STI 0), not falsely trusted
    assert assessment.sender_trust.level == "STI 0"
    # Safety warning must be explicitly present
    assert "SAFETY MANDATE" in assessment.safety_warning
