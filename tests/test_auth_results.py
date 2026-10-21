"""
TrustMail Test Suite: Untrusted Authentication-Results Headers.
Verifies that in-band Authentication-Results headers are treated as unverified claims,
not as verified facts or proof of real-world identity.
"""

from trustmail.parser import parse_email_defensively
from trustmail.analyzer.identity import analyze_identity
from trustmail.analyzer.models import FindingCategory


def test_auth_results_treated_as_unverified_claim():
    """Confirms that in-band Authentication-Results headers are categorized as UNVERIFIED_CLAIM."""
    raw = (
        b"From: \"Billing Service\" <billing@external-corp.com>\r\n"
        b"To: client@mycorp.com\r\n"
        b"Subject: Monthly Statement\r\n"
        b"Authentication-Results: relay.example.com; dkim=pass header.i=@external-corp.com; spf=pass\r\n\r\n"
        b"Your statement is ready."
    )
    parsed = parse_email_defensively(raw)
    score, findings, claimed_id = analyze_identity(parsed)

    auth_findings = [f for f in findings if "AUTH-RESULTS" in f.id]
    assert len(auth_findings) == 1
    # Must be UNVERIFIED_CLAIM
    assert auth_findings[0].category == FindingCategory.UNVERIFIED_CLAIM
    assert "CRITICAL SECURITY LIMITATION" in auth_findings[0].limitations
    # Identity level must not be inflated to verified without local cryptographic validation
    assert score.level == "T-IAL 0"
    assert score.is_simulated_or_limited is True


def test_missing_auth_results_produces_unknown_finding():
    """Negative test: When no Authentication-Results header exists, system documents this as UNKNOWN_INFORMATION."""
    raw = (
        b"From: \"Alice\" <alice@domain.org>\r\n"
        b"To: \"Bob\" <bob@domain.org>\r\n"
        b"Subject: Hello\r\n\r\n"
        b"Just saying hello."
    )
    parsed = parse_email_defensively(raw)
    score, findings, claimed_id = analyze_identity(parsed)

    unknown_findings = [f for f in findings if f.id == "UNKNOWN-ID-AUTH-RESULTS"]
    assert len(unknown_findings) == 1
    assert unknown_findings[0].category == FindingCategory.UNKNOWN_INFORMATION
