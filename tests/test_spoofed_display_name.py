"""
TrustMail Test Suite: Spoofed Display-Name Indicators.
Tests detection of embedded deceptive email addresses and brand impersonation in display names.
"""

from trustmail.parser import parse_email_defensively
from trustmail.analyzer.threat import analyze_threats


def test_display_name_embedded_email_spoof():
    """Positive test: Display name embeds a legitimate email differing from the envelope/header sender."""
    raw = (
        b"From: \"CEO John <john.ceo@enterprise.com>\" <attacker@freemail-spoof.net>\r\n"
        b"To: target@enterprise.com\r\n"
        b"Subject: Quick Request\r\n\r\n"
        b"Are you at your desk right now?"
    )
    parsed = parse_email_defensively(raw)
    score, findings, review_required, reasons = analyze_threats(parsed)

    spoof_findings = [f for f in findings if f.id == "ALERT-THREAT-DISPLAY-EMAIL-SPOOF"]
    assert len(spoof_findings) == 1
    assert "john.ceo@enterprise.com" in spoof_findings[0].description
    assert review_required is True
    assert any("Display name embeds a deceptive email" in r for r in reasons)


def test_display_name_brand_impersonation():
    """Positive test: Display name asserts 'PayPal Security' from a generic webmail address."""
    raw = (
        b"From: \"PayPal Security Department\" <urgent-case-99@gmail.com>\r\n"
        b"To: customer@victim.com\r\n"
        b"Subject: Account Verification Required\r\n\r\n"
        b"Your account access has been restricted."
    )
    parsed = parse_email_defensively(raw)
    score, findings, review_required, reasons = analyze_threats(parsed)

    impersonation_findings = [f for f in findings if "IMPERSONATION" in f.id]
    assert len(impersonation_findings) >= 1
    assert review_required is True


def test_legitimate_display_name_not_flagged():
    """Negative test: Normal human name with matching domain does not trigger spoofing alerts."""
    raw = (
        b"From: \"Sarah Connor\" <sarah.connor@acme-corp.com>\r\n"
        b"To: team@acme-corp.com\r\n"
        b"Subject: Weekly Status Report\r\n\r\n"
        b"Here is the status report for this week."
    )
    parsed = parse_email_defensively(raw)
    score, findings, review_required, reasons = analyze_threats(parsed)

    spoof_findings = [f for f in findings if "SPOOF" in f.id or "IMPERSONATION" in f.id]
    assert len(spoof_findings) == 0
    assert review_required is False
