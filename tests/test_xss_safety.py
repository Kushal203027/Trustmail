"""
TrustMail Test Suite: XSS and Hostile Content Isolation.
Verifies that malicious HTML, JavaScript tags, and payload injections
are treated strictly as inert text data and cannot trigger code execution.
"""

from trustmail.parser import parse_email_defensively
from trustmail.analyzer.evaluator import evaluate_email


def test_hostile_script_in_headers_and_body():
    """Confirms that <script> tags in headers and body are treated strictly as passive text."""
    hostile_email = (
        b"From: \"<script>alert('xss_from')</script>\" <test@domain.com>\r\n"
        b"To: target@domain.com\r\n"
        b"Subject: <img src=x onerror=alert('xss_subj')> Malicious Subject\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b"<html><body><script>document.cookie='stolen'</script><p>Normal text</p></body></html>"
    )

    parsed = parse_email_defensively(hostile_email)
    assessment = evaluate_email(parsed)

    # 1. Claimed display name retains the text representation without executing
    assert "<script>" in parsed.claimed_display_name
    assert "alert('xss_from')" in parsed.claimed_display_name

    # 2. Subject retains literal characters
    assert "<img src=x" in parsed.subject

    # 3. Assessment result model serializes cleanly into JSON without execution
    dumped_json = assessment.model_dump_json()
    assert "alert('xss_from')" in dumped_json

    # 4. Findings evidence fields are plain text strings
    for f in assessment.findings:
        assert isinstance(f.evidence, str)
        assert isinstance(f.description, str)


def test_api_safely_encodes_hostile_payload(client):
    """Verifies that API responses encode hostile characters in JSON without evaluation."""
    payload = "From: \"<svg/onload=alert(1)>\" <xss@test.com>\nSubject: Test\n\nBody content"
    response = client.post("/api/analyze", json={"raw_email": payload, "retain_evidence": False})
    assert response.status_code == 200
    data = response.json()
    assert data["claimed_identity"]["display_name"] == "<svg/onload=alert(1)>"
    assert data["claimed_identity"]["address"] == "xss@test.com"
