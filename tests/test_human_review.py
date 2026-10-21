"""
TrustMail Test Suite: Human-Review Escalation and Decision Support.
Verifies that potentially serious or ambiguous threats mandate human review,
and validates the human-in-the-loop review state machine.
"""

from trustmail.parser import parse_email_defensively
from trustmail.analyzer.evaluator import evaluate_email


def test_human_review_mandated_for_wire_transfer():
    """Confirms that financial redirection mandates human review."""
    raw = (
        b"From: \"Vendor Billing\" <billing@supplies-fast.com>\r\n"
        b"To: ap@mycompany.com\r\n"
        b"Subject: Updated Wire Transfer Instructions\r\n\r\n"
        b"Please change our bank routing number for all future wire transfer payments."
    )
    parsed = parse_email_defensively(raw)
    assessment = evaluate_email(parsed)

    assert assessment.human_review_required is True
    assert any("financial transaction indicator" in r.lower() for r in assessment.human_review_reasons)


def test_human_review_mandated_for_credential_phish():
    """Confirms that credential harvesting prompts mandate human review."""
    raw = (
        b"From: \"Admin\" <admin@domain.com>\r\n"
        b"To: user@domain.com\r\n"
        b"Subject: Password Reset\r\n\r\n"
        b"You must reset your password immediately."
    )
    parsed = parse_email_defensively(raw)
    assessment = evaluate_email(parsed)

    assert assessment.human_review_required is True
    assert any("credential" in r.lower() for r in assessment.human_review_reasons)


def test_review_status_lifecycle_api(client):
    """Tests the review state update endpoint via REST API."""
    raw_email = "From: test@domain.com\nSubject: Test\n\nPlease execute wire transfer immediately."
    post_res = client.post("/api/analyze", json={"raw_email": raw_email, "retain_evidence": False})
    assert post_res.status_code == 200
    incident_id = post_res.json()["incident_id"]

    # Initial state should be PENDING
    inc_res = client.get(f"/api/incidents/{incident_id}")
    assert inc_res.status_code == 200
    assert inc_res.json()["human_review_status"] == "PENDING"

    # Update to UNDER_REVIEW
    patch_res = client.patch(
        f"/api/incidents/{incident_id}/review",
        json={"status": "UNDER_REVIEW", "notes": "Analyst investigating vendor domain."},
    )
    assert patch_res.status_code == 200

    # Verify updated state and audit trail
    updated_inc = client.get(f"/api/incidents/{incident_id}").json()
    assert updated_inc["human_review_status"] == "UNDER_REVIEW"
    assert updated_inc["analyst_notes"] == "Analyst investigating vendor domain."
    assert any(a["event_type"] == "REVIEW_STATUS_UPDATED" for a in updated_inc["audit_events"])

    # Invalid status should return HTTP 400
    bad_res = client.patch(
        f"/api/incidents/{incident_id}/review",
        json={"status": "AUTONOMOUSLY_DISMISSED", "notes": "Invalid state"},
    )
    assert bad_res.status_code == 400
