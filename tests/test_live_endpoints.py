"""
TrustMail Test Suite: End-to-End API and Web Application Endpoints.
Verifies that all routes (frontend UI, static files, text intake, file intake,
incident log, incident details, human review lifecycle, and tamper verification) function correctly.
"""

from pathlib import Path


def test_frontend_and_static_assets_served(client):
    """Verifies that the dashboard HTML and required static assets are served with HTTP 200."""
    # Root dashboard
    res_root = client.get("/")
    assert res_root.status_code == 200
    assert "TrustMail" in res_root.text
    # Verify the product title and primary email-check workflow.
    assert "Email assessment" in res_root.text
    assert "Check an email" in res_root.text
    assert "Evidence-to-Claim Ledger" in res_root.text

    # CSS stylesheet
    res_css = client.get("/static/styles.css")
    assert res_css.status_code == 200
    assert "--accent: #315f9f" in res_css.text

    # JavaScript controller
    res_js = client.get("/static/app.js")
    assert res_js.status_code == 200
    assert "escapeHtml" in res_js.text


def test_complete_incident_lifecycle_and_endpoints(client, tmp_path):
    """
    Tests complete lifecycle:
    1. Ingestion via POST /api/analyze with explicit evidence retention
    2. Verification of subject field and orthogonal dimensions
    3. Retrieval via GET /api/incidents
    4. Retrieval via GET /api/incidents/{id}
    5. Review status transition via PATCH /api/incidents/{id}/review
    6. Retrieval confirming review state synced in embedded assessment
    7. Evidence integrity verification via POST /api/incidents/{id}/verify-evidence
    8. Physical tamper simulation on disk and detection
    """
    raw_email = (
        "From: \"Treasury Manager\" <treasury@partner-firm.org>\r\n"
        "To: accounts@mycompany.com\r\n"
        "Subject: Urgent: Change of Direct Deposit Account\r\n"
        "Date: Mon, 19 Oct 2026 09:00:00 +0000\r\n"
        "Message-ID: <wire.77192@partner-firm.org>\r\n"
        "\r\n"
        "Please update direct deposit routing details before the 5pm cutoff."
    )

    # 1. Intake with explicit retention
    res_post = client.post(
        "/api/analyze",
        json={"raw_email": raw_email, "retain_evidence": True},
    )
    assert res_post.status_code == 200
    assessment = res_post.json()

    incident_id = assessment["incident_id"]
    evidence_hash = assessment["evidence_hash"]

    # 2. Verify subject and dimensions
    assert assessment["subject"] == "Urgent: Change of Direct Deposit Account"
    assert assessment["identity_assurance"]["level"] == "T-IAL 0"
    assert assessment["message_authenticity"]["level"] == "MAL 1"
    assert assessment["threat_assessment"]["level"] in {"HIGH", "CRITICAL"}
    assert assessment["sender_trust"]["level"] == "STI 0"
    assert assessment["human_review_required"] is True

    # 3. List incidents
    res_list = client.get("/api/incidents")
    assert res_list.status_code == 200
    incidents = res_list.json()
    assert any(inc["id"] == incident_id for inc in incidents)

    # 4. Get single incident detail
    res_detail = client.get(f"/api/incidents/{incident_id}")
    assert res_detail.status_code == 200
    detail = res_detail.json()
    assert detail["id"] == incident_id
    assert detail["evidence_hash"] == evidence_hash
    assert detail["subject"] == "Urgent: Change of Direct Deposit Account"
    assert detail["human_review_status"] == "PENDING"
    assert detail["assessment"]["human_review_status"] == "PENDING"

    # 5. Update review status
    res_patch = client.patch(
        f"/api/incidents/{incident_id}/review",
        json={"status": "UNDER_REVIEW", "notes": "Checking with Treasury team out-of-band."},
    )
    assert res_patch.status_code == 200

    # 6. Re-check detail to ensure review state synced
    res_detail_updated = client.get(f"/api/incidents/{incident_id}")
    assert res_detail_updated.status_code == 200
    detail_updated = res_detail_updated.json()
    assert detail_updated["human_review_status"] == "UNDER_REVIEW"
    assert detail_updated["analyst_notes"] == "Checking with Treasury team out-of-band."
    # Confirms embedded assessment reflects live review status
    assert detail_updated["assessment"]["human_review_status"] == "UNDER_REVIEW"
    assert detail_updated["assessment"]["analyst_notes"] == "Checking with Treasury team out-of-band."

    # 7. Verify evidence integrity
    res_verify = client.post(f"/api/incidents/{incident_id}/verify-evidence")
    assert res_verify.status_code == 200
    verify_data = res_verify.json()
    assert verify_data["status"] == "VERIFIED"
    assert verify_data["matches"] is True

    # 8. Simulate on-disk file tampering
    evidence_path = Path(detail["evidence_path"])
    assert evidence_path.exists()
    original_bytes = evidence_path.read_bytes()
    import time
    for attempt in range(5):
        try:
            evidence_path.write_bytes(original_bytes + b"\x00TAMPER")
            break
        except PermissionError:
            time.sleep(0.1)

    res_tampered = client.post(f"/api/incidents/{incident_id}/verify-evidence")
    assert res_tampered.status_code == 200
    tampered_data = res_tampered.json()
    assert tampered_data["status"] == "TAMPER_DETECTED"
    assert tampered_data["matches"] is False


def test_file_upload_endpoint(client):
    """Verifies that .eml file upload works via /api/analyze-file."""
    eml_bytes = (
        b"From: \"Legal Team\" <legal@advisory.com>\r\n"
        b"To: client@firm.com\r\n"
        b"Subject: Contract Finalization\r\n"
        b"\r\n"
        b"The agreement is ready for signature."
    )
    response = client.post(
        "/api/analyze-file",
        files={"file": ("contract.eml", eml_bytes, "message/rfc822")},
        data={"retain_evidence": "false"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["subject"] == "Contract Finalization"
    assert data["claimed_identity"]["address"] == "legal@advisory.com"


def test_incident_not_found(client):
    """Verifies HTTP 404 handling for non-existent incident IDs."""
    fake_id = "00000000-0000-0000-0000-000000000000"
    res_get = client.get(f"/api/incidents/{fake_id}")
    assert res_get.status_code == 404

    res_patch = client.patch(
        f"/api/incidents/{fake_id}/review",
        json={"status": "UNDER_REVIEW", "notes": "Test"},
    )
    assert res_patch.status_code == 404

    res_verify = client.post(f"/api/incidents/{fake_id}/verify-evidence")
    assert res_verify.status_code == 404
