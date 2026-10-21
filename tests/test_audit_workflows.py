"""
TrustMail: End-to-End Audit Verification Suite.
Directly tests the 7 required demo workflows:
1. Synthetic suspicious email (BEC / wire fraud)
2. Synthetic legitimate email (Benign communication)
3. Upload of valid .eml message file
4. Malformed and oversized input safety
5. Incident history listing and detailed record retrieval
6. Human-review status lifecycle and persistence
7. Evidence integrity verification (Valid, Tampered, and Discarded)
"""

from pathlib import Path


def test_workflow_1_suspicious_email(client):
    """Workflow 1: Analyze synthetic suspicious email with display spoofing and financial urgency."""
    raw_suspicious = (
        "From: \"CEO John Doe <john@acme.com>\" <attacker@scam-mail.org>\r\n"
        "To: accounts@acme.com\r\n"
        "Reply-To: external-fraud@gmail.com\r\n"
        "Subject: Urgent: Executive Wire Transfer Authorization\r\n"
        "Date: Mon, 19 Oct 2026 09:30:00 +0000\r\n"
        "Message-ID: <bec.test.01@scam-mail.org>\r\n"
        "\r\n"
        "Please update direct deposit banking details and execute an immediate wire transfer within 24 hours."
    )
    res = client.post("/api/analyze", json={"raw_email": raw_suspicious, "retain_evidence": False})
    assert res.status_code == 200
    data = res.json()

    # Verify 4 orthogonal dimensions
    assert data["identity_assurance"]["level"] == "T-IAL 0"
    assert data["message_authenticity"]["level"] == "MAL 1"
    assert data["threat_assessment"]["level"] in {"HIGH", "CRITICAL"}
    assert data["sender_trust"]["level"] == "STI 0"

    # Verify human review mandated
    assert data["human_review_required"] is True
    assert any("Display name embeds a deceptive email" in r for r in data["human_review_reasons"])
    assert any("financial transaction indicator" in r.lower() for r in data["human_review_reasons"])


def test_workflow_2_legitimate_email(client):
    """Workflow 2: Analyze synthetic legitimate email with clean content."""
    raw_legitimate = (
        "From: \"Engineering Team\" <engineering@partner.com>\r\n"
        "To: team@mycompany.com\r\n"
        "Subject: Sprint Planning Agenda for Thursday\r\n"
        "Date: Mon, 19 Oct 2026 10:00:00 +0000\r\n"
        "Message-ID: <sprint.agenda.44@partner.com>\r\n"
        "\r\n"
        "Hello team, please find the proposed agenda for Thursday's sprint planning session."
    )
    res = client.post("/api/analyze", json={"raw_email": raw_legitimate, "retain_evidence": False})
    assert res.status_code == 200
    data = res.json()

    # Content is clean -> TSR is LOW
    assert data["threat_assessment"]["level"] == "LOW"
    assert data["human_review_required"] is False

    # Orthogonality: identity is NOT falsely marked verified just because content is harmless
    assert data["identity_assurance"]["level"] == "T-IAL 0"
    assert data["sender_trust"]["level"] == "STI 0"
    assert "SAFETY MANDATE" in data["safety_warning"]


def test_workflow_3_upload_eml_file(client):
    """Workflow 3: Upload a valid .eml file with multipart content."""
    eml_content = (
        b"From: \"Vendor Accounting\" <invoicing@vendor-logistics.com>\r\n"
        b"To: ap@client.com\r\n"
        b"Subject: Logistics Service Invoice #4401\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"EML_BOUND\"\r\n"
        b"\r\n"
        b"--EML_BOUND\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Please find our monthly logistics invoice attached.\r\n"
        b"\r\n"
        b"--EML_BOUND\r\n"
        b"Content-Type: application/pdf\r\n"
        b"Content-Disposition: attachment; filename=\"invoice_4401.pdf\"\r\n"
        b"\r\n"
        b"%PDF-1.4 [dummy content]\r\n"
        b"--EML_BOUND--\r\n"
    )
    res = client.post(
        "/api/analyze-file",
        files={"file": ("invoice_4401.eml", eml_content, "message/rfc822")},
        data={"retain_evidence": "false"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["subject"] == "Logistics Service Invoice #4401"
    assert data["claimed_identity"]["address"] == "invoicing@vendor-logistics.com"
    assert any("INVOICE" in f.get("id", "") for f in data["findings"])


def test_workflow_4_malformed_and_oversized_safety(client):
    """Workflow 4: Handle malformed headers and oversized inputs without unhandled crashes."""
    # A. Malformed with multiple From headers
    malformed_from = (
        "From: Admin <admin@corp.com>\r\n"
        "From: Attacker <attacker@scam.org>\r\n"
        "Subject: Duplicate From Injection\r\n"
        "\r\n"
        "Testing multiple from headers."
    )
    res_malformed = client.post("/api/analyze", json={"raw_email": malformed_from, "retain_evidence": False})
    assert res_malformed.status_code == 200
    assert res_malformed.json()["threat_assessment"]["level"] == "CRITICAL"

    # B. Oversized input > 1 MB rejected with 413
    oversized = "From: a@b.com\r\n\r\n" + ("A" * (1024 * 1024 + 50))
    res_oversized = client.post("/api/analyze", json={"raw_email": oversized, "retain_evidence": False})
    assert res_oversized.status_code == 413


def test_workflow_5_incident_history_and_details(client):
    """Workflow 5: Query incident log and retrieve single incident details with audit events."""
    raw = "From: user@corp.com\r\nSubject: Test Incident\r\n\r\nHello"
    res_create = client.post("/api/analyze", json={"raw_email": raw, "retain_evidence": False})
    inc_id = res_create.json()["incident_id"]

    # History list
    res_list = client.get("/api/incidents?limit=10")
    assert res_list.status_code == 200
    assert any(item["id"] == inc_id for item in res_list.json())

    # Details
    res_detail = client.get(f"/api/incidents/{inc_id}")
    assert res_detail.status_code == 200
    detail = res_detail.json()
    assert detail["id"] == inc_id
    assert len(detail["audit_events"]) >= 1


def test_workflow_6_human_review_persistence(client):
    """Workflow 6: Change human review status and verify persistence across queries."""
    raw = "From: hr@corp.com\r\nSubject: Wire Info\r\n\r\nChange direct deposit."
    res_create = client.post("/api/analyze", json={"raw_email": raw, "retain_evidence": False})
    inc_id = res_create.json()["incident_id"]

    # Initial state
    assert client.get(f"/api/incidents/{inc_id}").json()["human_review_status"] == "PENDING"

    # Update to ESCALATED with analyst notes
    res_update = client.patch(
        f"/api/incidents/{inc_id}/review",
        json={"status": "ESCALATED", "notes": "Escalated to Tier-2 SOC for vendor verification."},
    )
    assert res_update.status_code == 200

    # Verify persisted state
    updated = client.get(f"/api/incidents/{inc_id}").json()
    assert updated["human_review_status"] == "ESCALATED"
    assert updated["analyst_notes"] == "Escalated to Tier-2 SOC for vendor verification."
    assert updated["assessment"]["human_review_status"] == "ESCALATED"
    assert updated["assessment"]["analyst_notes"] == "Escalated to Tier-2 SOC for vendor verification."


def test_workflow_7_evidence_integrity_verification(client):
    """Workflow 7: Verify evidence integrity (Valid, Tampered, and Discarded modes)."""
    import time
    # A. With explicit retention
    raw = "From: legal@corp.com\r\nSubject: Evidentiary Record\r\n\r\nStrictly confidential."
    res_retained = client.post("/api/analyze", json={"raw_email": raw, "retain_evidence": True})
    inc_retained_id = res_retained.json()["incident_id"]

    # Verify untampered
    verify_valid = client.post(f"/api/incidents/{inc_retained_id}/verify-evidence").json()
    assert verify_valid["status"] == "VERIFIED"
    assert verify_valid["matches"] is True

    # Mutate byte on disk with retry for Windows OneDrive sync
    detail = client.get(f"/api/incidents/{inc_retained_id}").json()
    p = Path(detail["evidence_path"])
    for attempt in range(5):
        try:
            p.write_bytes(p.read_bytes() + b"TAMPERED_BYTE")
            break
        except PermissionError:
            time.sleep(0.1)

    # Verify tamper detected
    verify_tampered = client.post(f"/api/incidents/{inc_retained_id}/verify-evidence").json()
    assert verify_tampered["status"] == "TAMPER_DETECTED"
    assert verify_tampered["matches"] is False

    # B. Without retention (privacy default)
    res_discarded = client.post("/api/analyze", json={"raw_email": raw, "retain_evidence": False})
    inc_discarded_id = res_discarded.json()["incident_id"]

    verify_discarded = client.post(f"/api/incidents/{inc_discarded_id}/verify-evidence").json()
    assert verify_discarded["status"] == "NOT_RETAINED"
    assert verify_discarded["matches"] is None
