"""Public demo privacy and concurrent synthetic-analysis checks."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from main import app
from trustmail.api import routes
from trustmail.db import get_incident

ROOT = Path(__file__).resolve().parents[1]


def synthetic_email(subject: str) -> str:
    return (
        "From: Demo Sender <sender@example.test>\r\n"
        "To: Demo Recipient <recipient@example.test>\r\n"
        f"Subject: {subject}\r\n"
        "Date: Tue, 20 Oct 2026 10:00:00 +0000\r\n"
        "Message-ID: <demo@example.test>\r\n\r\n"
        "Synthetic message for an isolated TrustMail demo test."
    )


def test_demo_mode_analysis_does_not_retain_message_or_metadata(client, monkeypatch):
    monkeypatch.setattr(routes, "DEMO_MODE", True)

    def unexpected_write(*_args, **_kwargs):
        pytest.fail("demo mode must not write evidence or incident records")

    monkeypatch.setattr(routes, "store_evidence", unexpected_write)
    monkeypatch.setattr(routes, "save_incident", unexpected_write)
    raw_message = synthetic_email(f"Synthetic privacy check {uuid4()}")

    response = client.post(
        "/api/analyze",
        json={"raw_email": raw_message, "retain_evidence": True},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["subject"] in raw_message
    assert get_incident(data["incident_id"]) is None


def test_demo_mode_upload_does_not_retain_message_or_metadata(client, monkeypatch):
    monkeypatch.setattr(routes, "DEMO_MODE", True)

    def unexpected_write(*_args, **_kwargs):
        pytest.fail("demo mode must not write evidence or incident records")

    monkeypatch.setattr(routes, "store_evidence", unexpected_write)
    monkeypatch.setattr(routes, "save_incident", unexpected_write)
    upload_message = synthetic_email(f"Synthetic upload privacy check {uuid4()}").encode()
    response = client.post(
        "/api/analyze-file",
        files={"file": ("synthetic.eml", upload_message, "message/rfc822")},
        data={"retain_evidence": "true"},
    )

    assert response.status_code == 200
    assert get_incident(response.json()["incident_id"]) is None


def test_demo_mode_blocks_shared_incident_and_review_endpoints(client, monkeypatch):
    monkeypatch.setattr(routes, "DEMO_MODE", True)

    def storage_must_not_be_reached(*_args, **_kwargs):
        pytest.fail("demo mode must block shared-record access before reading or writing storage")

    monkeypatch.setattr(routes, "list_incidents", storage_must_not_be_reached)
    monkeypatch.setattr(routes, "get_incident", storage_must_not_be_reached)
    monkeypatch.setattr(routes, "update_review_status", storage_must_not_be_reached)
    monkeypatch.setattr(routes, "verify_stored_evidence_integrity", storage_must_not_be_reached)
    monkeypatch.setattr(routes, "log_audit_event", storage_must_not_be_reached)
    requests = [
        ("get", "/api/incidents", None),
        ("get", "/api/incidents/a-known-or-guessed-id", None),
        ("patch", "/api/incidents/a-known-or-guessed-id/review", {"status": "DISMISSED", "notes": "synthetic"}),
        ("post", "/api/incidents/a-known-or-guessed-id/verify-evidence", None),
    ]

    for method, path, payload in requests:
        response = client.request(method, path, json=payload)
        assert response.status_code == 503
        assert "disabled in public demo mode" in response.json()["detail"]


def test_status_endpoint_reports_public_demo_capabilities(client, monkeypatch):
    monkeypatch.setattr(routes, "DEMO_MODE", True)

    response = client.get("/api/status")

    assert response.status_code == 200
    assert response.json() == {"demo_mode": True, "history_enabled": False}


def test_frontend_explains_demo_limits_and_uses_server_error_message():
    app_js = (ROOT / "trustmail" / "static" / "app.js").read_text(encoding="utf-8")
    index_html = (ROOT / "trustmail" / "static" / "index.html").read_text(encoding="utf-8")

    assert 'fetch("/api/status")' in app_js
    assert '"/api/incidents?limit=50"' in app_js
    assert "getResponseError(res" in app_js
    assert 'id="demo-mode-banner"' in index_html
    assert 'id="demo-review-note"' in index_html
    assert "innerHTML" not in app_js


def test_frontend_does_not_claim_ephemeral_processing_when_status_is_unknown():
    app_js = (ROOT / "trustmail" / "static" / "app.js").read_text(encoding="utf-8")
    index_html = (ROOT / "trustmail" / "static" / "index.html").read_text(encoding="utf-8")

    assert "let statusConfirmed = false" in app_js
    assert "TrustMail cannot confirm its privacy mode" in app_js
    assert "Analysis is disabled until TrustMail confirms" in app_js
    assert "if (!statusConfirmed)" in app_js
    assert 'document.getElementById("btn-refresh-history").classList.add("hidden")' in app_js
    assert "Privacy details appear after the server confirms its mode." in index_html


def test_frontend_hides_and_guards_history_in_public_demo_mode():
    app_js = (ROOT / "trustmail" / "static" / "app.js").read_text(encoding="utf-8")
    index_html = (ROOT / "trustmail" / "static" / "index.html").read_text(encoding="utf-8")

    assert 'document.getElementById("tab-btn-incidents").classList.add("hidden")' in app_js
    assert "if ((!statusConfirmed || demoMode) && viewName === \"incidents\") return;" in app_js
    assert "if (!statusConfirmed || demoMode) return;" in app_js
    assert 'id="btn-refresh-history"' in index_html


def test_public_demo_privacy_copy_describes_server_processing_without_local_claims():
    index_html = (ROOT / "trustmail" / "static" / "index.html").read_text(encoding="utf-8")

    assert "Public demo privacy" in index_html
    assert "processed on the TrustMail server for this response only" in index_html
    assert "not saved to shared history" in index_html
    assert "Visitors are not individually signed in" in index_html
    assert "Local demo only" not in index_html
    assert "Keep TrustMail bound to this computer" not in index_html
    assert "Local assessment workspace" not in index_html


def test_frontend_review_badges_match_rule_based_review_requirement():
    app_js = (ROOT / "trustmail" / "static" / "app.js").read_text(encoding="utf-8")

    assert 'label: "No review queued by rules", className: "badge-neutral"' in app_js
    assert 'label: "Review pending", className: "badge-warning"' in app_js
    assert "reviewStatusPresentation(reviewStatus, Boolean(inc.human_review_required))" in app_js
    assert 'outcomeTitle.textContent = "No rule-based escalation"' in app_js
    assert 'outcomeMark.textContent = "i"' in app_js


def test_concurrent_demo_analyses_return_their_own_synthetic_results(monkeypatch):
    monkeypatch.setattr(routes, "DEMO_MODE", True)
    subjects = [f"Concurrent synthetic case {index} {uuid4()}" for index in range(8)]

    def analyze(subject):
        with TestClient(app) as concurrent_client:
            return concurrent_client.post(
                "/api/analyze",
                json={"raw_email": synthetic_email(subject), "retain_evidence": True},
            )

    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(analyze, subjects))

    assert all(response.status_code == 200 for response in responses)
    results = [response.json() for response in responses]
    assert {result["subject"] for result in results} == set(subjects)
    assert len({result["incident_id"] for result in results}) == len(subjects)
    assert all(get_incident(result["incident_id"]) is None for result in results)
