"""First Evidence-to-Claim Ledger slice: suspicious URL observations."""

from trustmail.analyzer.evaluator import evaluate_email
from trustmail.parser import parse_email_defensively


def test_suspicious_url_finding_serializes_linked_observation():
    raw = (
        b"From: sender@example.com\r\n"
        b"Subject: Sign in\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Please visit http://192.0.2.10/auth/login to continue."
    )
    parsed = parse_email_defensively(raw)
    assessment = evaluate_email(parsed)
    data = assessment.model_dump(mode="json")

    finding = next(f for f in data["findings"] if f["id"] == "ALERT-THREAT-URL-BARE-IP")
    observation = finding["observations"][0]
    assert observation["type"] == "EXTRACTED_URL"
    assert observation["value"] == "http://192.0.2.10/auth/login"
    assert observation["source_location"] == {
        "source": "parsed body_text",
        "available": True,
        "start": parsed.body_text.index(observation["value"]),
        "end": parsed.body_text.index(observation["value"]) + len(observation["value"]),
        "unavailable_reason": None,
    }
    assert finding["id"] == "ALERT-THREAT-URL-BARE-IP"


def test_html_extracted_url_marks_exact_source_location_unavailable():
    raw = (
        b"From: sender@example.com\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b'<a href="http://192.0.2.10/login">Continue</a>'
    )
    data = evaluate_email(parse_email_defensively(raw)).model_dump(mode="json")
    finding = next(f for f in data["findings"] if f["id"] == "ALERT-THREAT-URL-BARE-IP")
    location = finding["observations"][0]["source_location"]
    assert location["available"] is False
    assert location["start"] is None and location["end"] is None
    assert "exact source span is not available" in location["unavailable_reason"]


def test_display_name_mismatch_ledger_uses_parsed_header_fields():
    raw = (
        b'From: "Casey <casey@partner.example>" <sender@outside.example>\r\n'
        b"Subject: Update\r\n\r\nPlease review the update."
    )
    data = evaluate_email(parse_email_defensively(raw)).model_dump(mode="json")
    finding = next(
        f for f in data["findings"] if f["id"] == "ALERT-THREAT-DISPLAY-EMAIL-SPOOF"
    )
    assert [(o["type"], o["value"]) for o in finding["observations"]] == [
        ("DISPLAY_NAME", "Casey <casey@partner.example>"),
        ("EMBEDDED_EMAIL_ADDRESS", "casey@partner.example"),
        ("CLAIMED_FROM_ADDRESS", "sender@outside.example"),
    ]
    assert all(o["source_location"]["source"] in {"parsed From header", "parsed From display name"}
               for o in finding["observations"])
    assert all(o["source_location"]["start"] is None for o in finding["observations"])
    assert "does not prove impersonation" in finding["review_guidance"]
    assert finding["id"] in data["threat_assessment"]["related_finding_ids"]


def test_findings_without_ledger_observations_remain_compatible():
    raw = b"From: sender@example.com\r\nSubject: Hello\r\n\r\nNothing to see."
    data = evaluate_email(parse_email_defensively(raw)).model_dump(mode="json")
    sender_fact = next(f for f in data["findings"] if f["id"] == "FACT-ID-CLAIMED-FROM")
    assert sender_fact["observations"] == []


def test_api_and_incident_storage_preserve_url_observation(client):
    message = (
        "From: sender@example.com\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n\r\n"
        "Open http://192.0.2.44/login"
    )
    response = client.post("/api/analyze", json={"raw_email": message})
    assert response.status_code == 200
    response_data = response.json()
    response_finding = next(
        f for f in response_data["findings"] if f["id"] == "ALERT-THREAT-URL-BARE-IP"
    )
    assert response_finding["observations"][0]["value"] == "http://192.0.2.44/login"

    stored = client.get(f"/api/incidents/{response_data['incident_id']}")
    assert stored.status_code == 200
    stored_finding = next(
        f for f in stored.json()["assessment"]["findings"]
        if f["id"] == "ALERT-THREAT-URL-BARE-IP"
    )
    assert stored_finding["observations"] == response_finding["observations"]


def test_frontend_renders_ledger_fields_with_html_escaping():
    from pathlib import Path

    app_js = (Path(__file__).resolve().parents[1] / "trustmail" / "static" / "app.js").read_text(encoding="utf-8")
    assert "Rule/reference:" in app_js
    assert "Observed (${escapeHtml(observation.type)})" in app_js
    assert "escapeHtml(observation.value)" in app_js
    assert "Source location unavailable:" in app_js
    assert "escapeHtml(f.review_guidance)" in app_js
    assert "escapeHtml(f.description)" in app_js
    assert 'item.textContent = `${f.id}: ${f.title}`' in app_js
