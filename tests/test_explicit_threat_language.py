"""Focused regression tests for standalone explicit threat-language findings."""

from trustmail.analyzer.evaluator import evaluate_email
from trustmail.parser import parse_email_defensively
from trustmail.api import routes


FINDING_ID = "ALERT-THREAT-EXPLICIT-PHYSICAL-THREAT"


def assess_body(body: str):
    message = (
        "From: Campus Notices <notices@university.example>\r\n"
        "To: reader@example.test\r\n"
        "Subject: Campus Update\r\n"
        "Date: Tue, 20 Oct 2026 10:00:00 +0000\r\n"
        "Message-ID: <synthetic-threat-test@example.test>\r\n\r\n"
        f"{body}"
    ).encode("utf-8")
    parsed = parse_email_defensively(message)
    return parsed, evaluate_email(parsed)


def explicit_threat_findings(result):
    return [finding for finding in result.findings if finding.id == FINDING_ID]


def test_fictional_bomb_threat_records_exact_observation_without_url_or_identity_mismatch():
    body = "Fictional test message. I planted a bomb in the library and it will explode at noon."
    parsed, result = assess_body(body)

    findings = explicit_threat_findings(result)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category.value == "HEURISTIC_FINDING"
    assert finding.severity.value == "HIGH"
    assert finding.observations
    for observation in finding.observations:
        location = observation.source_location
        assert observation.type == "EXPLICIT_THREAT_LANGUAGE"
        assert location.source == "parsed body_text"
        assert location.available is True
        assert parsed.body_text[location.start:location.end] == observation.value
        assert observation.value in finding.evidence
    assert result.human_review_required is True
    assert any("urgent human review" in reason for reason in result.human_review_reasons)
    assert "cannot establish sender identity, intent, credibility" in finding.limitations
    assert "whether a weapon or explosive device exists" in finding.limitations
    assert not any(item.id.startswith("ALERT-THREAT-URL-") for item in result.findings)
    assert not any("SPOOF" in item.id or "IMPERSONATION" in item.id for item in result.findings)


def test_explicit_harm_and_attack_wording_are_recognized():
    for body in (
        "I will hurt someone who enters the building.",
        "We plan to attack the university campus.",
        "I will detonate a bomb at the campus entrance.",
    ):
        _parsed, result = assess_body(body)
        assert explicit_threat_findings(result), body
        assert result.human_review_required is True


def test_vague_urgency_is_not_classified_as_explicit_physical_threat():
    _parsed, result = assess_body("Please act urgently and reply as soon as possible.")

    assert not explicit_threat_findings(result)


def test_ordinary_university_announcement_is_not_flagged():
    _parsed, result = assess_body("The university announces a campus safety seminar next week.")

    assert not explicit_threat_findings(result)


def test_safety_report_quote_about_threat_language_is_not_flagged():
    body = 'This safety report uses the phrase "I planted a bomb in the library" as an example of language staff should report.'
    _parsed, result = assess_body(body)

    assert not explicit_threat_findings(result)


def test_emergency_preparedness_notice_is_not_flagged():
    body = "If you receive a bomb threat, leave the building and call campus security. Do not touch suspicious items."
    _parsed, result = assess_body(body)

    assert not explicit_threat_findings(result)


def test_analysis_endpoint_returns_linked_threat_finding_without_suspicious_url(client, monkeypatch):
    monkeypatch.setattr(routes, "DEMO_MODE", True)
    body = "I planted a bomb in the library and it will explode at noon."
    message = (
        "From: Campus Notices <notices@university.example>\r\n"
        "To: reader@example.test\r\n"
        "Subject: Synthetic incident\r\n\r\n"
        f"{body}"
    )

    response = client.post("/api/analyze", json={"raw_email": message})

    assert response.status_code == 200
    data = response.json()
    finding = next(item for item in data["findings"] if item["id"] == FINDING_ID)
    observation = finding["observations"][0]
    assert observation["value"] in body
    assert observation["source_location"]["source"] == "parsed body_text"
    assert FINDING_ID in data["threat_assessment"]["related_finding_ids"]
    assert data["human_review_required"] is True
