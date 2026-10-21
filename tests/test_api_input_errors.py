"""API-level checks for empty input and safe parser failure responses."""

from trustmail.api import routes
from trustmail import parser


def test_empty_or_whitespace_paste_is_rejected(client):
    for raw_email in ("", " \r\n\t "):
        response = client.post("/api/analyze", json={"raw_email": raw_email})

        assert response.status_code == 400
        assert "empty" in response.json()["detail"].lower()


def test_empty_upload_is_rejected(client):
    response = client.post(
        "/api/analyze-file",
        files={"file": ("empty.eml", b"", "message/rfc822")},
    )

    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_unexpected_parser_error_does_not_echo_email_content(client, monkeypatch, caplog):
    message_marker = "Synthetic private message body marker"

    def fail_parser(_raw_bytes):
        raise RuntimeError(message_marker)

    monkeypatch.setattr(routes, "parse_email_defensively", fail_parser)
    response = client.post(
        "/api/analyze",
        json={"raw_email": f"From: demo@example.test\n\n{message_marker}"},
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "Email analysis failed due to an internal error."
    assert message_marker not in response.text
    assert message_marker not in caplog.text


def test_parser_fallback_warnings_do_not_echo_exception_details(client, monkeypatch):
    message_marker = "Synthetic parser exception detail marker"

    def fail_parser(*_args, **_kwargs):
        raise RuntimeError(message_marker)

    monkeypatch.setattr(parser.email, "message_from_bytes", fail_parser)
    response = client.post(
        "/api/analyze",
        json={"raw_email": f"From: demo@example.test\n\n{message_marker}"},
    )

    assert response.status_code == 200
    assert message_marker not in response.text
    assert any("Primary email parser failed" in finding["description"] for finding in response.json()["findings"])
