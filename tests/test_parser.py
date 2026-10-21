"""
TrustMail Test Suite: Email Parser.
Validates RFC 5322 parsing, header extraction, MIME walking, and URL extraction.
"""

import pytest
from trustmail.parser import parse_email_defensively, extract_address_and_domain, extract_urls_from_text


def test_valid_single_part_parsing(sample_valid_email):
    """Verifies that a clean single-part RFC 5322 email is accurately parsed."""
    parsed = parse_email_defensively(sample_valid_email)

    assert parsed.claimed_display_name == "Alice Smith"
    assert parsed.claimed_address == "alice@example.com"
    assert parsed.claimed_domain == "example.com"
    assert parsed.subject == "Project Kickoff Meeting"
    assert parsed.message_id == "<msg.123456@example.com>"
    assert "Hi Bob" in parsed.body_text
    assert len(parsed.parser_warnings) == 0
    assert len(parsed.raw_hash) == 64


def test_valid_multipart_parsing(sample_multipart_email):
    """Verifies that multipart/mixed messages extract both text and attachment metadata."""
    parsed = parse_email_defensively(sample_multipart_email)

    assert parsed.claimed_address == "sender@domain.com"
    assert "Please see attached documentation" in parsed.body_text
    assert len(parsed.attachments) == 1
    assert parsed.attachments[0]["filename"] == "notes.pdf"
    assert parsed.attachments[0]["content_type"] == "application/pdf"
    assert parsed.attachments[0]["size_bytes"] > 0


def test_address_extraction_edge_cases():
    """Tests address and domain parsing across tricky formats."""
    name, addr, dom = extract_address_and_domain('Dr. John Doe <john.doe@hospital.org>')
    assert name == "Dr. John Doe"
    assert addr == "john.doe@hospital.org"
    assert dom == "hospital.org"

    # Bare address without angle brackets
    name2, addr2, dom2 = extract_address_and_domain('simple@domain.com')
    assert addr2 == "simple@domain.com"
    assert dom2 == "domain.com"

    # Malformed / empty input
    name3, addr3, dom3 = extract_address_and_domain('')
    assert name3 == ""
    assert addr3 == ""
    assert dom3 == ""


def test_url_extraction():
    """Tests regex extraction of URLs from text."""
    text = (
        "Visit our site at https://example.com/welcome and http://sub.domain.org:8080/path?id=123. "
        "Also see https://another.com/test)."
    )
    urls = extract_urls_from_text(text)
    assert "https://example.com/welcome" in urls
    assert "http://sub.domain.org:8080/path?id=123" in urls
    assert "https://another.com/test" in urls
