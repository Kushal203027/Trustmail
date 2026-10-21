"""
TrustMail: Pytest Test Fixtures and Configurations.
"""

import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient

from main import app
from trustmail.config import DATABASE_PATH, EVIDENCE_DIR
from trustmail.db import init_db


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Ensures test database tables exist."""
    init_db()


@pytest.fixture
def client():
    """Provides a FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def sample_valid_email() -> bytes:
    """Standard valid RFC 5322 email with single-part text."""
    return (
        b"From: \"Alice Smith\" <alice@example.com>\r\n"
        b"To: \"Bob Jones\" <bob@example.com>\r\n"
        b"Subject: Project Kickoff Meeting\r\n"
        b"Date: Mon, 19 Oct 2026 10:00:00 +0000\r\n"
        b"Message-ID: <msg.123456@example.com>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Hi Bob,\r\n"
        b"Looking forward to the kickoff meeting at 2pm today.\r\n"
        b"Best regards,\r\n"
        b"Alice\r\n"
    )


@pytest.fixture
def sample_multipart_email() -> bytes:
    """Multipart MIME email with text and attachment."""
    return (
        b"From: Sender <sender@domain.com>\r\n"
        b"To: Recipient <recipient@domain.com>\r\n"
        b"Subject: Meeting Notes and Attachment\r\n"
        b"Date: Mon, 19 Oct 2026 12:00:00 +0000\r\n"
        b"Message-ID: <multi.789@domain.com>\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"BOUNDARY_XYZ\"\r\n"
        b"\r\n"
        b"--BOUNDARY_XYZ\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Please see attached documentation.\r\n"
        b"\r\n"
        b"--BOUNDARY_XYZ\r\n"
        b"Content-Type: application/pdf;\r\n"
        b"Content-Disposition: attachment; filename=\"notes.pdf\"\r\n"
        b"\r\n"
        b"JVBERi0xLjQKJcTl8uXr...\r\n"
        b"--BOUNDARY_XYZ--\r\n"
    )
