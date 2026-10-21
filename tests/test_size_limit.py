"""
TrustMail Test Suite: Input-Size Enforcement.
Validates that inputs exceeding the 1 MB configurable threshold are rejected safely.
"""

import pytest
import asyncio
from fastapi import HTTPException
from trustmail.config import MAX_INPUT_BYTES
from trustmail.parser import parse_email_defensively
from trustmail.api.routes import read_limited_upload


def test_input_size_within_limit():
    """Confirms that messages within the 1 MB size limit are accepted."""
    small_data = b"From: a@b.com\r\nSubject: Test\r\n\r\n" + (b"A" * 5000)
    parsed = parse_email_defensively(small_data)
    assert parsed.byte_size == len(small_data)
    assert parsed.byte_size <= MAX_INPUT_BYTES


def test_input_size_exceeding_limit():
    """Confirms that messages exceeding 1 MB trigger a ValueError with descriptive message."""
    oversized_data = b"From: a@b.com\r\nSubject: Big\r\n\r\n" + (b"X" * (MAX_INPUT_BYTES + 10))
    with pytest.raises(ValueError) as excinfo:
        parse_email_defensively(oversized_data)
    assert "exceeds configured maximum limit" in str(excinfo.value)


def test_api_size_limit_rejection(client):
    """Verifies that the REST API returns HTTP 413 when receiving payload > 1 MB."""
    oversized_text = "From: a@b.com\nSubject: Too Big\n\n" + ("Z" * (MAX_INPUT_BYTES + 100))
    response = client.post("/api/analyze", json={"raw_email": oversized_text, "retain_evidence": False})
    assert response.status_code == 413
    assert "exceeds configured limit" in response.json()["detail"]


def test_api_file_size_limit_rejection(client):
    """Verifies that uploaded files > 1 MB return HTTP 413."""
    oversized_bytes = b"From: a@b.com\r\n\r\n" + (b"B" * (MAX_INPUT_BYTES + 50))
    response = client.post(
        "/api/analyze-file",
        files={"file": ("large.eml", oversized_bytes, "message/rfc822")},
        data={"retain_evidence": "false"},
    )
    assert response.status_code == 413


def test_file_reader_stops_at_limit_plus_one_byte():
    class LargeUpload:
        def __init__(self):
            self.bytes_read = 0

        async def read(self, size):
            amount = min(size, MAX_INPUT_BYTES * 2 - self.bytes_read)
            self.bytes_read += amount
            return b"x" * amount

    upload = LargeUpload()
    with pytest.raises(HTTPException) as error:
        asyncio.run(read_limited_upload(upload))
    assert error.value.status_code == 413
    assert upload.bytes_read == MAX_INPUT_BYTES + 1
