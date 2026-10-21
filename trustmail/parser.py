"""
TrustMail: Defensive Email Parser.
Extracts RFC 5322 headers, MIME payload text, URLs, and attachment metadata
without executing or evaluating scripts, links, or binary code.
"""

import email
import email.policy
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from trustmail.config import MAX_INPUT_BYTES
from trustmail.storage import calculate_evidence_hash


@dataclass
class ParsedEmail:
    """Represents a defensively parsed email message and its security artifacts."""
    raw_hash: str
    byte_size: int
    headers: List[Tuple[str, str]] = field(default_factory=list)
    from_headers: List[str] = field(default_factory=list)
    claimed_display_name: str = ""
    claimed_address: str = ""
    claimed_domain: str = ""
    reply_to: Optional[str] = None
    reply_to_address: Optional[str] = None
    reply_to_domain: Optional[str] = None
    return_path: Optional[str] = None
    return_path_address: Optional[str] = None
    return_path_domain: Optional[str] = None
    subject: str = ""
    date: Optional[str] = None
    message_id: Optional[str] = None
    auth_results_headers: List[str] = field(default_factory=list)
    dkim_headers: List[str] = field(default_factory=list)
    received_headers: List[str] = field(default_factory=list)
    body_text: str = ""
    body_html_snippet: str = ""
    urls: List[str] = field(default_factory=list)
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    parser_warnings: List[str] = field(default_factory=list)


def extract_address_and_domain(addr_str: str) -> Tuple[str, str, str]:
    """
    Safely parses a name-addr or addr-spec string into (display_name, email_address, domain).
    Does not crash on malformed input.
    """
    if not addr_str:
        return "", "", ""
    try:
        from email.utils import parseaddr
        name, address = parseaddr(addr_str)
        address = address.strip().lower()
        domain = address.split("@")[-1] if "@" in address else ""
        return name.strip(), address, domain
    except Exception:
        return "", "", ""


def extract_urls_from_text(text: str) -> List[str]:
    """
    Safely extracts HTTP/HTTPS URLs from text using regex.
    Limits collection to at most 100 URLs to avoid resource exhaustion.
    """
    if not text:
        return []
    # Standard URL pattern for email text
    url_pattern = re.compile(
        r'https?://(?:[a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=]|%[0-9a-fA-F]{2})+',
        re.IGNORECASE,
    )
    found = url_pattern.findall(text)
    # Deduplicate while preserving order, max 100
    seen = set()
    unique_urls = []
    for u in found:
        cleaned = u.rstrip(".,;!?)>'\"]}")
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique_urls.append(cleaned)
            if len(unique_urls) >= 100:
                break
    return unique_urls


def parse_email_defensively(raw_bytes: bytes) -> ParsedEmail:
    """
    Defensively parses raw email bytes into a structured ParsedEmail object.
    Enforces size limits, catches parser defects, and isolates hostile structures.
    """
    byte_size = len(raw_bytes)
    if byte_size > MAX_INPUT_BYTES:
        raise ValueError(
            f"Input size ({byte_size} bytes) exceeds configured maximum limit of {MAX_INPUT_BYTES} bytes (1 MB)."
        )

    evidence_hash = calculate_evidence_hash(raw_bytes)
    warnings: List[str] = []

    # Parse message with default modern policy (handles UTF-8, unfolds headers)
    try:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    except Exception:
        warnings.append("Primary email parser failed; falling back to compat32 policy.")
        try:
            msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)
        except Exception:
            warnings.append("Compat parser failed. Message structure is severely damaged.")
            return ParsedEmail(
                raw_hash=evidence_hash,
                byte_size=byte_size,
                parser_warnings=warnings,
            )

    # 1. Collect Headers Safely
    headers_list: List[Tuple[str, str]] = []
    from_headers: List[str] = []
    auth_results: List[str] = []
    dkim_headers: List[str] = []
    received_headers: List[str] = []

    try:
        for key, val in msg.items():
            k_lower = key.lower()
            str_val = str(val) if val is not None else ""
            headers_list.append((key, str_val))

            if k_lower == "from":
                from_headers.append(str_val)
            elif k_lower == "authentication-results":
                auth_results.append(str_val)
            elif k_lower == "dkim-signature":
                dkim_headers.append(str_val)
            elif k_lower == "received":
                received_headers.append(str_val)
    except Exception:
        warnings.append("Header iteration failed; some headers may be unavailable.")

    # Check for RFC 5322 §3.6 violation: Multiple From headers
    if len(from_headers) > 1:
        warnings.append(
            f"RFC 5322 VIOLATION: Message contains {len(from_headers)} 'From:' headers. Possible header injection attack."
        )
    elif len(from_headers) == 0:
        warnings.append("RFC 5322 VIOLATION: Message is missing required 'From:' header.")

    # Extract Primary From Identity
    primary_from = from_headers[0] if from_headers else ""
    claimed_name, claimed_addr, claimed_dom = extract_address_and_domain(primary_from)

    # Extract Reply-To
    reply_to_raw = msg.get("Reply-To", "")
    _, reply_to_addr, reply_to_dom = extract_address_and_domain(reply_to_raw)

    # Extract Return-Path
    return_path_raw = msg.get("Return-Path", "")
    _, return_path_addr, return_path_dom = extract_address_and_domain(return_path_raw)

    # Extract Subject, Date, Message-ID
    subject = str(msg.get("Subject", "") or "")
    date_val = msg.get("Date")
    date_str = str(date_val) if date_val else None
    msg_id = msg.get("Message-ID")
    msg_id_str = str(msg_id) if msg_id else None

    if not msg_id_str:
        warnings.append("Message is missing standard 'Message-ID' header.")
    if not date_str:
        warnings.append("Message is missing standard 'Date' header.")

    # 2. Defensively Walk MIME Tree (with depth guard)
    body_text_parts: List[str] = []
    body_html_parts: List[str] = []
    attachments: List[Dict[str, Any]] = []

    max_parts = 100
    part_count = 0

    try:
        if msg.is_multipart():
            for part in msg.walk():
                part_count += 1
                if part_count > max_parts:
                    warnings.append(f"MIME walk truncated at {max_parts} parts to prevent parser exhaustion.")
                    break

                # Check if part is an attachment
                content_disposition = str(part.get("Content-Disposition", "")).lower()
                is_attachment = "attachment" in content_disposition
                filename = part.get_filename() or ""

                content_type = part.get_content_type()

                if is_attachment or filename:
                    # Capture attachment metadata without loading full payload in memory
                    try:
                        payload = part.get_payload(decode=True)
                        att_size = len(payload) if payload else 0
                    except Exception:
                        att_size = 0
                    attachments.append({
                        "filename": filename or "unnamed_attachment",
                        "content_type": content_type,
                        "size_bytes": att_size,
                    })
                else:
                    # Textual content extraction
                    if content_type == "text/plain":
                        try:
                            charset = part.get_content_charset() or "utf-8"
                            text_bytes = part.get_payload(decode=True)
                            if text_bytes:
                                body_text_parts.append(text_bytes.decode(charset, errors="replace"))
                        except Exception:
                            warnings.append("Plaintext decoding failed for a message part.")
                    elif content_type == "text/html":
                        try:
                            charset = part.get_content_charset() or "utf-8"
                            html_bytes = part.get_payload(decode=True)
                            if html_bytes:
                                body_html_parts.append(html_bytes.decode(charset, errors="replace"))
                        except Exception:
                            warnings.append("HTML decoding failed for a message part.")
        else:
            # Single-part message
            content_type = msg.get_content_type()
            try:
                charset = msg.get_content_charset() or "utf-8"
                payload_bytes = msg.get_payload(decode=True)
                if payload_bytes:
                    decoded_str = payload_bytes.decode(charset, errors="replace")
                    if content_type == "text/html":
                        body_html_parts.append(decoded_str)
                    else:
                        body_text_parts.append(decoded_str)
            except Exception:
                warnings.append("Single-part payload decoding failed.")
    except Exception:
        warnings.append("MIME tree traversal failed; extracted content may be incomplete.")

    full_body_text = "\n".join(body_text_parts)
    full_html = "\n".join(body_html_parts)

    # 3. Safely Extract URLs
    all_urls = extract_urls_from_text(full_body_text)
    # Also extract href targets from HTML safely using regex (no DOM execution)
    if full_html:
        href_urls = re.findall(r'href=[\'"]?(https?://[^\'" >]+)', full_html, re.IGNORECASE)
        for u in href_urls:
            cleaned = u.rstrip(".,;!?)>'\"]}")
            if cleaned and cleaned not in all_urls:
                all_urls.append(cleaned)
                if len(all_urls) >= 100:
                    break

    return ParsedEmail(
        raw_hash=evidence_hash,
        byte_size=byte_size,
        headers=headers_list,
        from_headers=from_headers,
        claimed_display_name=claimed_name,
        claimed_address=claimed_addr,
        claimed_domain=claimed_dom,
        reply_to=reply_to_raw or None,
        reply_to_address=reply_to_addr or None,
        reply_to_domain=reply_to_dom or None,
        return_path=return_path_raw or None,
        return_path_address=return_path_addr or None,
        return_path_domain=return_path_dom or None,
        subject=subject,
        date=date_str,
        message_id=msg_id_str,
        auth_results_headers=auth_results,
        dkim_headers=dkim_headers,
        received_headers=received_headers,
        body_text=full_body_text,
        body_html_snippet=full_html[:1000] if full_html else "",
        urls=all_urls,
        attachments=attachments,
        parser_warnings=warnings,
    )
