"""
TrustMail: Identity Assurance Analyzer.
Evaluates claimed identity, envelope routing claims, and authentication headers.
Enforces the core rule: Email authentication does not prove a sender's real-world identity,
and sender-supplied Authentication-Results headers are untrusted claims.
"""

from typing import List, Tuple
from trustmail.parser import ParsedEmail
from trustmail.analyzer.models import (
    Finding,
    FindingCategory,
    Severity,
    DimensionScore,
    ClaimedIdentitySummary,
)


def analyze_identity(parsed: ParsedEmail) -> Tuple[DimensionScore, List[Finding], ClaimedIdentitySummary]:
    """
    Evaluates sender identity indicators and calculates Identity Assurance Level (T-IAL).
    """
    findings: List[Finding] = []

    claimed_summary = ClaimedIdentitySummary(
        display_name=parsed.claimed_display_name,
        address=parsed.claimed_address,
        domain=parsed.claimed_domain,
        reply_to=parsed.reply_to_address,
        return_path=parsed.return_path_address,
        all_from_headers=parsed.from_headers,
    )

    # 1. Fact: Claimed From header extracted
    if parsed.claimed_address:
        findings.append(Finding(
            id="FACT-ID-CLAIMED-FROM",
            dimension="IDENTITY",
            category=FindingCategory.VERIFIED_FACT,
            severity=Severity.INFO,
            title="Claimed Sender Address Extracted",
            description=f"The RFC 5322 From header asserts identity as '{parsed.claimed_address}'.",
            evidence=f"From: {parsed.from_headers[0] if parsed.from_headers else ''}",
            limitations="The From header is an unauthenticated presentation field that can be set arbitrarily by the sending MTA or client.",
        ))
    else:
        findings.append(Finding(
            id="ALERT-ID-MISSING-FROM",
            dimension="IDENTITY",
            category=FindingCategory.HEURISTIC_FINDING,
            severity=Severity.HIGH,
            title="Missing or Unparseable Sender Address",
            description="The message lacks a valid RFC 5322 sender address.",
            evidence="No valid address could be extracted from From: header.",
            limitations="Violates RFC 5322 §3.6; indicates severely malformed or adversarial message crafting.",
        ))

    # 2. Check for RFC 5322 multiple From headers
    if len(parsed.from_headers) > 1:
        findings.append(Finding(
            id="ALERT-ID-MULTIPLE-FROM",
            dimension="IDENTITY",
            category=FindingCategory.HEURISTIC_FINDING,
            severity=Severity.HIGH,
            title="Multiple From Headers Detected",
            description=f"Message contains {len(parsed.from_headers)} separate 'From:' headers.",
            evidence=" | ".join(parsed.from_headers),
            limitations="RFC 5322 allows exactly one From header unless a Sender header is specified. Multiple From headers are commonly used to exploit parser differences between security gateways and mail clients.",
        ))

    # 3. Analyze Return-Path vs From Domain alignment
    if parsed.claimed_domain and parsed.return_path_domain:
        if parsed.claimed_domain.lower() != parsed.return_path_domain.lower():
            findings.append(Finding(
                id="CLAIM-ID-RETURN-PATH-MISMATCH",
                dimension="IDENTITY",
                category=FindingCategory.UNVERIFIED_CLAIM,
                severity=Severity.MEDIUM,
                title="Envelope Return-Path / From Domain Mismatch",
                description=(
                    f"The presentation domain '{parsed.claimed_domain}' differs from the "
                    f"envelope Return-Path domain '{parsed.return_path_domain}'."
                ),
                evidence=f"From Domain: {parsed.claimed_domain} | Return-Path: {parsed.return_path}",
                limitations=(
                    "Domain misalignment is common in legitimate mailing lists and bulk transactional services, "
                    "but is also a frequent characteristic of domain spoofing and phishing."
                ),
            ))

    # 4. Analyze untrusted Authentication-Results headers
    if parsed.auth_results_headers:
        for idx, ar in enumerate(parsed.auth_results_headers):
            findings.append(Finding(
                id=f"CLAIM-ID-AUTH-RESULTS-{idx+1}",
                dimension="IDENTITY",
                category=FindingCategory.UNVERIFIED_CLAIM,
                severity=Severity.LOW,
                title="Untrusted In-Band Authentication-Results Header Found",
                description="Message contains an Authentication-Results header reported in transit.",
                evidence=ar[:200] + ("..." if len(ar) > 200 else ""),
                limitations=(
                    "CRITICAL SECURITY LIMITATION: Any header received inside the email payload could have been "
                    "inserted by an untrusted external sender or malicious upstream MTA. These results are unverified claims "
                    "and cannot be accepted as proof of SPF/DKIM/DMARC validation without local cryptographic verification."
                ),
            ))
    else:
        findings.append(Finding(
            id="UNKNOWN-ID-AUTH-RESULTS",
            dimension="IDENTITY",
            category=FindingCategory.UNKNOWN_INFORMATION,
            severity=Severity.INFO,
            title="No Authentication-Results Headers Present",
            description="The message contains no transit-level Authentication-Results headers.",
            evidence="Header scan: 0 instances of 'Authentication-Results'.",
            limitations="Indicates that upstream relays did not record authentication, or the message was submitted directly via an uninstrumented channel.",
        ))

    # Determine T-IAL Level
    # In this local prototype with no live DNS/DKIM crypto engine, we assign T-IAL 0 with transparent explanation
    score = DimensionScore(
        level="T-IAL 0",
        title="Unverified / Anonymous (Claimed Identity Only)",
        description="The sender identity is based entirely on unauthenticated presentation headers.",
        rationale=(
            "No live cryptographic domain verification (SPF/DKIM/DMARC) or individual credentials (S/MIME/VC) "
            "were validated by this local prototype. Any authentication results in the headers are treated as unverified claims."
        ),
        is_simulated_or_limited=True,
    )

    return score, findings, claimed_summary
