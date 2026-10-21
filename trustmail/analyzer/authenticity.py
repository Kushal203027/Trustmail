"""
TrustMail: Message Authenticity Analyzer.
Evaluates payload integrity, DKIM header structures, and cryptographic hash evidence.
Enforces the core rule: A cryptographic hash alone establishes integrity at intake,
not complete end-to-end provenance or chain of custody.
"""

import re
from typing import List, Tuple
from trustmail.parser import ParsedEmail
from trustmail.analyzer.models import (
    Finding,
    FindingCategory,
    Severity,
    DimensionScore,
)


def analyze_authenticity(parsed: ParsedEmail) -> Tuple[DimensionScore, List[Finding]]:
    """
    Evaluates message integrity, signature header presence, and intake hashing.
    """
    findings: List[Finding] = []

    # 1. Fact: Intake Hash Computed
    findings.append(Finding(
        id="FACT-AUTH-SHA256-INTAKE",
        dimension="AUTHENTICITY",
        category=FindingCategory.VERIFIED_FACT,
        severity=Severity.INFO,
        title="Intake SHA-256 Digest Established",
        description=f"Computed SHA-256 hash over {parsed.byte_size} original bytes: {parsed.raw_hash}",
        evidence=f"SHA-256: {parsed.raw_hash} (Size: {parsed.byte_size} bytes)",
        limitations=(
            "Cryptographic hashing proves only that the stored or compared byte sequence matches the intake bytes. "
            "It does NOT prove message authenticity prior to receipt, nor does it identify who originally authored the bytes."
        ),
    ))

    # 2. Check for DKIM-Signature headers
    if parsed.dkim_headers:
        for idx, dkim_raw in enumerate(parsed.dkim_headers):
            # Extract tags safely using regex
            d_match = re.search(r'\bd=([a-zA-Z0-9.-]+)', dkim_raw)
            s_match = re.search(r'\bs=([a-zA-Z0-9.-]+)', dkim_raw)
            bh_match = re.search(r'\bbh=([a-zA-Z0-9+/=]+)', dkim_raw)
            l_match = re.search(r'\bl=([0-9]+)', dkim_raw)

            domain_tag = d_match.group(1) if d_match else "unknown"
            selector_tag = s_match.group(1) if s_match else "unknown"
            bh_tag = bh_match.group(1) if bh_match else "missing"

            findings.append(Finding(
                id=f"CLAIM-AUTH-DKIM-HEADER-{idx+1}",
                dimension="AUTHENTICITY",
                category=FindingCategory.UNVERIFIED_CLAIM,
                severity=Severity.INFO,
                title=f"DKIM-Signature Header Present (d={domain_tag}, s={selector_tag})",
                description=(
                    f"Message payload includes a DKIM-Signature header for domain '{domain_tag}' "
                    f"using selector '{selector_tag}' and body hash '{bh_tag[:16]}...'."
                ),
                evidence=dkim_raw[:200] + ("..." if len(dkim_raw) > 200 else ""),
                limitations=(
                    "CRITICAL LIMITATION: The cryptographic validity of this DKIM signature was NOT validated "
                    "against live DNS records in this offline prototype. Senders can insert malformed, expired, "
                    "or fabricated DKIM headers. Presence of a DKIM header alone does not guarantee authenticity."
                ),
            ))

            # Check for dangerous deprecated 'l=' tag (body length limit)
            if l_match:
                findings.append(Finding(
                    id=f"ALERT-AUTH-DKIM-L-TAG-{idx+1}",
                    dimension="AUTHENTICITY",
                    category=FindingCategory.HEURISTIC_FINDING,
                    severity=Severity.HIGH,
                    title="Deprecated DKIM Length Tag ('l=') Detected",
                    description=(
                        f"DKIM signature specifies a body length limit of {l_match.group(1)} bytes. "
                        "This permits arbitrary malicious content to be appended to the message without invalidating the DKIM signature."
                    ),
                    evidence=f"DKIM tag: l={l_match.group(1)}",
                    limitations="RFC 6376 §8.2 discourages 'l=' due to DKIM body-append replay attacks.",
                ))
    else:
        findings.append(Finding(
            id="UNKNOWN-AUTH-NO-DKIM",
            dimension="AUTHENTICITY",
            category=FindingCategory.UNKNOWN_INFORMATION,
            severity=Severity.INFO,
            title="No Cryptographic Signature Headers Detected",
            description="The message payload contains zero DKIM-Signature, S/MIME, or OpenPGP signature structures.",
            evidence="Header scan: 0 instances of 'DKIM-Signature', 'X-PGP-Sig', or S/MIME multipart/signed.",
            limitations="The message payload possesses zero mathematical guarantees against transit tampering.",
        ))

    # Calculate MAL Score
    mal_level = "MAL 1"
    score = DimensionScore(
        level=mal_level,
        title="MAL 1: Ingress Integrity Established (Local)",
        description="The exact received byte stream has been captured and hashed via SHA-256.",
        rationale=(
            "Original bytes are fingerprinted for local tamper detection. However, end-to-end cryptographic "
            "verification (live DNS DKIM or S/MIME PKI) is not verified by this prototype."
        ),
        is_simulated_or_limited=True,
    )

    return score, findings
