"""
TrustMail: Sender Trust and Reputation Analyzer.
Evaluates historical communication patterns and reputation baselines.
Enforces the core rule: An unknown sender is NOT assumed malicious,
and a verified sender is NOT assumed trustworthy.
"""

from typing import List, Tuple
from trustmail.parser import ParsedEmail
from trustmail.analyzer.models import (
    Finding,
    FindingCategory,
    Severity,
    DimensionScore,
)


def analyze_trust(parsed: ParsedEmail) -> Tuple[DimensionScore, List[Finding]]:
    """
    Evaluates sender trust and reputation baseline.
    """
    findings: List[Finding] = []

    domain = parsed.claimed_domain
    addr = parsed.claimed_address

    if not addr:
        findings.append(Finding(
            id="UNKNOWN-TRUST-NO-SENDER",
            dimension="TRUST",
            category=FindingCategory.UNKNOWN_INFORMATION,
            severity=Severity.INFO,
            title="Sender Identity Missing for Trust Evaluation",
            description="Reputation baseline cannot be queried because no sender address was identified.",
            evidence="Sender address is empty.",
            limitations="Sender trust requires a stable identifier to correlate historical interaction.",
        ))
    else:
        findings.append(Finding(
            id="UNKNOWN-TRUST-UNESTABLISHED-HISTORY",
            dimension="TRUST",
            category=FindingCategory.UNKNOWN_INFORMATION,
            severity=Severity.INFO,
            title=f"Unestablished Interaction History for '{addr}'",
            description=(
                f"No prior communication records or verified trust relationship exist in the "
                f"local environment for sender '{addr}' or domain '{domain}'."
            ),
            evidence=f"Sender Domain: {domain or 'None'}",
            limitations=(
                "CORE SAFETY PRINCIPLE: An unestablished reputation is a neutral factual state, "
                "NOT proof of malicious activity. Legitimate first-time contacts, external inquiries, "
                "and whistleblowers routinely present with unestablished reputation."
            ),
        ))

    score = DimensionScore(
        level="STI 0",
        title="STI 0: Unestablished / Unknown Sender Trust",
        description="No historical communication baseline or peer attestation exists for this sender.",
        rationale=(
            "The prototype does not connect to external DNSBL/reputation feeds. "
            "In accordance with TrustMail safety principles, unestablished trust is treated as neutral, "
            "not adversarial."
        ),
        is_simulated_or_limited=True,
    )

    return score, findings
