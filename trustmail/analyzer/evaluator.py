"""
TrustMail: Evaluation Orchestrator.
Coordinates the four orthogonal analysis modules (Identity, Authenticity, Threat, Trust),
enforces epistemological partitioning, and constructs the structured AssessmentResult.
"""

import uuid
from datetime import datetime, timezone
from typing import List

from trustmail.config import ASSESSMENT_VERSION
from trustmail.parser import ParsedEmail
from trustmail.analyzer.identity import analyze_identity
from trustmail.analyzer.authenticity import analyze_authenticity
from trustmail.analyzer.threat import analyze_threats
from trustmail.analyzer.trust import analyze_trust
from trustmail.analyzer.models import (
    AssessmentResult,
    Finding,
    FindingCategory,
)


def evaluate_email(parsed: ParsedEmail, incident_id: str = None) -> AssessmentResult:
    """
    Executes the full multi-dimensional security evaluation on a parsed email.
    Maintains strict orthogonality between identity, authenticity, threat, and trust.
    """
    inc_id = incident_id or str(uuid.uuid4())
    now_utc = datetime.now(timezone.utc).isoformat()

    # 1. Run the 4 Orthogonal Analysis Engines
    ial_score, id_findings, claimed_id = analyze_identity(parsed)
    mal_score, auth_findings = analyze_authenticity(parsed)
    threat_score, threat_findings, review_required, review_reasons = analyze_threats(parsed)
    trust_score, trust_findings = analyze_trust(parsed)

    # These IDs show findings associated with each assessment dimension. They are
    # explanatory links, not a claim that the score is a sum of finding values.
    ial_score = ial_score.model_copy(update={"related_finding_ids": [f.id for f in id_findings]})
    mal_score = mal_score.model_copy(update={"related_finding_ids": [f.id for f in auth_findings]})
    threat_score = threat_score.model_copy(update={"related_finding_ids": [f.id for f in threat_findings]})
    trust_score = trust_score.model_copy(update={"related_finding_ids": [f.id for f in trust_findings]})

    # 2. Add Parser Warnings into Threat Findings
    for warn in parsed.parser_warnings:
        threat_findings.append(Finding(
            id="ALERT-PARSER-WARNING",
            dimension="THREAT",
            category=FindingCategory.HEURISTIC_FINDING,
            severity="MEDIUM",
            title="Parser Structural Warning",
            description=warn,
            evidence="Detected during RFC 5322 MIME traversal.",
            limitations="Malformed syntax may result from benign encoder bugs or deliberate parser evasion.",
        ))

    # Combine all findings
    all_findings: List[Finding] = id_findings + auth_findings + threat_findings + trust_findings

    # 3. Partition Findings by Epistemological Category
    verified_facts: List[str] = []
    unverified_claims: List[str] = []
    heuristic_findings: List[str] = []
    unknown_information: List[str] = []

    for f in all_findings:
        entry = f"[{f.dimension}] {f.title}: {f.description}"
        if f.category == FindingCategory.VERIFIED_FACT:
            verified_facts.append(entry)
        elif f.category == FindingCategory.UNVERIFIED_CLAIM:
            unverified_claims.append(entry)
        elif f.category == FindingCategory.HEURISTIC_FINDING:
            heuristic_findings.append(entry)
        elif f.category == FindingCategory.UNKNOWN_INFORMATION:
            unknown_information.append(entry)

    # 4. Construct Full Orthogonal Assessment Result
    return AssessmentResult(
        incident_id=inc_id,
        evidence_hash=parsed.raw_hash,
        byte_size=parsed.byte_size,
        timestamp=now_utc,
        assessment_version=ASSESSMENT_VERSION,
        subject=parsed.subject,
        claimed_identity=claimed_id,
        identity_assurance=ial_score,
        message_authenticity=mal_score,
        threat_assessment=threat_score,
        sender_trust=trust_score,
        human_review_required=review_required,
        human_review_reasons=review_reasons,
        human_review_status="PENDING",
        findings=all_findings,
        verified_facts=verified_facts,
        unverified_claims=unverified_claims,
        heuristic_findings=heuristic_findings,
        unknown_information=unknown_information,
    )
