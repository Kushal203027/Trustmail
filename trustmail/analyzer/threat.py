"""
TrustMail: Deterministic Threat Analyzer.
Detects explainable heuristic indicators: display name spoofing, suspicious URLs,
financial/credential urgency, coercive language, malformed headers, and risky attachments.
Enforces the core rule: Keyword detection does NOT prove intent or maliciousness,
and absence of indicators does NOT prove a message is harmless.
"""

import re
from typing import List, Tuple
from urllib.parse import urlparse

from trustmail.parser import ParsedEmail
from trustmail.analyzer.models import (
    Finding,
    Observation,
    SourceLocation,
    FindingCategory,
    Severity,
    DimensionScore,
)


def _url_observation(url: str, parsed: ParsedEmail) -> Observation:
    """Describe the extracted URL and point to body text when its span is known."""
    start = parsed.body_text.find(url)
    if start >= 0:
        location = SourceLocation(
            source="parsed body_text", available=True, start=start, end=start + len(url)
        )
    else:
        location = SourceLocation(
            source="parsed.urls", available=False,
            unavailable_reason="The parser extracted this URL, but its exact source span is not available in parsed body text (for example, it may come from an HTML href).",
        )
    return Observation(type="EXTRACTED_URL", value=url, source_location=location)


def _header_observation(observation_type: str, value: str, parsed_source: str) -> Observation:
    """Record a parser-extracted header field without claiming a raw-byte offset."""
    return Observation(
        type=observation_type,
        value=value,
        source_location=SourceLocation(
            source=parsed_source,
            available=True,
            unavailable_reason=None,
        ),
    )

# Common free webmail domains frequently abused in display-name spoofing
FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "tutanota.com", "mail.com", "yandex.com", "zoho.com",
}

# High-trust keywords frequently impersonated in display names
IMPERSONATION_KEYWORDS = [
    "microsoft", "apple", "google", "paypal", "it helpdesk", "it support",
    "security team", "security alert", "payroll", "human resources", "hr dept",
    "chief executive", "ceo", "cfo", "bank of america", "wells fargo", "chase bank",
]

# Risky attachment extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".ps1",
    ".iso", ".img", ".hta", ".cpl", ".docm", ".xlsm", ".pptm",
}

# Financial urgency patterns
FINANCIAL_PATTERNS = [
    (r"\bwire\s+transfer\b", "Wire Transfer Request"),
    (r"\b(update|change)\s+(bank|banking|direct\s+deposit|routing)\b", "Banking Details Change"),
    (r"\b(overdue\s+invoice|unpaid\s+invoice|invoice\s+attached)\b", "Urgent Invoice Request"),
    (r"\bgift\s+cards?\b", "Gift Card Solicitation"),
    (r"\bremittance\s+advice\b", "Remittance Advice Notice"),
    (r"\b(swift|iban)\s+code\b", "International Wire Identifier (SWIFT/IBAN)"),
]

# Credential harvesting patterns
CREDENTIAL_PATTERNS = [
    (r"\b(reset|verify|confirm)\s+your\s+password\b", "Password Reset Prompt"),
    (r"\baccount\s+(has\s+been\s+)?(suspended|locked|terminated)\b", "Account Suspension Notice"),
    (r"\b(verify|update)\s+your\s+(login|credentials|account)\b", "Credential Verification Demand"),
    (r"\bunauthorized\s+(login|access|activity)\s+detected\b", "Security Alert / False Breach Notice"),
    (r"\blogin\s+immediately\b", "Immediate Login Urgency"),
]

# Coercive / Threatening patterns
COERCIVE_PATTERNS = [
    (r"\bwithin\s+(24|12|48)\s+hours?\b", "Tight Deadline / Coercive Window"),
    (r"\b(legal\s+action|law\s+enforcement|warrant\s+issued)\b", "Legal Action or Law Enforcement Threat"),
    (r"\btermination\s+of\s+(employment|contract|service)\b", "Termination Threat"),
    (r"\bfailure\s+to\s+comply\b", "Coercive Compliance Warning"),
    (r"\bdo\s+not\s+contact\s+anyone\b", "Isolation Directive (Secrecy Command)"),
]


def analyze_threats(parsed: ParsedEmail) -> Tuple[DimensionScore, List[Finding], bool, List[str]]:
    """
    Executes deterministic checks and returns (DimensionScore, findings, human_review_required, reasons).
    """
    findings: List[Finding] = []
    human_review_reasons: List[str] = []

    # ---------------------------------------------------------
    # 1. Display-Name Spoofing and Impersonation Analysis
    # ---------------------------------------------------------
    display_name = parsed.claimed_display_name.strip()
    sender_addr = parsed.claimed_address.lower()
    sender_domain = parsed.claimed_domain.lower()

    if display_name:
        # Check A: Display name looks like an email address that differs from the actual sender
        email_in_name = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', display_name)
        if email_in_name:
            embedded_email = email_in_name.group(0).lower()
            if embedded_email != sender_addr:
                findings.append(Finding(
                    id="ALERT-THREAT-DISPLAY-EMAIL-SPOOF",
                    dimension="THREAT",
                    category=FindingCategory.HEURISTIC_FINDING,
                    severity=Severity.HIGH,
                    title="Display Name Contains Deceptive Sender Address",
                    description=(
                        f"The display name '{display_name}' embeds an email address '{embedded_email}' "
                        f"that does not match the actual transmitting address '{sender_addr}'."
                    ),
                    evidence=f"Display Name: {display_name} | Actual Address: {sender_addr}",
                    limitations=(
                        "Heuristic observation. While common in advanced credential phishing and CEO fraud, "
                        "some third-party ticketing systems generate similar headers."
                    ),
                    observations=[
                        _header_observation("DISPLAY_NAME", display_name, "parsed From header"),
                        _header_observation("EMBEDDED_EMAIL_ADDRESS", embedded_email, "parsed From display name"),
                        _header_observation("CLAIMED_FROM_ADDRESS", sender_addr, "parsed From header"),
                    ],
                    review_guidance="Contact the claimed sender using a known, independently obtained address or phone number. A display-name mismatch alone does not prove impersonation.",
                ))
                human_review_reasons.append("Display name embeds a deceptive email address differing from sender.")

        # Check B: High-trust organization/role in display name with free or unaligned domain
        disp_lower = display_name.lower()
        for kw in IMPERSONATION_KEYWORDS:
            if kw in disp_lower:
                if sender_domain in FREE_WEBMAIL_DOMAINS or kw not in sender_domain:
                    findings.append(Finding(
                        id=f"ALERT-THREAT-IMPERSONATION-{kw.replace(' ', '_').upper()}",
                        dimension="THREAT",
                        category=FindingCategory.HEURISTIC_FINDING,
                        severity=Severity.HIGH,
                        title=f"Potential Impersonation of '{kw.title()}' in Display Name",
                        description=(
                            f"Display name asserts authoritative role or brand '{kw}' "
                            f"while transmitting from unrelated domain '{sender_domain}'."
                        ),
                        evidence=f"Display Name: {display_name} | Sender: {sender_addr}",
                        limitations=(
                            "Keyword match does not establish criminal intent. External contractors or legitimate "
                            "users on consumer mail systems occasionally use descriptive display titles."
                        ),
                        observations=[
                            _header_observation("DISPLAY_NAME", display_name, "parsed From header"),
                            _header_observation("CLAIMED_FROM_ADDRESS", sender_addr, "parsed From header"),
                        ],
                        review_guidance="Verify the sender through a previously trusted contact method before acting. Do not rely on the message's reply address.",
                    ))
                    human_review_reasons.append(f"Potential impersonation of '{kw}' from non-authoritative domain '{sender_domain}'.")
                    break

    # ---------------------------------------------------------
    # 2. Suspicious URL Patterns and Domain Lookalikes
    # ---------------------------------------------------------
    for url in parsed.urls:
        try:
            parsed_u = urlparse(url)
            netloc = parsed_u.netloc.lower()
            path = parsed_u.path.lower()

            # Check A: IP-based URL
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?$', netloc):
                findings.append(Finding(
                    id="ALERT-THREAT-URL-BARE-IP",
                    dimension="THREAT",
                    category=FindingCategory.HEURISTIC_FINDING,
                    severity=Severity.HIGH,
                    title="URL Targets Bare IP Address Instead of Domain Name",
                    description=f"Message contains link pointing directly to bare IP address '{netloc}'.",
                    evidence=f"URL: {url}",
                    limitations="Standard corporate communications use registered DNS names. Bare IP links strongly correlate with evasion of domain reputation filters.",
                    observations=[_url_observation(url, parsed)],
                    review_guidance="Do not open the link. Verify its purpose and destination through a trusted security workflow.",
                ))
                human_review_reasons.append(f"Bare IP address in URL: {netloc}")

            # Check B: Punycode (IDN) domain
            if "xn--" in netloc:
                findings.append(Finding(
                    id="ALERT-THREAT-URL-PUNYCODE",
                    dimension="THREAT",
                    category=FindingCategory.HEURISTIC_FINDING,
                    severity=Severity.MEDIUM,
                    title="Punycode / Internationalized Domain Name in Link",
                    description=f"Link uses Punycode encoding '{netloc}', which may conceal a homoglyph spoof.",
                    evidence=f"URL: {url}",
                    limitations="Punycode is valid for legitimate non-Latin scripts, but is frequently exploited for lookalike phishing domains.",
                    observations=[_url_observation(url, parsed)],
                    review_guidance="Check the internationalized domain in an approved safe-analysis tool and verify it independently before use.",
                ))
                human_review_reasons.append(f"Punycode lookalike candidate in URL: {netloc}")

            # Check C: Excessive subdomains (> 3 parts, e.g. login.microsoft.com.malicious.net)
            parts = netloc.split(":")[0].split(".")
            if len(parts) > 4:
                findings.append(Finding(
                    id="ALERT-THREAT-URL-EXCESSIVE-SUBDOMAINS",
                    dimension="THREAT",
                    category=FindingCategory.HEURISTIC_FINDING,
                    severity=Severity.MEDIUM,
                    title="Excessive Subdomain Nesting in Link",
                    description=f"URL host '{netloc}' contains {len(parts)} domain labels, indicating potential brand nesting.",
                    evidence=f"URL: {url}",
                    limitations="Some CDN and cloud storage services legitimately utilize multi-label subdomains.",
                    observations=[_url_observation(url, parsed)],
                    review_guidance="Read the registered domain from right to left and verify the destination through a trusted source.",
                ))

            # Check D: Suspicious URL path keywords
            suspicious_path_tokens = ["/login", "/verify", "/update", "/password", "/credential", "/auth", "/signin"]
            for token in suspicious_path_tokens:
                if token in path:
                    findings.append(Finding(
                        id=f"ALERT-THREAT-URL-CREDENTIAL-PATH",
                        dimension="THREAT",
                        category=FindingCategory.HEURISTIC_FINDING,
                        severity=Severity.MEDIUM,
                        title=f"Credential Harvesting Keyword '{token}' in URL Path",
                        description=f"URL path '{path}' contains sensitive authentication keywords.",
                        evidence=f"URL: {url}",
                        limitations="Legitimate login links also use these paths; must be correlated with sender domain assurance.",
                        observations=[_url_observation(url, parsed)],
                        review_guidance="Do not sign in through the message link. Navigate to the service using a known address and check with its support channel.",
                    ))
                    break
        except Exception:
            continue

    # ---------------------------------------------------------
    # 3. Financial and Credential Urgency Patterns
    # ---------------------------------------------------------
    full_content = (parsed.subject + "\n" + parsed.body_text).lower()

    for pattern, title in FINANCIAL_PATTERNS:
        match = re.search(pattern, full_content, re.IGNORECASE)
        if match:
            snippet = match.group(0)
            findings.append(Finding(
                id=f"ALERT-THREAT-FINANCIAL-{title.replace(' ', '_').upper()}",
                dimension="THREAT",
                category=FindingCategory.HEURISTIC_FINDING,
                severity=Severity.HIGH,
                title=f"Financial Request Detected: {title}",
                description=f"The message contains vocabulary associated with financial transactions or wire instructions.",
                evidence=f"Matched text: '...{snippet}...' in subject/body.",
                limitations="Keyword presence does not confirm fraud; legitimate procurement and invoicing discuss these terms routinely.",
            ))
            human_review_reasons.append(f"High-consequence financial transaction indicator: {title}.")

    for pattern, title in CREDENTIAL_PATTERNS:
        match = re.search(pattern, full_content, re.IGNORECASE)
        if match:
            snippet = match.group(0)
            findings.append(Finding(
                id=f"ALERT-THREAT-CREDENTIAL-{title.replace(' ', '_').upper()}",
                dimension="THREAT",
                category=FindingCategory.HEURISTIC_FINDING,
                severity=Severity.HIGH,
                title=f"Credential Alert / Reset Solicitation: {title}",
                description="The message requests password alteration, account credential verification, or claims an impending lockout.",
                evidence=f"Matched text: '...{snippet}...' in subject/body.",
                limitations="Legitimate IT notices also use this language; verification requires cross-referencing domain authentication.",
            ))
            human_review_reasons.append(f"Credential solicitation indicator: {title}.")

    # ---------------------------------------------------------
    # 4. Threatening and Coercive Language
    # ---------------------------------------------------------
    for pattern, title in COERCIVE_PATTERNS:
        match = re.search(pattern, full_content, re.IGNORECASE)
        if match:
            snippet = match.group(0)
            findings.append(Finding(
                id=f"ALERT-THREAT-COERCIVE-{title.replace(' ', '_').upper()}",
                dimension="THREAT",
                category=FindingCategory.HEURISTIC_FINDING,
                severity=Severity.MEDIUM,
                title=f"Coercive / High-Pressure Language: {title}",
                description="Message incorporates urgency multipliers or punitive consequences to force immediate compliance.",
                evidence=f"Matched text: '...{snippet}...' in subject/body.",
                limitations="Psychological pressure tactics are standard in social engineering, but also occur in legitimate emergency communications.",
            ))
            human_review_reasons.append(f"Coercive urgency pattern: {title}.")

    # ---------------------------------------------------------
    # 5. Malformed / Conflicting Headers & Attachments
    # ---------------------------------------------------------
    if len(parsed.from_headers) > 1:
        findings.append(Finding(
            id="ALERT-THREAT-HEADER-INJECTION",
            dimension="THREAT",
            category=FindingCategory.HEURISTIC_FINDING,
            severity=Severity.CRITICAL,
            title="Multiple RFC 5322 From Headers (Possible Exploitation)",
            description="The message includes more than one From header, which is an explicit protocol violation.",
            evidence=f"Total From headers: {len(parsed.from_headers)}",
            limitations="Frequently associated with parser differential exploitation across security gateways and email clients.",
        ))
        human_review_reasons.append("RFC 5322 violation: Multiple From headers detected.")

    if parsed.reply_to_domain and parsed.claimed_domain:
        if parsed.reply_to_domain.lower() != parsed.claimed_domain.lower():
            findings.append(Finding(
                id="ALERT-THREAT-REPLY-TO-MISMATCH",
                dimension="THREAT",
                category=FindingCategory.HEURISTIC_FINDING,
                severity=Severity.MEDIUM,
                title="Reply-To Domain Differs from From Domain",
                description=(
                    f"Replies are routed to domain '{parsed.reply_to_domain}', differing from "
                    f"the sender domain '{parsed.claimed_domain}'."
                ),
                evidence=f"From: {parsed.claimed_address} | Reply-To: {parsed.reply_to}",
                limitations="Common in legitimate customer support desks and CRM platforms, but also used in BEC to redirect replies to attacker mailboxes.",
            ))

    for att in parsed.attachments:
        fname = att.get("filename", "").lower()
        for ext in DANGEROUS_EXTENSIONS:
            if fname.endswith(ext):
                findings.append(Finding(
                    id=f"ALERT-THREAT-DANGEROUS-ATTACHMENT-{ext.replace('.', '').upper()}",
                    dimension="THREAT",
                    category=FindingCategory.HEURISTIC_FINDING,
                    severity=Severity.HIGH,
                    title=f"Potentially Dangerous Attachment Type: '{ext}'",
                    description=f"Attachment '{att.get('filename')}' uses an executable, script, or macro-enabled format.",
                    evidence=f"Attachment: {att.get('filename')} (Type: {att.get('content_type')}, Size: {att.get('size_bytes')} bytes)",
                    limitations="The prototype inspects file extensions only; it does not detonate files or perform static binary disassembly.",
                ))
                human_review_reasons.append(f"Potentially executable or script attachment detected: {fname}.")

    # ---------------------------------------------------------
    # 6. Overall Severity and Review Determination
    # ---------------------------------------------------------
    severities = [f.severity for f in findings]

    if Severity.CRITICAL in severities:
        overall_level = "CRITICAL"
        title = "Critical Threat Indicators Detected"
        desc = "High-consequence attack vectors or protocol exploitation signatures observed."
        review_required = True
    elif Severity.HIGH in severities:
        overall_level = "HIGH"
        title = "High Severity Threat Indicators Detected"
        desc = "Substantial indicators of credential phishing, display-name spoofing, or financial fraud."
        review_required = True
    elif Severity.MEDIUM in severities:
        overall_level = "MEDIUM"
        title = "Medium Severity / Ambiguous Indicators"
        desc = "Noticeable anomalies, suspicious links, or psychological urgency markers present."
        review_required = True
    else:
        overall_level = "LOW"
        title = "No Obvious Threat Indicators Detected"
        desc = "No overt financial requests, known deceptive display patterns, or malicious links identified."
        review_required = False

    score = DimensionScore(
        level=overall_level,
        title=title,
        description=desc,
        rationale=(
            f"Severity follows the highest severity among {len(findings)} deterministic threat finding(s); "
            "this is not a calibrated probability or a sum of findings. "
            "IMPORTANT: Absence of detected indicators does NOT establish that a message is safe."
        ),
        is_simulated_or_limited=False,
    )

    return score, findings, review_required, human_review_reasons
