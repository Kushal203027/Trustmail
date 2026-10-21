# TrustMail: System Vision and Foundation Requirements

**Document Version:** 1.0.0  
**Phase:** 1 — Foundation and Security Requirements  
**Classification:** Engineering Specification / Architecture Document  
**Status:** Approved for Foundation Engineering  

---

## 1. Mission Statement

TrustMail is an open, software-only cybersecurity architecture designed to restore foundational trust, accountability, and verifiable authenticity to digital messaging without compromising individual privacy or breaking global interoperability. 

TrustMail rejects the industry convention of treating email security as a reactive heuristic game of pattern matching and heuristic spam/phishing filtering. Instead, TrustMail engineers an authoritative, multi-dimensional verification architecture that decouples identity assurance, message authenticity, sender trust, and threat assessment—delivering tamper-evident evidence preservation, fail-safe incident response, and privacy-preserving sender attestation capable of integrating natively with standard Internet mail systems.

---

## 2. Problem Statement

### 2.1 The Architectural Flaw of Store-and-Forward Messaging
The global email ecosystem remains rooted in RFC 821 (1982) and its successor RFC 5321 (Simple Mail Transfer Protocol - SMTP). Designed for a small, cooperative academic and governmental network (ARPANET), SMTP was constructed on implicit trust:
1. **Decoupled Envelopes and Payloads:** SMTP fundamentally separates the transport envelope (`RFC 5321.MailFrom` / Return-Path) from the presentation payload (`RFC 5322.From` / Header From displayed to users). This architectural decoupling enables trivial display impersonation.
2. **Absence of Native Identity Attestation:** SMTP possesses no native mechanism to verify whether the entity transmitting a bitstream has any legitimate authority to represent the human or organization identified in the message body.
3. **Store-and-Forward Indirection:** Emails traverse an arbitrary sequence of intermediate Mail Transfer Agents (MTAs). Intermediate relays can rewrite headers, modify content, expand mailing lists, or inject malicious payloads without breaking downstream transport delivery.

### 2.2 The Inadequacy of Existing Overlay Protocols
Industry overlays developed over the last two decades (SPF, DKIM, DMARC) provide valuable but structurally incomplete protections:
- **Sender Policy Framework (SPF, RFC 7208):** Authenticates only the envelope sender IP against DNS records; it does not protect the display header `From:`, breaks under legitimate message forwarding, and validates servers, not human senders.
- **DomainKeys Identified Mail (DKIM, RFC 6376):** Provides cryptographic integrity for selected headers and message bodies against a domain key. However, DKIM keys authenticate domain tenancy, not individual sender identity. Furthermore, DKIM signatures are vulnerable to replay attacks, fragile canonicalization breakage, and do not attest to the benign nature of the content.
- **Domain-based Message Authentication, Reporting, and Conformance (DMARC, RFC 7489 / RFC 9686):** Enforces alignment between the `RFC 5322.From` domain and the SPF/DKIM validated domains. While critical against direct domain spoofing, DMARC provides zero protection against:
  - Compromised legitimate corporate accounts (Account Takeover - ATO).
  - Lookalike / homoglyph domains (e.g., `micros0ft.com` or internationalized domain name attacks).
  - Malicious free-mail accounts (e.g., Gmail, Yahoo) targeting organizations.
  - Impersonation via display names (e.g., `"CEO Name" <attacker@throwaway.org>`).

### 2.3 The Conflation Crisis in Modern Email Security
Contemporary Email Security Gateways (ESGs) and Integrated Cloud Email Security (ICES) platforms introduce severe operational vulnerabilities by conflating distinct dimensions of communication security:
- **Conflating Authenticity with Safety:** Traditional systems often treat an email with valid SPF, DKIM, and DMARC as "safe", allowing Business Email Compromise (BEC) and compromised vendor attacks to bypass perimeter filters.
- **Conflating Anonymity with Malice:** Unauthenticated or first-time senders (e.g., whistleblowers, new clients, personal inquiries) are aggressively penalized or discarded by statistical filters, crippling legitimate communication.
- **The Black-Box AI Dismissal Risk:** Deep learning and natural language processing models deployed in email security generate probabilistic threat scores. When these systems classify a sophisticated, low-signal attack (e.g., zero-day social engineering, prompt injection, subtle invoice fraud) as "low risk", security operations teams are completely blinded. High-impact threats are silently dismissed without deterministic audit trails or human recourse.
- **Ephemerality and Lack of Evidentiary Integrity:** Existing gateways modify, strip, or quarantine emails in proprietary databases without cryptographic chain-of-custody tracking. When an incident occurs, digital forensics and incident response (DFIR) teams discover that raw RFC 5322 artifacts, transport metadata, DNS states at time-of-delivery, and gateway decisions were either destroyed, modified, or stored in non-admissible formats.

---

## 3. Long-Term Vision

TrustMail engineers a principled, defensible, and transparent security architecture that transforms email from an unverified transport medium into an accountable communication network:

```
+---------------------------------------------------------------------------------------+
|                                    TRUSTMAIL VISION                                   |
+---------------------------------------------------------------------------------------+
|  1. MULTI-TIERED IDENTITY ASSURANCE                                                   |
|     Cryptographic, verifiable sender identity ranging from anonymous integrity        |
|     to organizational attestation and verified individual credentials (W3C VC/DID).   |
+---------------------------------------------------------------------------------------+
|  2. ORTHOGONAL SECURITY EVALUATION                                                    |
|     Strict separation of Identity Assurance, Message Authenticity, Threat Severity,  |
|     and Historical Sender Trust.                                                      |
+---------------------------------------------------------------------------------------+
|  3. DETERMINISTIC AND AI-ASSISTED THREAT TRIAGE                                       |
|     AI serves strictly as a transparent triage assistant and hypothesis generator;   |
|     AI predictions can NEVER unilaterally dismiss high-severity or high-anomaly alerts|
+---------------------------------------------------------------------------------------+
|  4. TAMPER-EVIDENT EVIDENCE PRESERVATION                                              |
|     Immutable, RFC 3161-timestamped, cryptographic chain-of-custody ledgers for every |
|     processed message, security assertion, and incident escalation.                   |
+---------------------------------------------------------------------------------------+
|  5. SEAMLESS BACKWARD-COMPATIBLE INTEROPERABILITY                                     |
|     Software-only integration via SMTP Milters, MX Proxies, and Mailbox APIs          |
|     (Microsoft Graph, Google Workspace), requiring no custom client software.         |
+---------------------------------------------------------------------------------------+
```

---

## 4. Target Users and Operational Contexts

TrustMail addresses the specific operational demands of four primary stakeholder categories:

| Stakeholder Category | Operational Needs and Context | Primary Value Delivered |
| :--- | :--- | :--- |
| **Enterprise Security Operations Centers (SOC) & DFIR Teams** | Triaging thousands of daily alerts; investigating BEC, supply-chain fraud, and targeted spear-phishing. | Forensically sound message artifacts, transparent audit trails, deterministic rule gating, and elimination of silent AI dismissals. |
| **Regulated Organizations (Finance, Healthcare, Legal, Gov)** | Complying with strict evidentiary, confidentiality, and data retention standards (e.g., SEC, HIPAA, FINRA, GDPR). | Legally defensible chain of custody, verifiable time-stamping, audit logs, and granular access control over preserved communications. |
| **Enterprise Knowledge Workers & End Users** | Making daily trust decisions regarding urgent vendor invoices, executive requests, and unfamiliar external contacts. | Contextual, unambiguous security indicators that distinguish domain identity from human identity without cognitive overload or alarm fatigue. |
| **External Senders, Partners, & Whistleblowers** | Transmitting critical information without being forced to dox personal identities or risk arbitrary spam quarantine. | Privacy-preserving sender attestation (zero-knowledge credential verification) and verifiable reputation mechanisms. |

---

## 5. Architectural and Safety Principles

TrustMail adheres to six non-negotiable architectural axioms:

### Principle 1: Explicit Orthogonality
Under no circumstances shall the system combine Identity Assurance, Message Authenticity, Sender Trust, and Threat Severity into a single scalar "trust score":
$$\text{Security Assessment} \neq f(\text{single score})$$
$$\text{Security Assessment} = \langle \text{Identity Assurance}, \text{Message Authenticity}, \text{Threat Severity}, \text{Sender Trust} \rangle$$
An email may possess Level 4 verified individual identity (e.g., an executive) and Level 4 cryptographic authenticity (valid S/MIME signature), yet represent Level 4 critical threat severity (compromised key, extortion, or active insider threat).

### Principle 2: Asymmetric Safety (Non-Equivalence Axiom)
- **Unknown $\neq$ Malicious:** A sender with zero historical reputation or unverified real-world identity must be treated as *unverified*, not as an adversary. Legitimate anonymous whistleblowing, cold professional outreach, and privacy-conscious communications must be preserved.
- **Verified $\neq$ Harmless:** A cryptographically authenticated, organizational-verified sender must never bypass threat inspection. The highest rates of catastrophic financial loss occur through authenticated accounts (Account Takeover, vendor compromise, insider threats).

### Principle 3: Non-Autonomous Dismissal (Fail-Safe Gating)
No probabilistic model (heuristic, statistical, or neural AI) is permitted to automatically dismiss, archive, or suppress a communication if deterministic threat rules, high-consequence keywords, anomalous financial requests, or cryptographic invalidations trigger a threat flag. AI may *escalate* or *enrich* an investigation, but human oversight is mandatory for dismissal of high-severity risks.

### Principle 4: Privacy by Design and Proportional Disclosure
Universal disclosure of real-world legal identity is antithetical to human rights, whistleblower protection, and global privacy frameworks (GDPR Art. 5(1)(c) Data Minimization). TrustMail establishes verifiable trust through cryptographic proofs (e.g., selective disclosure, pseudonymous domain tenancy, verifiable credentials) without requiring senders to transmit government identifiers to receiving parties.

### Principle 5: Evidentiary Rigor and Forensic Integrity
A cryptographic hash alone does not prove authenticity, provenance, or chain of custody. True evidentiary integrity requires:
1. Canonical raw RFC 5322 MIME capture at ingest before gateway mutation.
2. Cryptographic binding of transport metadata (TLS cipher, connecting IP, HELO/EHLO, SMTP envelope).
3. Synchronized, independent RFC 3161 digital timestamping.
4. Tamper-evident append-only logging (Merkle tree / transparency log construction).
5. Strict, auditable cryptographic access controls governing evidence retrieval.

### Principle 6: Software-Only, Universal Interoperability
TrustMail enforces a strict software-only constraint. It does not require custom physical hardware, specialized client hardware dongles, or proprietary biometric sensors. Furthermore, it operates within standard Internet protocols:
- Compatible with standard MTAs (Postfix, Sendmail, Exim) via the Milter protocol.
- Compatible with cloud email environments (Microsoft 365, Google Workspace) via secure REST webhooks and Graph APIs.
- Compatible with standard email user agents (Outlook, Apple Mail, Thunderbird, Webmail) via standard headers, S/MIME, and standards-compliant visual indicators.

---

## 6. System Scope

### 6.1 In-Scope Capabilities
- **Ingest & Parsing:** Robust, standards-compliant parsing of RFC 5321 envelopes, RFC 5322 headers, and MIME multipart payloads with strict handling of malformed and adversarial encodings.
- **Multi-Layer Identity Engine:** Independent evaluation of Claimed Identity, Account Ownership, Domain Authentication (SPF/DKIM/DMARC/ARC), Organizational Verification (BIMI/Certificates), and Individual Identity (S/MIME, OpenPGP, Verifiable Credentials).
- **Dual-Track Threat Assessment Engine:**
  - *Track A: Deterministic Rule Engine:* Cryptographic verification, DMARC alignment, structural syntax checks, known IOC matching, domain age calculation, and high-consequence keyword gating.
  - *Track B: Probabilistic AI Analysis:* Multi-modal semantic analysis, behavioral anomaly detection, and contextual relationship mapping with strict explainability.
- **Evidence Preservation Core:** WORM (Write Once, Read Many) compatible evidence archiving, cryptographic hashing, RFC 3161 timestamping, and Merkle-tree based audit logging.
- **Incident Response & Investigation Interfaces:** Structured incident schema, threat escalation workflows, human-in-the-loop triage gates, and forensic export modules (aligned with ISO/IEC 27037).

### 6.2 Out-of-Scope (Explicit Exclusions)
- **Physical Hardware & IoT:** No hardware tokens, biometrics scanners, smartcards, or physical appliance requirements.
- **Proprietary Closed Walled Gardens:** No custom proprietary transport protocol that refuses federation with standard Internet SMTP.
- **Autonomous Unsupervised Threat Dismissal:** No "auto-clean" or "auto-dismiss" feature powered solely by opaque machine learning classifiers.
- **Universal Identity Mandates:** No architectural assumption requiring every Internet email user to submit government KYC documentation.

---

## 7. Success Criteria

The TrustMail architecture will be evaluated against rigorous engineering benchmarks:

1. **Deterministic False-Dismissal Rate:** $0.0\%$ automated dismissal of high-consequence threat indicators (financial diversion, credential harvesting, unauthorized execution instructions).
2. **Identity-Authenticity Orthogonality:** $100\%$ of processed messages must yield distinct, independently queryable ratings for Identity Assurance, Message Authenticity, Sender Trust, and Threat Severity.
3. **Forensic Admissibility Compliance:** Preserved evidence records must meet the integrity requirements of ISO/IEC 27037 (Digital Evidence Handling) and NIST SP 800-86.
4. **Zero Header-Mutation Corruption:** Zero unintended alteration of upstream RFC 5322 MIME structures or breakage of preexisting valid DKIM signatures during pipeline transit.
5. **Privacy and Data Minimization:** Preservation and analysis pipelines must support automated redaction/pseudonymization of sensitive PII in audit logs while maintaining cryptographic integrity proofs.
6. **Interoperability Verification:** Fully functional verification pipelines operating over standard Postfix milter streams and Microsoft 365 / Google Workspace API message streams.
