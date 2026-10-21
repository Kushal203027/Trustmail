# TrustMail: Structured Cybersecurity Research Plan

**Document Version:** 1.0.0  
**Phase:** 1 — Foundation and Security Requirements  
**Classification:** Research Plan & Technical Literature Synthesis  
**Methodology:** Evidence-Based Cybersecurity Engineering  

---

## 1. Introduction and Research Framework

The objective of this research plan is to establish a rigorous, verified technical foundation for the TrustMail architecture. 

To maintain scientific and engineering integrity, all domain areas within this document are strictly partitioned into three distinct epistemological categories:
- **Verified Facts:** Principles, protocol constraints, cryptographic properties, and operational realities established by formal technical standards (IETF RFCs, W3C Recommendations, NIST Special Publications, ISO/IEC standards) and empirically verified industry data.
- **Hypotheses:** Testable engineering propositions formulated for TrustMail's architectural design that require prototype validation, empirical measurement, or simulation.
- **Open Questions:** Unresolved trade-offs, theoretical tensions, or operational challenges that require active investigation during Phase 1 and Phase 2.

---

## 2. Topic Area 1: SMTP and Core Email Architecture

### 2.1 Authoritative References
- **RFC 5321:** Simple Mail Transfer Protocol (SMTP).
- **RFC 5322:** Internet Message Format (IMF).
- **RFC 2045–2049:** Multipurpose Internet Mail Extensions (MIME).
- **RFC 6530–6533:** Internationalized Email (SMTPUTF8).

### 2.2 Verified Facts
1. SMTP fundamentally separates the transport envelope (`RFC 5321.MailFrom`, Return-Path) from the presentation payload (`RFC 5322.From`). Mail Transfer Agents (MTAs) route messages based solely on the envelope, while Mail User Agents (MUAs / email clients) display the presentation header.
2. The `RFC 5322.From` header can be populated with arbitrary text without triggering transport-layer rejection by standard MTAs.
3. SMTP is a hop-by-hop, store-and-forward protocol. Each intermediate MTA prepends a `Received:` header. However, headers prepended by untrusted upstream relays prior to the first trusted MTA can be fabricated or manipulated by adversaries.
4. MIME payloads allow arbitrary nested multipart hierarchies. Different email clients employ disparate parsing algorithms for boundary handling, malformed headers, and charset decoding, enabling MIME-smuggling and differential rendering attacks.

### 2.3 Hypotheses
- **H-1.1:** Parsing and normalizing raw RFC 5322 streams into an immutable, canonical Abstract Syntax Tree (AST) at the earliest ingestion point prevents downstream MIME confusion and parser-differential exploits.
- **H-1.2:** Capturing transport-layer connection metadata (TLS cipher suite, source IP, reverse DNS, HELO/EHLO handshake) at ingress and cryptographically binding it to the parsed MIME AST provides sufficient context to detect 95%+ of transport-level relay spoofing.

### 2.4 Open Questions
- **Q-1.1:** How can TrustMail reliably normalize messages containing non-standard or malformed internationalized headers (RFC 6532) without corrupting existing DKIM signatures that signed the non-canonical byte stream?
- **Q-1.2:** What memory and execution timeouts must be enforced during MIME AST generation to protect the gateway against recursive MIME zip-bombs without dropping legitimate, heavily nested corporate correspondence?

---

## 3. Topic Area 2: Domain Authentication (SPF, DKIM, DMARC, ARC)

### 3.1 Authoritative References
- **RFC 7208:** Sender Policy Framework (SPF).
- **RFC 6376:** DomainKeys Identified Mail (DKIM) Signatures.
- **RFC 7489 / RFC 9686:** Domain-based Message Authentication, Reporting, and Conformance (DMARC / DMARCbis).
- **RFC 8617:** Authenticated Received Chain (ARC).
- **RFC 8601:** Authentication-Results Header Field.

### 3.2 Verified Facts
1. **SPF Limitations:** SPF authenticates the `RFC 5321.MailFrom` IP against DNS TXT records. It does not validate `RFC 5322.From`. Furthermore, standard email forwarding breaks SPF because the forwarding server's IP is rarely listed in the original sender's SPF record.
2. **DKIM Limitations:** DKIM binds an email's body and selected headers to a domain name using public-key cryptography. DKIM does not bind the message to a specific human user or mailbox. DKIM signatures are vulnerable to replay attacks if an attacker intercepts a signed message and retransmits it to different recipients.
3. **Canonicalization Fragility:** DKIM canonicalization algorithms (`relaxed` vs `simple`) are fragile; benign MTA modifications (footer additions, trailing whitespace stripping, character re-encoding) break body hash (`bh=`) verification.
4. **DMARC Scope:** DMARC enforces identifier alignment between the `RFC 5322.From` domain and the domains authenticated via SPF and/or DKIM. DMARC provides zero protection against display name spoofing, homoglyph domain impersonation, or legitimate compromised accounts within the domain.
5. **ARC Mechanics:** ARC preserves authentication state across intermediaries by sealing previous `Authentication-Results`. However, ARC requires downstream receivers to explicitly trust the ARC Seal (`as=`) of the intermediate forwarders.

### 3.3 Hypotheses
- **H-2.1:** Evaluating DKIM signature parameters (specifically disallowing the obsolete `l=` length tag and enforcing over-signing of critical headers like `Subject`, `To`, `From`, `Date`, and `Message-ID`) deterministically mitigates DKIM body-append and replay manipulation.
- **H-2.2:** Maintaining an active reputation and integrity ledger of intermediate forwarders allows ARC validation to function reliably without blindly trusting rogue third-party sealers.

### 3.4 Open Questions
- **Q-2.1:** What is the empirical latency overhead of executing multi-hop ARC validation and DNSSEC-validated DNS lookups on high-throughput email streams (e.g., 500+ messages/second)?
- **Q-2.2:** When SPF passes but DKIM fails due to forwarding-induced whitespace mutation, what deterministic thresholds should govern whether the message is demoted from T-IAL 2 to T-IAL 1?

---

## 4. Topic Area 3: Federated Identity and Web Authentication

### 4.1 Authoritative References
- **OpenID Connect Core 1.0** (OpenID Foundation).
- **RFC 6749:** The OAuth 2.0 Authorization Framework.
- **W3C Web Authentication (WebAuthn):** Level 3 / FIDO2.
- **NIST SP 800-63-3 / SP 800-63C:** Digital Identity Guidelines: Federation and Assertions.

### 4.2 Verified Facts
1. Federated identity protocols (OIDC/SAML) authenticate users to identity providers (IdPs) and issue signed assertions (JWTs/SAML tokens) to relying parties (RPs).
2. Modern enterprise mail systems (Microsoft 365, Google Workspace) use OAuth 2.0 / OIDC for mail submission (SMTP AUTH via XOAUTH2) and API access.
3. An OAuth token confirms that the sending client authenticated to the mail server; it does not intrinsically sign the transmitted MIME payload or provide non-repudiation to external recipients.
4. Token theft via session hijacking, adversary-in-the-middle (AiTM) phishing proxies (e.g., Evilginx), or compromised OAuth application consents bypasses multi-factor authentication (MFA) and grants attackers programmatic email access.

### 4.3 Hypotheses
- **H-3.1:** Integrating internal enterprise email submission with short-lived, sender-scoped cryptographic assertions (derived from OIDC identity tokens) allows internal recipients to verify exact mailbox origin without full S/MIME certificate infrastructure.
- **H-3.2:** WebAuthn/FIDO2 hardware-bound credentials can be used in software-only architectures to authorize administrative operations, evidence access, and policy changes within the TrustMail management plane.

### 4.4 Open Questions
- **Q-3.1:** Can federated identity claims be standardized across disparate email tenants without creating a centralized surveillance point or vendor lock-in?
- **Q-3.2:** How can cross-organization federated identity assertions be validated when relying parties have no pre-existing trust relationship with the sender's IdP?

---

## 5. Topic Area 4: Digital Signatures and Public-Key Cryptography

### 5.1 Authoritative References
- **RFC 8551:** Secure/Multipurpose Internet Mail Extensions (S/MIME) Version 4.0.
- **RFC 4880 / RFC 9580:** OpenPGP Message Format.
- **RFC 7672:** SMTP Security via Opportunistic DANE TLS.
- **RFC 8461:** Mail Transfer Agent Strict Transport Security (MTA-STS).
- **RFC 9162:** Certificate Transparency Version 2.0.

### 5.2 Verified Facts
1. S/MIME provides end-to-end cryptographic integrity, authentication, and confidentiality using hierarchical X.509 public key infrastructure (PKI).
2. OpenPGP provides similar cryptographic capabilities via a decentralized "Web of Trust" or direct key exchange.
3. Both S/MIME and PGP have suffered near-universal adoption failure in consumer email and limited adoption in enterprise email due to:
   - Severe key lifecycle and distribution friction (private key migration across mobile/desktop, key backup).
   - Inability of gateway security filters to inspect encrypted payloads without escrowing private keys.
   - Leakage of critical metadata (Subject, From, To, Date, and thread headers remain unencrypted in standard S/MIME and OpenPGP).
   - Certificate revocation latency and failures (OCSP/CRL checking frequently fails open in email clients).
4. S/MIME certificates bind an identity to an email address, but standard Class 1/2 certificates verify only email control, not legal human identity. Only Class 3/4 certificates verify real-world legal identity.

### 5.3 Hypotheses
- **H-4.1:** Separating digital signing of message *integrity and authenticity* from payload *encryption* allows gateway security engines to inspect content while preserving non-repudiation and high identity assurance.
- **H-4.2:** Publishing sender public keys via DNS DANE (RFC 7672 / RFC 7929 SMIMEA / OPENPGPKEY) backed by DNSSEC provides an automated, zero-touch public key discovery mechanism that eliminates manual certificate exchange.

### 5.4 Open Questions
- **Q-4.1:** Given that DNSSEC deployment remains under 15% globally among commercial domains, what fallback trust discovery mechanisms can be securely deployed without introducing MITM vulnerabilities?
- **Q-4.2:** How should the system handle signature verification when a sender's certificate was valid at the precise moment of signing and transit, but revoked prior to forensic investigation?

---

## 6. Topic Area 5: Verifiable Credentials and Decentralized Identifiers

### 6.1 Authoritative References
- **W3C Recommendation:** Verifiable Credentials Data Model v2.0.
- **W3C Recommendation:** Decentralized Identifiers (DIDs) v1.0.
- **DIF / W3C:** `did:web` Method Specification.
- **NIST SP 800-63A:** Enrollment and Identity Proofing.

### 6.2 Verified Facts
1. W3C Verifiable Credentials (VCs) provide a standardized data format for expressing tamper-evident, cryptographically verifiable claims about an entity.
2. A VC contains claims issued by an Issuer, bound to a Subject, and cryptographically signed.
3. DIDs provide resolvable, globally unique identifiers that do not require a centralized registry (e.g., `did:web` leverages existing DNS and TLS infrastructure to publish DID Documents containing public keys).
4. Verifiable Credentials allow claims to be transported in application-layer protocols without requiring bilateral integration between the verifier and the issuer.

### 6.3 Hypotheses
- **H-5.1:** Embedding a lightweight, base64-encoded W3C Verifiable Credential in an email header (e.g., `TrustMail-Assertion:`) enables cryptographically verifiable organizational and professional claims without altering standard email transport.
- **H-5.2:** Using `did:web` (bound to the authenticated DMARC domain) enables zero-cost, standards-compliant public key resolution for organizational credential verification.

### 6.4 Open Questions
- **Q-5.1:** How can header-size constraints (RFC 5322 recommendations and practical MTA limits of 32KB–64KB total header size) accommodate cryptographically rich VC payloads and proof chains?
- **Q-5.2:** What standard revocation query mechanism (StatusList2021, Bitstring Status List) offers optimal performance and privacy when checking credential validity at wire speed?

---

## 7. Topic Area 6: Privacy-Preserving Identity Verification

### 7.1 Authoritative References
- **W3C VC Data Integrity BBS Cryptosuites v1.0.**
- **IETF RFC 9901 (Draft):** Selective Disclosure for JWTs (SD-JWT).
- **ISO/IEC 20008-2:** Anonymous Digital Signatures.
- **NIST SP 800-162:** Guide to Attribute Based Access Control (ABAC).

### 7.2 Verified Facts
1. Traditional identity verification (S/MIME, KYC registries) leaks complete legal names, addresses, and identifiers, creating severe tracking, surveillance, and whistleblower retaliation risks.
2. Zero-Knowledge Proofs (ZKPs) allow a prover to mathematically prove to a verifier that a statement is true without disclosing any information beyond the statement's validity.
3. BBS+ signatures and SD-JWT allow *selective disclosure*: an issuer can sign a set of attributes (e.g., `role: CFO`, `org: Acme Corp`, `clearance: Secret`, `legal_name: Jane Doe`), and the holder can present a cryptographic proof disclosing *only* `role: CFO` and `org: Acme Corp` while proving the credential was signed by the authoritative issuer, mathematically redacting `legal_name`.
4. Cryptographic proof verification is computationally asymmetric: generating complex ZK-SNARK proofs can require seconds of CPU time on the client, but verifying the resulting proof takes milliseconds on the gateway.

### 7.3 Hypotheses
- **H-6.1:** Selective disclosure credentials (SD-JWT or BBS+) can achieve Level 4-P Identity Assurance in email without disclosing the personal identity of the sender to either the recipient or intermediate relays.
- **H-6.2:** A software-only zero-knowledge proof verification module can execute within an MTA milter pipeline with an average processing latency under 15 milliseconds per message.

### 7.4 Open Questions
- **Q-6.1:** What is the minimal cryptographic proof payload size achievable for email headers without triggering header truncation by legacy intermediary MTAs?
- **Q-6.2:** How can trust in the *issuer* of a privacy-preserving credential be established without a centralized global trust list?

---

## 8. Topic Area 7: Email Security Gateways and Integration

### 8.1 Authoritative References
- **Sendmail Milter Protocol Specification.**
- **Postfix SMTP Access Policy Delegation & Milter Applications.**
- **Microsoft Graph API - Mail Ingestion / Security API.**
- **Google Workspace Gmail REST API.**
- **RFC 3207:** SMTP Service Extension for Secure SMTP over TLS.

### 8.2 Verified Facts
1. The Sendmail Milter protocol is the de facto standard for synchronous, real-time message filtering in open-source MTAs (Postfix, Sendmail, Exim), allowing inspection and modification of envelope, headers, and body during the SMTP dialogue.
2. In-line MTA gateways operate synchronously; if a milter hangs or crashes, it either causes connection timeouts (denial of service) or causes the MTA to "fail-open" (bypassing security) depending on the `milter_default_action` configuration.
3. Cloud mailboxes (Microsoft 365, Google Workspace) increasingly rely on out-of-band or API-based integration (Integrated Cloud Email Security - ICES) via webhooks and REST APIs.
4. API-based ingestion avoids inline MTA latency, but introduces a non-zero time-to-remediate (TTR) window (typically 2 to 30 seconds) during which a user can click a malicious link or read a malicious email before the API issues a quarantine call.

### 8.3 Hypotheses
- **H-7.1:** A dual-mode architecture that supports both synchronous MTA Milter filtering (for on-premises / perimeter MTAs) and asynchronous API webhooks (for Microsoft 365 / Google Workspace) ensures universal deployability across hybrid enterprise topologies.
- **H-7.2:** An asynchronous quarantine-at-ingress pattern in cloud mailboxes (using mail routing rules to hold messages in a staging folder until TrustMail API assessment completes) eliminates the TTR vulnerability window without requiring an inline MX change.

### 8.4 Open Questions
- **Q-7.1:** What are the exact rate-limit and throttling boundaries of the Microsoft Graph API and Google Workspace API during sustained high-volume phishing attacks (e.g., 50,000 incoming messages in 10 minutes)?
- **Q-7.2:** How can message integrity be preserved when cloud email APIs normalize, re-encode, or strip original RFC 5322 MIME structures upon ingestion?

---

## 9. Topic Area 8: Threat Intelligence and Adversarial ML Limitations

### 9.1 Authoritative References
- **STIX Version 2.1 / TAXII Version 2.1** (OASIS Standard).
- **MISP Threat Sharing Protocol & Data Model.**
- **NIST SP 800-150:** Guide to Cyber Threat Information Sharing.
- **MITRE ATT&CK for Enterprise:** Phishing (T1566) & Impersonation (T1656).

### 9.2 Verified Facts
1. Threat intelligence indicators of compromise (IOCs: hashes, IP addresses, malicious domains) have a rapid decay rate; adversaries deploy unique disposable domains and single-use URLs for targeted campaigns.
2. Behavioral indicators and intent analysis (IOAs: invoice modification requests, urgent gift card purchases, credential reset prompts) exhibit significantly longer operational half-lives than atomic IOCs.
3. Machine learning (ML) and Natural Language Processing (NLP) models are fundamentally probabilistic classifiers. They are subject to:
   - **Evasion Attacks:** Character substitution, homoglyphs, zero-width spaces, and base64 injection designed to alter token embeddings.
   - **Indirect Prompt Injection:** Adversarial instructions embedded in email bodies or HTML comments that hijack the reasoning of underlying LLMs.
   - **Distributional Shift:** Normal linguistic drift across organizations causes false-positive spikes.
4. **Authoritative Engineering Rule:** Machine learning models CANNOT reliably establish real-world identity from email prose alone, nor can they be trusted to autonomously dismiss high-severity threat alerts.

### 9.3 Hypotheses
- **H-8.1:** Structuring AI analysis strictly as an *advisory signal* that outputs structured threat hypotheses and explanations—while enforcing deterministic rule gating for containment—reduces analyst review time by 50% without introducing false-negative dismissals.
- **H-8.2:** Sanitizing incoming email text (stripping hidden HTML elements, zero-width characters, invisible CSS, and command-like delimiters) prior to model inference eliminates 90%+ of prompt injection vectors.

### 9.4 Open Questions
- **Q-8.1:** How can local, privacy-compliant NLP/LLM runtimes be optimized to run on commodity CPU infrastructure without requiring expensive GPU accelerators?
- **Q-8.2:** What formal schema best captures the uncertainty, rationale, and confidence bounds of an AI threat assessment for human SOC consumption?

---

## 10. Topic Area 9: Incident Response and Human-in-the-Loop Governance

### 10.1 Authoritative References
- **NIST SP 800-61 Rev. 3:** Computer Security Incident Handling Guide.
- **ISO/IEC 27035-1/2:** Information Security Incident Management.
- **CISA Incident Response Playbooks.**

### 10.2 Verified Facts
1. Alert fatigue is a primary operational cause of enterprise security failures; human analysts presented with high volumes of ambiguous, low-fidelity alerts suffer cognitive exhaustion and miss true positives.
2. Autonomous email security systems that automatically purge or quarantine emails without transparent explanations cause operational friction, leading business executives to request security bypasses or allow-listing of vulnerable domains.
3. The "Non-Autonomous Dismissal" principle is required in high-assurance environments: an automated system must never silently discard or declare safe any communication that triggers high-consequence indicators (e.g., changes to financial wire instructions, executive impersonation, or credential harvesting payloads).

### 10.3 Hypotheses
- **H-9.1:** Providing analysts with a multi-dimensional score (IAL, MAL, TSR, STI) accompanied by explicit evidence links (e.g., exact header mismatch, specific lexical trigger, DNSSEC status) reduces mean-time-to-triage (MTTT) by over 60%.
- **H-9.2:** Implementing a dual-analyst authorization gate for permanent deletion or release of high-severity quarantined messages prevents both insider threat exploitation and accidental compromise.

### 10.4 Open Questions
- **Q-9.1:** What human-interface design patterns minimize analyst cognitive load when inspecting complex cryptographic validation failures?
- **Q-9.2:** How can user-reported phishing submissions (via MUA add-in) be integrated into the TrustMail response pipeline without overwhelming analysts with false positives?

---

## 11. Topic Area 10: Evidence Integrity and Forensic Custody

### 11.1 Authoritative References
- **RFC 3161:** Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP).
- **ISO/IEC 27037:** Guidelines for Identification, Collection, Acquisition, and Preservation of Digital Evidence.
- **NIST SP 800-86:** Guide to Integrating Forensic Techniques into Incident Response.
- **RFC 6962:** Certificate Transparency (Merkle Tree Audit Proofs).

### 11.2 Verified Facts
1. **A Hash is Not a Complete Chain of Custody:** A cryptographic hash (e.g., SHA-256) proves that a byte sequence has not changed since the hash was generated. It does NOT prove:
   - When the hash was created (requires trusted timestamping).
   - Who generated the hash or had access to the data (requires access logging).
   - What the legal or operational provenance of the original artifact was (requires custodial records).
   - Whether the artifact was captured before or after modification by an intermediary (requires ingress capture).
2. For digital evidence to be admissible and defensible under ISO/IEC 27037 and legal standards (e.g., Federal Rules of Evidence Rule 902(13)/(14) in the US), evidence must be captured in its original raw state, verified via cryptographic hashes, tied to an independent, synchronized time source, and maintained in a tamper-evident log documenting every access and transfer.
3. Standard file systems and relational databases are mutable; administrators with root/DBA privileges can alter records and recalculate hashes without leaving a cryptographic trace unless append-only, tamper-evident data structures (such as Merkle trees or WORM storage) are enforced.

### 11.3 Hypotheses
- **H-10.1:** Constructing a cryptographic Merkle tree of incoming message hashes—where the root hash is periodically sealed via an external RFC 3161 Time-Stamp Authority (TSA)—provides mathematically irrefutable proof of message existence and immutability without requiring blockchain technology.
- **H-10.2:** Storing raw RFC 5322 message bytes in an envelope-encrypted, content-addressable storage format enables efficient deduplication, compliance with privacy regulations (GDPR "Right to be Forgotten" via cryptographic key erasure), and complete forensic fidelity.

### 11.4 Open Questions
- **Q-10.1:** How can an organization comply with GDPR Article 17 (Right to Erasure) if email hashes and evidence metadata are immutably committed to an append-only cryptographic ledger?
- **Q-10.2:** What is the storage expansion factor of preserving complete raw RFC 5322 artifacts and associated transport telemetry over a multi-year retention mandate?

---

## 12. Topic Area 11: Existing Standards and Competing Approaches

### 12.1 Authoritative References
- **BIMI (AuthIndicators Working Group / IETF Draft).**
- **IETF DANCE:** DNS-based Authentication of Named Entities (DANE) as a technology for Applications to Authenticate Named Entities.
- **IETF MLS (RFC 9420):** Messaging Layer Security.
- **ProtonMail / Tutanota Technical Whitepapers** (Zero-Access Encryption Architecture).

### 12.2 Comparative Analysis Matrix

| Technology / Standard | Primary Strengths | Critical Vulnerabilities / Limitations | Applicability to TrustMail |
| :--- | :--- | :--- | :--- |
| **BIMI (with VMC)** | Visual logo display in inbox; strong enforcement of DMARC `p=reject`; trademark verification via CAs. | High cost (\$1,000+/yr); accessible only to established corporations; trademark focus, not sender/human identity. | **Adopt as T-IAL 3 input:** Validates corporate trademark tenancy; does not establish human identity. |
| **S/MIME v4.0** | End-to-end encryption; individual digital signatures; enterprise CA management via Active Directory. | Key distribution failure; metadata unencrypted; gateway inspection blocked; complex mobile provisioning. | **Adopt verification support:** Gateway verifies signatures on ingress to award T-IAL 4 without forcing end-to-end encryption. |
| **OpenPGP** | Decentralized; no CA costs; strong open-source tooling. | Web of Trust is unscalable; zero revocation efficiency; metadata exposed; complex key management for non-technical users. | **Adopt verification support:** Gateway verifies clearsign signatures when present. |
| **Proprietary Encrypted Mail (Proton, Tuta)** | Seamless zero-access encryption between users on the same platform; strong privacy. | Walled garden; breaks when communicating with standard external SMTP; does not solve external BEC/phishing. | **Synthesize concepts:** Maintain compatibility with standard SMTP while adopting their cryptographic evidence protections. |
| **IETF MLS (RFC 9420)** | Modern asynchronous group key exchange; post-compromise security; forward secrecy. | Designed for real-time messaging (chat), not asynchronous, store-and-forward, federated email. | **Monitor for Future:** Potential long-term transport layer replacement, but outside current SMTP scope. |
| **IETF DANCE** | Leverages DANE/DNSSEC to authenticate application endpoints and client certificates. | Dependent on DNSSEC adoption; currently emerging working group status. | **Research Track:** Investigate for automated client certificate discovery without centralized CAs. |

---

## 13. Research Synthesis: Answering the Core Research Questions

### 1. Why can email senders communicate without establishing their real-world identity?
**Verified Answer:** SMTP (RFC 821/5321) was engineered in 1982 for a closed, cooperative network where nodes were implicitly trusted. It separated the transport envelope from the header presentation, and included no protocol-level requirement for identity verification, proof of authority, or cryptographic attestation.

### 2. What limitations exist in current email authentication and identity systems?
**Verified Answer:** SPF checks only the sending server IP and breaks under forwarding. DKIM authenticates domain key tenancy, not individual senders, and is vulnerable to replay and canonicalization breakage. DMARC enforces alignment with the header domain, but offers no defense against compromised accounts (ATO), display-name spoofing, or malicious domains registered by attackers. S/MIME and PGP failed to scale due to catastrophic key management UX and metadata leakage.

### 3. Can we establish stronger levels of sender assurance without requiring universal disclosure of personal identity?
**Verified Answer:** Yes. By adopting W3C Verifiable Credentials with Zero-Knowledge Proofs (ZKPs) or selective disclosure algorithms (SD-JWT, BBS+), a sender can prove authorized attributes (e.g., "Active Employee of Organization X", "Licensed Attorney") without revealing personal identifiers.

### 4. How should the system distinguish identity assurance, message authenticity, threat severity, and sender trust?
**Verified Answer:** By treating them as orthogonal dimensions of a 4-tuple evaluation vector ($\langle\text{IAL}, \text{MAL}, \text{TSR}, \text{STI}\rangle$). Each dimension is evaluated by distinct, dedicated engines and maintained independently in data schemas and user interfaces.

### 5. How can the system handle serious threats without allowing an AI prediction to automatically dismiss them?
**Verified Answer:** By enforcing a deterministic Non-Autonomous Dismissal Policy. High-consequence indicators (financial changes, credential requests, execution instructions, cryptographic failures) execute through deterministic safety gates. AI models serve strictly as explainable triage assistants and cannot override or dismiss a deterministic flag.

### 6. How should security evidence be preserved, verified, accessed, and audited?
**Verified Answer:** Raw RFC 5322 byte streams must be captured at ingress prior to gateway mutation. Integrity is preserved using content-addressable storage, external RFC 3161 timestamps, and append-only Merkle tree audit ledgers. Access is controlled via dual-key authorization and audited under ISO/IEC 27037 standards. Standalone hashing is explicitly rejected as insufficient for a chain of custody.

### 7. How can the architecture integrate with existing email providers without unnecessarily exposing sensitive data?
**Verified Answer:** Via standard Sendmail Milter interfaces for on-premises MTAs (Postfix/Exim) and least-privilege REST API webhooks for Microsoft 365 and Google Workspace. Sensitive payload data is redacted/pseudonymized in telemetry, and analysis occurs in isolated local runtimes or customer-controlled tenancies.

### 8. What security, privacy, usability, and interoperability limitations must be addressed?
**Verified Answer:** 
- *Security:* DKIM replay, account takeover, indirect prompt injection, parser denial-of-service.
- *Privacy:* Unmasking of whistleblowers, unauthorized SOC surveillance, cross-border data transfer violations.
- *Usability:* End-user alarm fatigue, complex key management, cognitive overload from confusing security indicators.
- *Interoperability:* Header size limits, mailing list modifications breaking signatures, cloud API throttling and format normalization.
