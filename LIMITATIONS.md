# TrustMail: Prototype Limitations and Verification Boundaries

**Document Version:** 1.0.0  
**Phase:** 1 — Milestone 2 Prototype  
**Classification:** Engineering Transparency & Assurance Notice  

---

## 1. Explicit Architectural Limitations

In adherence to TrustMail engineering principles, this document provides an honest, comprehensive account of features that are simulated, incomplete, or not independently verified in this initial prototype.

### 1.1 Live Protocol & Domain Authentication Checks
- **No Live DNS Lookups:** This prototype does **not** perform live external DNS queries to resolve SPF (`TXT`) records, DKIM public keys (`selector._domainkey.domain`), DMARC policies (`_dmarc.domain`), or DNSSEC validation chains.
- **Untrusted In-Band Authentication Headers:** Any `Authentication-Results` or `Received-SPF` headers present in submitted messages are treated strictly as **`UNVERIFIED_CLAIM`** structures. In an untrusted email stream, any upstream adversary or intermediate relay can inject fabricated `Authentication-Results: dkim=pass` headers. TrustMail explicitly refuses to elevate identity assurance levels based on unverified header claims alone.
- **Simulated / Baseline T-IAL Rating:** Because live cryptographic key retrieval and certificate verification are out of scope for this offline vertical slice, all external messages are assigned `T-IAL 0 (Unverified / Anonymous)` with an explicit `is_simulated_or_limited: true` flag.

### 1.2 Cryptographic Evidence & Chain of Custody
- **A Hash is Not a Complete Chain of Custody:** While TrustMail computes an exact SHA-256 digest over the original intake bytes, this hash proves **only** that the stored or compared byte sequence has not altered since receipt.
- **No External RFC 3161 Time-Stamp Authority (TSA):** Timestamps recorded in the SQLite database reflect the local operating system clock (UTC ISO 8601). They are not countersigned by an independent, cryptographic Time-Stamp Authority.
- **Not Legally Admissible or Forensically Certified:** This prototype is a local research runtime. It must not be represented as a certified digital forensics tool (e.g., ISO/IEC 27037 or Federal Rules of Evidence Rule 902 compliant).
- **Local Tamper Detection Scope:** The `/api/incidents/{id}/verify-evidence` endpoint detects unauthorized file mutations on disk by comparing on-disk bytes to the intake hash. However, an attacker with administrative access to the underlying operating system could alter both the database record and the on-disk file simultaneously.

### 1.3 Threat Detection & Heuristic Limits
- **Keyword Detection Does Not Establish Intent:** Detection of words such as "wire transfer", "invoice", "password reset", or "legal action" does **not** prove that an email is malicious or fraudulent. Legitimate accounts payable departments, corporate IT teams, and legal counsel routinely use this vocabulary.
- **No Sandbox or Binary Detonation:** The prototype inspects attachment extensions (`.exe`, `.scr`, `.bat`, etc.) and MIME content types. It does **not** execute, disassemble, sandbox, or detonate attachments.
- **Absence of Indicators $\neq$ Harmless Message:** A message that triggers zero heuristic alerts receives a `TSR LOW` rating. This rating is accompanied by a mandatory safety warning: **Low indicator counts do not establish safety.** Highly targeted spear-phishing, novel zero-day exploits, and low-and-slow social engineering can evade deterministic lexical rules completely.
- **No AI / Machine Learning Engine (Milestone 3):** This prototype relies entirely on deterministic lexical, structural, and syntactic rules. No large language models (LLMs) or neural classifiers are incorporated in Milestone 2.

### 1.4 Sender Trust & Reputation Baselines
- **No External Threat Intelligence Feeds:** The prototype does **not** query external DNSBLs, Spamhaus, VirusTotal, MISP, or STIX/TAXII threat feeds.
- **Unestablished Trust $\neq$ Adversarial Intent:** Senders without historical records in the local SQLite database receive `STI 0: Unestablished / Unknown Sender Trust`. This is a neutral factual state, not an accusation of malice. First-time clients, whistleblowers, and legitimate partners will initially present as `STI 0`.

### 1.5 Integration & Mailbox Deployment
- **Local Web Application Only:** The prototype runs as a standalone FastAPI web application bound to `127.0.0.1:8000`. It is **not** currently integrated as an in-line MTA milter (Postfix/Exim) or as an API webhook with Microsoft 365 / Google Workspace.
- **No Outbound Email Delivery:** TrustMail currently acts as an inspection, analysis, and triage sink. It does not retransmit, relay, or inject messages into downstream mailboxes.

### 1.6 Local API, Data Protection & Evaluation
- **No Analyst Authentication:** Incident listing, detail retrieval, review changes, and evidence checks have no user authentication or role checks. The app binds to localhost by default; do not expose it to a network or use it as a shared analyst service.
- **Sensitive Metadata Persists:** Even when raw message retention is off, SQLite stores sender, subject, findings, and assessment data. The database is not encrypted at rest and has no built-in retention or deletion policy.
- **Bounded Upload Reads:** Uploaded files are read in chunks and rejected after the configured byte limit plus one byte. The ASGI server and multipart parser still receive and spool the HTTP request before this route processes the upload. Pasted JSON is also parsed by the web framework before the route can enforce the email byte limit.
- **Synthetic Evaluation Only:** `tests/fixtures/synthetic_emails.json` contains eight hand-labelled synthetic cases. The runner checks expected heuristic findings and review labels. Its false-positive/false-negative counts apply only to those labels and do not estimate operational accuracy.
- **Ledger Coverage Is Partial:** Structured parser observations currently cover suspicious URL findings and the display-name/address mismatch rules. Other findings remain unstructured; missing precise source spans are reported as unavailable.

---

## 2. Feature Status Summary Matrix

| Capability | Milestone 2 Prototype Status | Verification Mechanism / Reality |
| :--- | :--- | :--- |
| **RFC 5322 Ingress Parsing** | **IMPLEMENTED** | Validated via `email.message_from_bytes` and pytest suite. |
| **1 MB Input Size Limit** | **IMPLEMENTED** | Enforced at parser and FastAPI routes; verified by tests. |
| **Orthogonal Dimensions** | **IMPLEMENTED** | Four distinct dimensions (IAL, MAL, TSR, STI) output separately. |
| **Intake SHA-256 Fingerprint** | **IMPLEMENTED** | Verified against Python `hashlib.sha256`. |
| **Local Tamper Detection** | **IMPLEMENTED** | Verified via test mutating file bytes on disk. |
| **Epistemological Partitioning**| **IMPLEMENTED** | Findings split into Facts, Claims, Heuristics, Unknowns. |
| **Human Review Escalation** | **IMPLEMENTED** | Auto-escalates on high severity; review state machine active. |
| **Live DNS SPF/DKIM/DMARC** | **NOT IMPLEMENTED** | Headers treated as unverified claims; labeled as limited. |
| **External Threat Feeds** | **NOT IMPLEMENTED** | Reputation is evaluated against local baseline only. |
| **RFC 3161 TSA Timestamping**| **NOT IMPLEMENTED** | Uses local system UTC time; not an external TSA. |
| **AI Threat Triager** | **NOT IMPLEMENTED** | Reserved for Milestone 3; deterministic rules only. |
| **MTA Milter / Cloud Webhooks**| **NOT IMPLEMENTED** | Manual paste or `.eml` upload only; reserved for Milestone 5. |
