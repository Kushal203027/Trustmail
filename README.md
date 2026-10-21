# TrustMail — Prototype v0.1.0 (Milestone 2)

TrustMail is an open, software-only cybersecurity platform designed for structured email security analysis, evidence tracking, and human-reviewed incident triage.

This repository contains the **first working prototype** (Milestone 2) of the TrustMail architecture, implementing deterministic analysis, orthogonal identity and threat assessment, defensive email parsing, evidence integrity verification, and human-in-the-loop review workflows.

---

## 1. Key Principles

1. **Explicit Orthogonality:** Identity Assurance (T-IAL), Message Authenticity (MAL), Threat Severity (TSR), and Sender Trust (STI) are evaluated as independent dimensions. They are never combined into an arbitrary scalar "trust score".
2. **Asymmetric Safety:**
   - *Unknown sender $\neq$ Malicious.* Unverified senders are treated as neutral, not criminal.
   - *Verified identity $\neq$ Harmless.* Authenticated domains can be compromised (Account Takeover, BEC).
3. **Non-Autonomous Dismissal:** High-consequence indicators (financial changes, credential harvesting, protocol violations) mandate human analyst review. No automated rule or model can silently dismiss flagged communications.
4. **Epistemological Integrity:** Findings are strictly partitioned into Verified Facts, Unverified Claims, Heuristics, and Unknown Information.
5. **Privacy by Default:** Raw email byte streams are discarded immediately post-assessment unless explicit evidence retention is authorized.

---

## 2. Prerequisites

- Python 3.10 or higher (verified on Python 3.14).
- Commodity operating system (Windows, Linux, macOS).
- No external hardware tokens, smartcards, or physical sensors required.

---

## 3. Quickstart & Installation

### Step 1: Clone and Enter Directory
```bash
cd "kagada project"
```

### Step 2: Create and Activate Virtual Environment
On Windows (PowerShell):
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

On Linux / macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Run the Application
```bash
python main.py
```
Or with Uvicorn directly:
```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Open your browser and navigate to:
```
http://127.0.0.1:8000
```

---

## 4. Running the Automated Test Suite

TrustMail includes a comprehensive test suite across 10 functional and security areas:
```bash
pytest
```

Run the deterministic synthetic behavior evaluation with:

```powershell
python tests/run_synthetic_evaluation.py
```

It evaluates eight hand-labelled synthetic examples. Its counts describe agreement with those examples only and are not a measure of real-world accuracy.

### Test Coverage Areas
1. **Valid Email Parsing:** Single-part and multipart MIME structure extraction (`test_parser.py`).
2. **Malformed Email Handling:** Missing `From:` headers, multiple conflicting `From:` headers (RFC 5322 violation), missing `Date:`/`Message-ID:`, binary garbage (`test_malformed.py`).
3. **Input-Size Enforcement:** Strict 1 MB cap enforcement in parser and API endpoints (`test_size_limit.py`).
4. **Spoofed Display Names:** Embedded email mismatches and high-trust brand impersonation against webmail domains (`test_spoofed_display_name.py`).
5. **Untrusted Authentication Headers:** Categorization of in-band `Authentication-Results` as unverified claims (`test_auth_results.py`).
6. **Independent Assessment Dimensions:** Validation of 4-tuple orthogonality (`test_independent_dimensions.py`).
7. **Hash Consistency:** Exact SHA-256 reproducibility over identical byte sequences (`test_evidence_hash.py`).
8. **Tamper Detection:** Verification that modifying retained on-disk bytes triggers `TAMPER_DETECTED` (`test_tamper_detection.py`).
9. **Human-Review Escalation:** Automated review mandates on high severity and review state transitions (`test_human_review.py`).
10. **XSS & Hostile Content Isolation:** Safe handling and HTML escaping of `<script>`, `onerror`, and SVG injections (`test_xss_safety.py`).

---

## 5. Prototype Features & User Interface

The web interface (`http://127.0.0.1:8000`) provides a responsive, restrained cybersecurity console:
- **Ingress Panel:** Supports raw RFC 5322 text pasting or `.eml` drag-and-drop file upload with a live byte counter.
- **Pre-Packaged Scenarios:** One-click loading of realistic test vectors (Display-Name BEC, Credential Phishing, Malformed Headers, Clean Newsletter).
- **Four Orthogonal Dimension Cards:**
  - `T-IAL`: TrustMail Identity Assurance Level (T-IAL 0 through T-IAL 4-P).
  - `MAL`: Message Authenticity Level (MAL 0 through MAL 2).
  - `TSR`: Threat Severity Rating (LOW, MEDIUM, HIGH, CRITICAL).
  - `STI`: Sender Trust Index (STI 0 through STI 2).
- **Epistemological Filter Tabs:** Filter findings by *Verified Facts*, *Unverified Claims*, *Heuristic Findings*, and *Unknown Information*.
- **Decision Support & Triage:** View escalation triggers, update review status (`PENDING`, `UNDER_REVIEW`, `ESCALATED`, `DISMISSED`, `CONFIRMED_THREAT`), and record analyst notes.
- **Tamper Verification:** If evidence retention was enabled, click "Verify Retained Byte Integrity" to recompute SHA-256 over the on-disk file and prove tamper detection.
- **Incident History Log:** Browse, sort, and inspect past analyzed incidents stored in SQLite.

---

## 6. Project Documentation Directory

- **`VISION.md`**: Mission, problem statement, long-term architectural vision, safety principles, and success criteria.
- **`THREAT_MODEL.md`**: STRIDE threat model, adversary profiles, trust boundaries, attack scenarios, and mitigations.
- **`IDENTITY_SPEC.md`**: Specification of the 8 dimensions of identity, technical limitations, and the T-IAL framework.
- **`RESEARCH.md`**: Structured research plan across 11 technical domains, separating verified facts, hypotheses, and open questions.
- **`ARCHITECTURE.md`**: Detailed technical architecture, dataflow diagrams, and subsystem designs for the working prototype.
- **`LIMITATIONS.md`**: Honest account of simulated features, unverified headers, and explicit security boundaries.
- **`MILESTONES.md`**: Development milestones tracking progress from foundation to integration.

---

## 7. Security & Privacy Notice

TrustMail Prototype v0.1.0 is intended for local security evaluation and research:
- Binds strictly to `127.0.0.1` (localhost).
- Does not transmit telemetry, email contents, or user data to external cloud services or LLMs.
- Raw email bytes are discarded immediately unless explicit retention is toggled.
- Not a forensically certified tool; evidence hashes verify local byte consistency only and do not establish a complete chain of custody.
