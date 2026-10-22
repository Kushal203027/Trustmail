# TrustMail

### Explainable email threat assessment, with evidence behind every signal.

[**🚀 Live Demo — Open TrustMail**](https://trustmail.onrender.com)

TrustMail helps people investigate suspicious email with understandable evidence. It assesses **Identity, Authenticity, Threat, and Sender Trust** independently, then uses its **Evidence-to-Claim Ledger** to distinguish observed signals from rule-based interpretations and their limitations. It supports human investigation; it does not declare an email safe or a sender genuine.

> **For the hosted demo:** email is processed on the TrustMail server for the current response. In public demo mode, submitted messages and assessments are not saved to shared incident history. The demo does not sign visitors in or isolate results by visitor; please use synthetic or non-sensitive email only.

## Why TrustMail

Email warnings are often difficult to act on: a risk label may not show what was observed, why a rule reacted, or what remains unknown. TrustMail makes those distinctions visible. A parser-extracted fact, an email's own claim, a heuristic interpretation, and missing information are represented separately so reviewers can examine the reasoning instead of relying on an opaque overall score.

TrustMail does not combine its dimensions into a numeric confidence score. An unfamiliar sender is not automatically malicious, and a warning is a reason to investigate—not proof of malicious intent.

## What the assessment covers

Each analysis reports four dimensions independently:

| Dimension | What it describes |
| --- | --- |
| **Identity (T-IAL)** | What the email's sender fields claim and whether available identity signals are incomplete or inconsistent. A `From` header is a claim, not verified real-world identity. |
| **Authenticity (MAL)** | Message-level evidence such as an intake SHA-256 digest and the presence of signature-related headers. A digest supports byte comparison; it does not authenticate the sender. |
| **Threat (TSR)** | Deterministic indicators in message content and structure, including selected suspicious-link patterns, impersonation cues, explicit threat-like wording, pressure language, and attachment types. |
| **Sender trust (STI)** | Whether a sender trust baseline is established. The current analyzer reports this baseline as unestablished (`STI 0`) and does not query external reputation services; unknown is not malicious. |

### Evidence-to-Claim Ledger

The ledger separates **observed evidence** from the **rule/reference** and its interpretation. It also displays finding category, severity, limitations, and review guidance when available. Some selected findings include structured parser observations and source locations. Other findings show their available evidence text and identify when a structured observation or precise location is unavailable. This makes the current evidence boundary visible rather than implying every conclusion has the same level of traceability.

## Try it

- Paste RFC 5322 email text, or upload an `.eml` file (maximum input size: **1 MB**).
- Load a built-in synthetic sample to explore the workflow.
- Review the summary, four dimensions, and expandable Evidence-to-Claim Ledger.
- In local mode, inspect incident history and update review status. Optional original-byte retention enables a later SHA-256 comparison of the saved copy.

When original bytes are retained, the integrity check compares them with the intake SHA-256 reference digest. A mismatch can reveal byte changes since intake. This comparison does not prove sender identity or legal chain of custody. Review states record a human workflow decision; they do not make the system's conclusion true.

## Privacy and deployment modes

### Hosted public demo

The hosted demo uses `TRUSTMAIL_DEMO_MODE=true`. Analysis is performed by the TrustMail server and the result is returned to the browser, but submitted email, assessment metadata, and retained evidence are not written for the request. The shared history, incident detail, review update, and integrity-check endpoints are unavailable in this mode. There are no analyst accounts or per-visitor data partitions, so do not submit private email.

Enabling demo mode does not delete records that may already exist in the server's database or evidence directory; it disables the shared-record routes and prevents new analysis records from being saved. Deployment operators should review existing server storage separately.

### Local development

With demo mode unset or false, incident metadata and assessment results are stored in the local SQLite database. Original email bytes are stored only when the retention option is selected. The development server binds to `127.0.0.1` by default and has no analyst authentication; keep it on a trusted local machine. Do not expose local mode as a shared service.

The current version uses deterministic, rule-based analysis and does **not** run live SPF, DKIM, or DMARC verification. TrustMail may report that an `Authentication-Results` or `DKIM-Signature` header is present, but it does not validate those results against live DNS or cryptographic keys. Findings are indicators for human investigation, not proof of authenticity or malicious intent, and they cannot guarantee safety. Absence of a finding does not establish that an email is harmless.

## How it works

```text
Paste text / .eml upload
        ↓
FastAPI intake and defensive email parsing
        ↓
Identity · Authenticity · Threat · Sender Trust analyzers
        ↓
Structured assessment and findings
        ↓
Browser summary, dimensions, and Evidence-to-Claim Ledger
```

The browser uses plain HTML, CSS, and JavaScript. The Python/FastAPI service parses email, coordinates deterministic analyzers, and serves the API and static interface. In local mode, SQLite stores incident and review records; optional evidence retention stores original bytes for comparison. In public demo mode, analysis returns without saving new incident or evidence records. Dynamic email-derived values are rendered as text in the interface.

### Technology

- **Python 3.10+**, **FastAPI**, and **Uvicorn** for the application and API
- Python email parsing and **Pydantic** assessment models
- **SQLite** for local incident and review history
- Vanilla **HTML, CSS, and JavaScript** for the interface
- **pytest** and **HTTPX** for automated tests

## Run locally

### Requirements

- Python 3.10 or newer
- Git

### Setup

```bash
git clone https://github.com/Kushal203027/Trustmail.git
cd Trustmail
python -m venv .venv
```

Activate the environment:

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```bash
# macOS / Linux
source .venv/bin/activate
```

Install dependencies and start the local server:

```bash
python -m pip install -r requirements.txt
python main.py
```

Then open **http://127.0.0.1:8000**. This address is for local development; the hosted prototype is linked at the top of this README.

To run Uvicorn directly instead:

```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

## Run tests

Run the full automated suite from the repository root:

```bash
python -m pytest -q
```

The suite covers parsing and malformed input, request-size limits, assessment dimensions, threat indicators, evidence serialization, review and integrity workflows, demo-mode restrictions, and safe rendering. To run the small hand-labelled synthetic behavior check:

```bash
python tests/run_synthetic_evaluation.py
```

That script checks eight synthetic examples against expected findings. It is a development check, not a benchmark or estimate of real-world detection accuracy.

## Repository map

```text
main.py                         FastAPI entry point and static-file serving
trustmail/api/routes.py         Analysis, status, history, review, and integrity routes
trustmail/parser.py             Defensive email parsing
trustmail/analyzer/             Four analyzers, evaluator, and assessment models
trustmail/static/               HTML, CSS, and JavaScript interface
trustmail/db.py                 SQLite incident and review storage
trustmail/storage.py            Optional retained evidence and byte comparison
tests/                          Automated tests and synthetic evaluation
```

Additional design and security context is in [`ARCHITECTURE.md`](ARCHITECTURE.md), [`THREAT_MODEL.md`](THREAT_MODEL.md), [`LIMITATIONS.md`](LIMITATIONS.md), [`IDENTITY_SPEC.md`](IDENTITY_SPEC.md), and [`RESEARCH.md`](RESEARCH.md).

## Roadmap — planned, not implemented

- Add live SPF, DKIM, and DMARC verification with clear source and result provenance.
- Extend structured observation and source-location traceability across more finding types.
- Add authenticated analyst accounts and per-user incident separation before enabling shared history in a hosted service.
- Expand synthetic and independently reviewed evaluation cases, including false-positive analysis.

These are future directions; they are not current TrustMail capabilities.

## Project links

- [Live demo](https://trustmail.onrender.com)
- [GitHub repository](https://github.com/Kushal203027/Trustmail)
