# TrustMail Development Milestones

## Milestone 1: Security Foundation (Completed)

- [x] Define the threat model (`THREAT_MODEL.md`).
- [x] Identify assets and adversaries.
- [x] Document trust assumptions.
- [x] Define identity assurance levels (`IDENTITY_SPEC.md`).
- [x] Define security and privacy requirements (`VISION.md`, `RESEARCH.md`).

## Milestone 2: First Working Workflow (Current Iteration)

- [x] Accept a sample email (raw paste or `.eml` upload with strict 1MB limit).
- [x] Parse the message and headers defensively using Python standard libraries.
- [x] Extract available security indicators without executing content.
- [x] Perform supported deterministic checks (display name spoofing, suspicious URLs, urgency/coercion keywords, malformed headers, untrusted Auth-Results).
- [x] Produce a structured assessment across 4 orthogonal dimensions (Identity Assurance, Authenticity, Threat Severity, Sender Trust).
- [x] Preserve the original input bytes (compute SHA-256 evidence hash; optional explicit retention).
- [x] Create an incident record in SQLite with full audit events.
- [x] Support human-in-the-loop review escalation and status updates.

## Milestone 3: Threat Intelligence (Future)

- [ ] Integrate AI-assisted analysis as an advisory triage signal.
- [ ] Separate severity from identity assurance.
- [ ] Represent uncertainty explicitly with confidence intervals.
- [ ] Support human review queues and analyst annotation workflows.
- [ ] Evaluate false positives and false negatives against benchmark sets.

## Milestone 4: Security Engineering (Future)

- [ ] Implement role-based access controls and dual-authorization gates.
- [ ] Protect sensitive data with envelope encryption.
- [ ] Maintain an immutable audit trail using Merkle tree log construction.
- [ ] Test malformed and adversarial inputs with automated fuzzing.
- [ ] Validate evidence integrity with RFC 3161 Time-Stamp Authority integration.

## Milestone 5: Integration and Evaluation (Future)

- [ ] Evaluate email-provider integration options (Sendmail Milter, Microsoft Graph, Google Workspace).
- [ ] Test with representative datasets across enterprise workloads.
- [ ] Document production limitations.
- [ ] Conduct independent security review.
- [ ] Prepare a controlled deployment.
