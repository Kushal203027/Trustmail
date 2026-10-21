/**
 * TrustMail: Email assessment workspace controller.
 * Implements strict XSS defense, multi-dimensional assessment rendering,
 * and human-in-the-loop review interactions.
 */

// Global State
let currentAssessment = null;
let currentIncidentId = null;
let currentFindingsFilter = "all";
let uploadedFileObject = null;
let demoMode = false;

// Build text nodes with textContent so untrusted email/API values stay inert.
function appendText(parent, tagName, value, className = "") {
  const element = document.createElement(tagName);
  if (className) element.className = className;
  element.textContent = value === null || value === undefined ? "" : String(value);
  parent.appendChild(element);
  return element;
}

function appendBadge(parent, label, className) {
  return appendText(parent, "span", label, `badge ${className}`);
}

function formatDate(value, options = {}) {
  if (!value) return "Unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unavailable" : date.toLocaleString(undefined, options);
}

async function getResponseError(response, fallback) {
  const body = await response.json().catch(() => ({}));
  return typeof body.detail === "string" ? body.detail : fallback;
}

// Built-in Realistic Test Scenarios
const SAMPLES = {
  bec_spoof: 
`From: "Sarah Connor - Chief Financial Officer" <payroll-update@secure-vendor-invoices.com>
To: accounting@company.com
Reply-To: executive-wire-desk@gmail.com
Subject: URGENT: Wire Transfer Routing Change - Vendor Invoice #8849
Date: Mon, 19 Oct 2026 09:15:00 +0000
Message-ID: <bec.88492026@secure-vendor-invoices.com>

Please update our vendor direct deposit banking details immediately.
The attached invoice requires a wire transfer payment within 24 hours.
Failure to comply will cause immediate project termination.
Swift Code: CHASEUS33
Do not contact anyone regarding this confidential executive update.`,

  credential_phish:
`From: "Microsoft Security Team" <alert-noreply@freemail-service.net>
To: employee@company.com
Subject: Critical Security Alert: Account Suspended Within 12 Hours
Date: Mon, 19 Oct 2026 11:20:00 +0000
Message-ID: <ms.alert.991@freemail-service.net>
Authentication-Results: mx.google.com; dkim=pass (unverified external claim)

Unauthorized access detected on your workstation.
Your account has been locked. To prevent permanent termination of service,
you must login immediately and verify your login credentials here:
http://192.168.1.105/auth/password-reset.php
Failure to verify your credentials will result in legal action.`,

  malformed_headers:
`From: "IT Helpdesk" <legit-admin@company.com>
From: "Shadow Admin" <attacker@evil-domain.org>
To: target@company.com
Subject: Quarterly Server Maintenance Schedule
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=company.com; s=mail; l=50; bh=Z3hz...; b=H1...

Please review scheduled server maintenance windows.
This message was signed with a deprecated body length tag.`,

  benign_newsletter:
`From: "Tech News Monthly" <editor@technews-bulletin.org>
To: subscriber@company.com
Subject: Monthly Open Source Security Summary - Issue #42
Date: Mon, 19 Oct 2026 14:00:00 +0000
Message-ID: <news.42@technews-bulletin.org>

Welcome to issue #42 of our monthly security bulletin.
In this edition, we review emerging IETF standards for email authentication
and the importance of decoupling identity assurance from message safety.
Read the full editorial on our community site: https://technews-bulletin.org/articles/issue-42`
};

// UI Initialization
document.addEventListener("DOMContentLoaded", () => {
  document.addEventListener("click", (event) => {
    const control = event.target.closest("[data-action]");
    if (!control) return;
    switch (control.dataset.action) {
      case "switch-view": switchView(control.dataset.view); break;
      case "switch-intake": switchIntakeMode(control.dataset.mode); break;
      case "load-sample": loadSample(control.dataset.sample); break;
      case "submit-analysis": submitAnalysis(); break;
      case "clear-intake": clearIntake(); break;
      case "save-review": submitReviewUpdate(); break;
      case "verify-evidence": verifyTamperIntegrity(); break;
      case "filter-findings": filterFindings(control.dataset.category); break;
      case "refresh-history": loadIncidentsList(); break;
      default: break;
    }
  });

  const rawInput = document.getElementById("raw-email-input");
  const byteCounter = document.getElementById("byte-counter");

  if (rawInput && byteCounter) {
    rawInput.addEventListener("input", () => {
      const bytes = new TextEncoder().encode(rawInput.value).length;
      byteCounter.textContent = `${bytes.toLocaleString()} bytes / 1,048,576 bytes limit (1 MB)`;
      if (bytes > 1048576) {
        byteCounter.classList.add("over-limit");
      } else {
        byteCounter.classList.remove("over-limit");
      }
    });
  }

  // Drop zone setup
  const dropZone = document.getElementById("drop-zone");
  const fileInput = document.getElementById("file-input");

  if (dropZone && fileInput) {
    dropZone.addEventListener("click", (event) => {
      if (event.target !== fileInput) fileInput.click();
    });
    dropZone.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        fileInput.click();
      }
    });
    dropZone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropZone.classList.add("drag-active");
    });
    dropZone.addEventListener("dragleave", () => {
      dropZone.classList.remove("drag-active");
    });
    dropZone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropZone.classList.remove("drag-active");
      if (e.dataTransfer.files.length > 0) {
        handleFileSelection(e.dataTransfer.files[0]);
      }
    });
    fileInput.addEventListener("change", () => {
      if (fileInput.files.length > 0) {
        handleFileSelection(fileInput.files[0]);
      }
    });
  }

  initializeWorkspace();
});

async function initializeWorkspace() {
  try {
    const response = await fetch("/api/status");
    if (!response.ok) throw new Error("Application status is unavailable.");
    const status = await response.json();
    demoMode = status.demo_mode === true;
  } catch (_error) {
    // Fail closed in the UI if it cannot confirm whether shared storage is enabled.
    demoMode = true;
  }

  if (demoMode) {
    document.getElementById("demo-mode-banner").classList.remove("hidden");
    document.getElementById("input-help").textContent = "In public demo mode, email is analyzed for this response only. Submitted messages and assessment details are not saved.";
    document.getElementById("retention-option").classList.add("hidden");
    document.getElementById("retain-evidence-checkbox").checked = false;
    document.getElementById("history-storage-label").textContent = "Disabled in public demo";
    document.getElementById("triage-actions").classList.add("hidden");
    document.getElementById("demo-review-note").classList.remove("hidden");
    document.getElementById("audit-trail-disclosure").classList.add("hidden");
  } else {
    loadIncidentsList();
  }
}

function handleFileSelection(file) {
  const errorBox = document.getElementById("submit-error");
  if (file.size === 0 || file.size > 1048576) {
    uploadedFileObject = null;
    document.getElementById("file-input").value = "";
    errorBox.textContent = file.size === 0
      ? "This file is empty. Choose an email file that contains message data."
      : "This file is larger than the 1 MB limit. Choose a smaller email file.";
    errorBox.classList.remove("hidden");
    document.getElementById("selected-file-info").classList.add("hidden");
    return;
  }
  errorBox.classList.add("hidden");
  uploadedFileObject = file;
  const info = document.getElementById("selected-file-info");
  if (info) {
    info.textContent = `Selected: ${file.name} (${file.size.toLocaleString()} bytes)`;
    info.classList.remove("hidden");
  }
}

// Navigation View Switching
function switchView(viewName) {
  const onAnalyze = viewName === "analyze";
  document.getElementById("tab-btn-analyze").classList.toggle("active", onAnalyze);
  document.getElementById("tab-btn-incidents").classList.toggle("active", !onAnalyze);
  document.getElementById("tab-btn-analyze").toggleAttribute("aria-current", onAnalyze);
  document.getElementById("tab-btn-incidents").toggleAttribute("aria-current", !onAnalyze);

  document.getElementById("view-analyze").classList.toggle("hidden", !onAnalyze);
  document.getElementById("view-incidents").classList.toggle("hidden", onAnalyze);
  document.getElementById("page-title").textContent = onAnalyze ? "Check an email" : "Incident history";

  if (viewName === "incidents") {
    loadIncidentsList();
  }
}

// Intake Mode Switching
function switchIntakeMode(mode) {
  document.getElementById("subtab-paste").classList.toggle("active", mode === "paste");
  document.getElementById("subtab-upload").classList.toggle("active", mode === "upload");
  document.getElementById("subtab-paste").setAttribute("aria-pressed", String(mode === "paste"));
  document.getElementById("subtab-upload").setAttribute("aria-pressed", String(mode === "upload"));

  document.getElementById("intake-paste-box").classList.toggle("hidden", mode !== "paste");
  document.getElementById("intake-upload-box").classList.toggle("hidden", mode !== "upload");
}

function loadSample(key) {
  if (SAMPLES[key]) {
    switchIntakeMode("paste");
    const input = document.getElementById("raw-email-input");
    input.value = SAMPLES[key];
    input.dispatchEvent(new Event("input"));
    document.getElementById("submit-error").classList.add("hidden");
  }
}

function clearIntake() {
  document.getElementById("raw-email-input").value = "";
  document.getElementById("raw-email-input").dispatchEvent(new Event("input"));
  uploadedFileObject = null;
  const fileInput = document.getElementById("file-input");
  if (fileInput) fileInput.value = "";
  document.getElementById("retain-evidence-checkbox").checked = false;
  switchIntakeMode("paste");
  const info = document.getElementById("selected-file-info");
  if (info) {
    info.textContent = "";
    info.classList.add("hidden");
  }
  document.getElementById("submit-error").classList.add("hidden");
  document.getElementById("analysis-status").textContent = "";
  document.getElementById("results-container").classList.add("hidden");
  currentAssessment = null;
  currentIncidentId = null;
}

// Submit Analysis to API
async function submitAnalysis() {
  const errBox = document.getElementById("submit-error");
  errBox.classList.add("hidden");
  errBox.textContent = "";

  const retainEvidence = document.getElementById("retain-evidence-checkbox").checked;
  const isUploadMode = document.getElementById("subtab-upload").classList.contains("active");

  const btn = document.getElementById("btn-submit-analyze");
  btn.disabled = true;
  btn.setAttribute("aria-busy", "true");
  btn.textContent = "Checking email…";
  document.getElementById("analysis-status").textContent = "Checking email. This may take a moment.";

  try {
    let response;

    if (isUploadMode) {
      if (!uploadedFileObject) {
        throw new Error("Please select or drop an .eml file to upload.");
      }
      const formData = new FormData();
      formData.append("file", uploadedFileObject);
      formData.append("retain_evidence", retainEvidence);

      response = await fetch("/api/analyze-file", {
        method: "POST",
        body: formData,
      });
    } else {
      const rawText = document.getElementById("raw-email-input").value;
      if (!rawText.trim()) {
        throw new Error("Please paste raw RFC 5322 email text or load a sample scenario.");
      }

      response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          raw_email: rawText,
          retain_evidence: retainEvidence,
        }),
      });
    }

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || `Server error (${response.status})`);
    }

    const data = await response.json();
    data.evidence_retained = !demoMode && retainEvidence;
    renderAssessment(data);
    if (!demoMode) loadIncidentsList();
    document.getElementById("analysis-status").textContent = "Assessment complete. Review the summary and findings.";
  } catch (err) {
    errBox.textContent = err.message;
    errBox.classList.remove("hidden");
    document.getElementById("analysis-status").textContent = `Assessment failed. ${err.message}`;
  } finally {
    btn.disabled = false;
    btn.removeAttribute("aria-busy");
    btn.textContent = "Check this email";
  }
}

// Render Assessment into UI
function renderAssessment(data) {
  currentAssessment = data;
  currentIncidentId = data.incident_id;

  const resContainer = document.getElementById("results-container");
  resContainer.classList.remove("hidden");

  // Header Details
  document.getElementById("res-subject").textContent = data.subject 
    ? `Subject: ${data.subject}` 
    : "Subject: (No Subject)";
  document.getElementById("res-incident-id").textContent = data.incident_id;
  document.getElementById("res-timestamp").textContent = data.timestamp ? new Date(data.timestamp).toUTCString() : "Unavailable";
  document.getElementById("res-hash").textContent = data.evidence_hash;

  const findings = Array.isArray(data.findings) ? data.findings : [];
  const unknownCount = findings.filter(f => f.category === "UNKNOWN_INFORMATION").length;
  document.getElementById("summary-finding-count").textContent = findings.length;
  document.getElementById("summary-unknown-count").textContent = unknownCount;
  const outcomeTitle = document.getElementById("outcome-title");
  const outcomeDescription = document.getElementById("outcome-description");
  const outcomePanel = document.querySelector(".outcome-panel");
  if (data.human_review_required) {
    outcomeTitle.textContent = "Human review required before acting";
    outcomeDescription.textContent = "TrustMail found signals that need a person to review. Check the findings and verify important requests through a separate trusted channel.";
    outcomePanel.classList.add("outcome-review");
    outcomePanel.classList.remove("outcome-quiet");
  } else {
    outcomeTitle.textContent = "No configured rule required escalation";
    outcomeDescription.textContent = "This does not establish that the email is safe. Review the unknowns and consider the context of the request.";
    outcomePanel.classList.add("outcome-quiet");
    outcomePanel.classList.remove("outcome-review");
  }

  // Review Badge
  const reviewBadge = document.getElementById("res-review-badge");
  reviewBadge.textContent = data.human_review_status;
  reviewBadge.className = `badge ${data.human_review_status === "PENDING" ? "badge-warning" : "badge-info"}`;

  // 4 Dimensions
  // Dim 1: IAL
  document.getElementById("dim-ial-level").textContent = data.identity_assurance.level;
  document.getElementById("dim-ial-title").textContent = data.identity_assurance.title;
  document.getElementById("dim-ial-desc").textContent = data.identity_assurance.description;
  document.getElementById("dim-ial-rationale").textContent = data.identity_assurance.rationale;
  renderDimensionFindings("dim-ial-findings", data.identity_assurance, data.findings, "IDENTITY");

  // Dim 2: MAL
  document.getElementById("dim-mal-level").textContent = data.message_authenticity.level;
  document.getElementById("dim-mal-title").textContent = data.message_authenticity.title;
  document.getElementById("dim-mal-desc").textContent = data.message_authenticity.description;
  document.getElementById("dim-mal-rationale").textContent = data.message_authenticity.rationale;
  renderDimensionFindings("dim-mal-findings", data.message_authenticity, data.findings, "AUTHENTICITY");

  // Dim 3: TSR
  const tsrBadge = document.getElementById("dim-tsr-level");
  tsrBadge.textContent = data.threat_assessment.level;
  tsrBadge.className = `badge ${severityBadgeClass(data.threat_assessment.level)}`;
  document.getElementById("dim-tsr-title").textContent = data.threat_assessment.title;
  document.getElementById("dim-tsr-desc").textContent = data.threat_assessment.description;
  document.getElementById("dim-tsr-rationale").textContent = data.threat_assessment.rationale;
  renderDimensionFindings("dim-tsr-findings", data.threat_assessment, data.findings, "THREAT");

  // Dim 4: STI
  document.getElementById("dim-sti-level").textContent = data.sender_trust.level;
  document.getElementById("dim-sti-title").textContent = data.sender_trust.title;
  document.getElementById("dim-sti-desc").textContent = data.sender_trust.description;
  document.getElementById("dim-sti-rationale").textContent = data.sender_trust.rationale;
  renderDimensionFindings("dim-sti-findings", data.sender_trust, data.findings, "TRUST");

  // Human Review & Triage
  const triageFlag = document.getElementById("triage-review-flag");
  const reasonsBox = document.getElementById("triage-reasons-box");
  const reasonsList = document.getElementById("triage-reasons-list");
  reasonsList.replaceChildren();

  if (data.human_review_required) {
    triageFlag.textContent = "HUMAN REVIEW MANDATED";
    triageFlag.className = "badge badge-alert";
    reasonsBox.classList.remove("hidden");
    data.human_review_reasons.forEach(r => {
      const li = document.createElement("li");
      li.textContent = r;
      reasonsList.appendChild(li);
    });
  } else {
    triageFlag.textContent = "No review required by current rules";
    triageFlag.className = "badge badge-neutral";
    reasonsBox.classList.add("hidden");
  }

  document.getElementById("review-status-select").value = data.human_review_status || "PENDING";
  document.getElementById("analyst-notes-input").value = data.analyst_notes || "";
  document.getElementById("tamper-verify-result").classList.add("hidden");
  const verifyButton = document.getElementById("btn-verify-tamper");
  const retained = data.evidence_retained === true;
  verifyButton.disabled = !retained;
  document.getElementById("tamper-availability").textContent = retained
    ? "The saved bytes can be compared with the intake digest. This does not prove who sent the message."
    : "No original copy was retained, so there are no saved bytes to verify.";

  // Findings Counts & Table
  updateFindingsCounters(data);
  filterFindings("all");

  // Audit Events
  if (!demoMode) renderAuditTrail(data.incident_id);

  // Scroll to results
  resContainer.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
}

function severityBadgeClass(severity) {
  const allowed = new Set(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]);
  return allowed.has(severity) ? `sev-badge-${severity}` : "badge-neutral";
}

function renderDimensionFindings(containerId, dimension, findings, dimensionKey) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.replaceChildren();
  const heading = document.createElement("strong");
  heading.textContent = "Related findings (context, not a formula):";
  container.appendChild(heading);

  const related = (findings || []).filter(f => f.dimension === dimensionKey);
  if (!related.length) {
    const empty = document.createElement("p");
    empty.textContent = "No specific findings were recorded for this dimension.";
    container.appendChild(empty);
  } else {
    const list = document.createElement("ul");
    related.forEach(f => {
      const item = document.createElement("li");
      item.textContent = `${f.id}: ${f.title}`;
      list.appendChild(item);
    });
    container.appendChild(list);
  }

  if (dimension.is_simulated_or_limited) {
    const note = document.createElement("p");
    note.className = "dimension-limit-note";
    note.textContent = "Limited assessment: this prototype does not verify all signals needed for a stronger conclusion. See the rationale above.";
    container.appendChild(note);
  }
}

function updateFindingsCounters(data) {
  const counts = {
    all: data.findings.length,
    VERIFIED_FACT: 0,
    UNVERIFIED_CLAIM: 0,
    HEURISTIC_FINDING: 0,
    UNKNOWN_INFORMATION: 0,
  };

  data.findings.forEach(f => {
    if (counts[f.category] !== undefined) counts[f.category]++;
  });

  document.getElementById("count-all").textContent = counts.all;
  document.getElementById("count-facts").textContent = counts.VERIFIED_FACT;
  document.getElementById("count-claims").textContent = counts.UNVERIFIED_CLAIM;
  document.getElementById("count-heuristics").textContent = counts.HEURISTIC_FINDING;
  document.getElementById("count-unknowns").textContent = counts.UNKNOWN_INFORMATION;
}

function filterFindings(category) {
  currentFindingsFilter = category;
  document.querySelectorAll(".findings-filter .filter-btn").forEach(btn => {
    const isTarget = btn.dataset.category === category;
    btn.classList.toggle("active", isTarget);
    btn.setAttribute("aria-pressed", String(isTarget));
  });

  if (!currentAssessment) return;
  const filtered = category === "all" 
    ? currentAssessment.findings 
    : currentAssessment.findings.filter(f => f.category === category);
  renderFindingsTable(filtered);
}

function renderFindingsTable(findings) {
  const tbody = document.getElementById("findings-table-body");
  tbody.replaceChildren();

  if (!findings || findings.length === 0) {
    const row = document.createElement("tr");
    row.className = "empty-row";
    const cell = appendText(row, "td", "No findings in this category.");
    cell.colSpan = 4;
    tbody.appendChild(row);
    return;
  }

  findings.forEach(f => {
    const tr = document.createElement("tr");
    let catClass = "cat-claim";
    if (f.category === "VERIFIED_FACT") catClass = "cat-fact";
    else if (f.category === "HEURISTIC_FINDING") catClass = "cat-heuristic";
    else if (f.category === "UNKNOWN_INFORMATION") catClass = "cat-unknown";

    const classification = document.createElement("td");
    appendBadge(classification, f.dimension || "Unknown dimension", "badge-dim");
    classification.appendChild(document.createElement("br"));
    appendBadge(classification, f.category || "UNKNOWN_INFORMATION", catClass);
    appendBadge(classification, f.severity || "UNKNOWN", severityBadgeClass(f.severity));
    tr.appendChild(classification);

    const claim = document.createElement("td");
    appendText(claim, "strong", f.title || "Untitled finding");
    appendText(claim, "p", f.description || "No explanation was recorded.", "finding-description");
    const reference = appendText(claim, "p", "", "ledger-reference");
    appendText(reference, "strong", "Rule/reference: ");
    reference.appendChild(document.createTextNode(f.id || "Unavailable"));
    tr.appendChild(claim);

    const evidence = document.createElement("td");
    if (f.evidence) appendText(evidence, "code", f.evidence, "evidence-code");
    else appendText(evidence, "p", "No evidence snippet recorded.", "limitations-text");
    const observations = Array.isArray(f.observations) ? f.observations : [];
    if (observations.length === 0) {
      appendText(evidence, "p", "No structured parser observation is linked to this finding.", "ledger-location");
    }
    observations.forEach(observation => {
      const observed = appendText(evidence, "p", "", "ledger-observation");
      appendText(observed, "strong", `Observed (${observation.type || "observation"}): `);
      observed.appendChild(document.createTextNode(String(observation.value ?? "Unavailable")));

      const location = observation.source_location;
      let locationText = "Source location unavailable: no precise source location was recorded.";
      if (location && location.available) {
        locationText = `Source: ${location.source || "Unspecified"}`;
        if (location.start !== null && location.start !== undefined && location.end !== null && location.end !== undefined) {
          locationText += `, characters ${location.start}–${location.end}`;
        }
      } else if (location?.unavailable_reason) {
        locationText = `Source location unavailable: ${location.unavailable_reason}`;
      }
      appendText(evidence, "p", locationText, "ledger-location");
    });
    if (f.category === "HEURISTIC_FINDING") {
      const interpretation = appendText(evidence, "p", "", "ledger-interpretation");
      appendText(interpretation, "strong", "Rule interpretation: ");
      interpretation.appendChild(document.createTextNode(f.description || "A heuristic rule raised this indicator; it is not proof of malicious intent."));
    }
    tr.appendChild(evidence);

    const limits = document.createElement("td");
    appendText(limits, "p", f.limitations || "No specific limitation recorded.", "limitations-text");
    if (f.review_guidance) {
      const review = appendText(limits, "p", "", "ledger-review");
      appendText(review, "strong", "Review next: ");
      review.appendChild(document.createTextNode(String(f.review_guidance)));
    }
    tr.appendChild(limits);
    tbody.appendChild(tr);
  });
}

// Review Status Update
async function submitReviewUpdate() {
  if (!currentIncidentId) return;

  const status = document.getElementById("review-status-select").value;
  const notes = document.getElementById("analyst-notes-input").value;
  const updateResult = document.getElementById("review-update-result");
  if (updateResult) updateResult.classList.add("hidden");

  try {
    const res = await fetch(`/api/incidents/${currentIncidentId}/review`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, notes }),
    });

    if (!res.ok) throw new Error(await getResponseError(res, "Failed to update incident review status."));

    const resBadge = document.getElementById("res-review-badge");
    resBadge.textContent = status;
    resBadge.className = `badge ${status === "CONFIRMED_THREAT" ? "badge-alert" : status === "PENDING" ? "badge-warning" : "badge-info"}`;

    renderAuditTrail(currentIncidentId);
    loadIncidentsList();

    if (updateResult) {
      updateResult.className = "alert-box alert-success";
      updateResult.textContent = `Review decision successfully recorded as '${status}'.`;
      updateResult.classList.remove("hidden");
    }
  } catch (err) {
    if (updateResult) {
      updateResult.className = "alert-box alert-error";
      updateResult.textContent = err.message;
      updateResult.classList.remove("hidden");
    } else {
      document.getElementById("submit-error").textContent = err.message || "Review update failed.";
      document.getElementById("submit-error").classList.remove("hidden");
    }
  }
}

// Verify Tamper Integrity
async function verifyTamperIntegrity() {
  if (!currentIncidentId) return;

  const resultBox = document.getElementById("tamper-verify-result");
  resultBox.className = "alert-box";
  resultBox.classList.remove("hidden");
  resultBox.textContent = "Verifying cryptographic hash of on-disk bytes...";

  try {
    const res = await fetch(`/api/incidents/${encodeURIComponent(currentIncidentId)}/verify-evidence`, {
      method: "POST",
    });
    if (!res.ok) throw new Error(await getResponseError(res, "Evidence integrity checking is unavailable."));
    const data = await res.json();

    if (data.status === "VERIFIED") {
      resultBox.classList.add("alert-success");
      appendText(resultBox, "strong", "Integrity verified: ");
      resultBox.appendChild(document.createTextNode("Saved bytes match the intake SHA-256 digest ("));
      appendText(resultBox, "code", data.recomputed_hash || "Unavailable");
      resultBox.appendChild(document.createTextNode("). This does not establish sender identity or chain of custody."));
    } else if (data.status === "TAMPER_DETECTED") {
      resultBox.classList.add("alert-error");
      appendText(resultBox, "strong", "Integrity check mismatch: ");
      resultBox.appendChild(document.createTextNode("The saved bytes differ from the intake digest. Expected: "));
      appendText(resultBox, "code", data.expected_hash || "Unavailable");
      resultBox.appendChild(document.createTextNode(". Found: "));
      appendText(resultBox, "code", data.recomputed_hash || "Unavailable");
      resultBox.appendChild(document.createTextNode("."));
    } else {
      resultBox.classList.add("alert-info");
      resultBox.textContent = data.message || "No retained email copy is available to check.";
    }

    renderAuditTrail(currentIncidentId);
  } catch (err) {
    resultBox.classList.add("alert-error");
    resultBox.textContent = "Failed to run verification: " + err.message;
  }
}

// Render Audit Trail
async function renderAuditTrail(incidentId) {
  const container = document.getElementById("audit-trail-list");
  try {
    const res = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}`);
    if (!res.ok) throw new Error(await getResponseError(res, "Incident activity could not be loaded."));
    const incident = await res.json();

    container.replaceChildren();
    if (!incident.audit_events || incident.audit_events.length === 0) {
      appendText(container, "p", "No incident activity has been recorded.", "inline-state");
      return;
    }

    incident.audit_events.forEach(evt => {
      const item = document.createElement("div");
      item.className = "audit-item";
      const eventDescription = document.createElement("div");
      appendBadge(eventDescription, evt.event_type || "Activity", "badge-neutral");
      appendText(eventDescription, "span", JSON.stringify(evt.details || {}), "audit-details");
      item.appendChild(eventDescription);
      appendText(item, "time", formatDate(evt.timestamp, { timeZone: "UTC", timeZoneName: "short" }), "audit-meta");
      container.appendChild(item);
    });
  } catch (err) {
    container.replaceChildren();
    appendText(container, "p", err.message || "Incident activity could not be loaded. Refresh the incident details to try again.", "inline-state");
  }
}

// Load Incidents Table
async function loadIncidentsList() {
  const tbody = document.getElementById("incidents-table-body");
  const countEl = document.getElementById("incident-count");
  const errorBox = document.getElementById("incident-list-error");
  if (errorBox) errorBox.classList.add("hidden");
  tbody.setAttribute("aria-busy", "true");

  try {
    const res = await fetch("/api/incidents?limit=50");
    if (!res.ok) throw new Error(await getResponseError(res, `Could not load incident history (server error ${res.status}).`));
    const list = await res.json();

    countEl.textContent = list.length;
    tbody.replaceChildren();

    if (list.length === 0) {
      const row = document.createElement("tr");
      row.className = "empty-row";
      const cell = appendText(row, "td", "No incidents recorded yet. Check an email to start a history.");
      cell.colSpan = 7;
      tbody.appendChild(row);
      return;
    }

    list.forEach(inc => {
      const tr = document.createElement("tr");
      const createdCell = tr.insertCell();
      appendText(createdCell, "time", formatDate(inc.created_at), "history-date");
      const senderCell = tr.insertCell();
      appendText(senderCell, "code", inc.claimed_sender || "Unknown sender");
      appendText(tr.insertCell(), "span", inc.subject || "(No subject)");

      const assessmentCell = tr.insertCell();
      appendBadge(assessmentCell, `Threat ${inc.tsr_level || "Unknown"}`, severityBadgeClass(inc.tsr_level));
      appendText(assessmentCell, "span", `Identity ${inc.ial_level || "Unknown"} · Authenticity ${inc.mal_level || "Unknown"} · Trust ${inc.sti_level || "Unknown"}`, "history-dimensions");

      const reviewCell = tr.insertCell();
      const reviewStatus = inc.human_review_status || "Unknown";
      const reviewClass = reviewStatus === "PENDING" ? "badge-warning" : reviewStatus === "CONFIRMED_THREAT" ? "badge-alert" : "badge-neutral";
      appendBadge(reviewCell, reviewStatus, reviewClass);
      appendText(tr.insertCell(), "span", inc.evidence_retained ? "Copy kept" : "Not retained");

      const actionCell = tr.insertCell();
      const openButton = document.createElement("button");
      openButton.type = "button";
      openButton.className = "btn btn-secondary";
      openButton.textContent = "Open";
      openButton.setAttribute("aria-label", `Open assessment for ${inc.subject || "untitled email"}`);
      openButton.addEventListener("click", () => viewIncidentDetail(inc.id));
      actionCell.appendChild(openButton);
      tr.appendChild(actionCell);
      tbody.appendChild(tr);
    });
  } catch (err) {
    if (errorBox) {
      errorBox.textContent = err.message || "Incident history could not be loaded. Check that TrustMail is running, then refresh.";
      errorBox.classList.remove("hidden");
    }
  } finally {
    tbody.removeAttribute("aria-busy");
  }
}

// View an Incident from the Log
async function viewIncidentDetail(incidentId) {
  try {
    const res = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}`);
    if (!res.ok) throw new Error(await getResponseError(res, "Could not load incident details."));
    const inc = await res.json();
    if (!inc.assessment) throw new Error("This incident has no assessment details to display.");
    switchView("analyze");
    inc.assessment.human_review_status = inc.human_review_status;
    inc.assessment.analyst_notes = inc.analyst_notes || "";
    inc.assessment.evidence_retained = inc.evidence_retained === true;
    renderAssessment(inc.assessment);
  } catch (err) {
    switchView("incidents");
    const errorBox = document.getElementById("incident-list-error");
    errorBox.textContent = err.message || "Could not load this assessment. Try refreshing the history list.";
    errorBox.classList.remove("hidden");
  }
}
