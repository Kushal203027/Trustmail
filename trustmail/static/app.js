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

// Safe HTML Escaper to Prevent XSS / Script Injection
function escapeHtml(unsafe) {
  if (unsafe === null || unsafe === undefined) return "";
  return String(unsafe)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
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

  // Initial incidents load
  loadIncidentsList();
});

function handleFileSelection(file) {
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
  document.getElementById("subtab-paste").setAttribute("aria-selected", String(mode === "paste"));
  document.getElementById("subtab-upload").setAttribute("aria-selected", String(mode === "upload"));

  document.getElementById("intake-paste-box").classList.toggle("hidden", mode !== "paste");
  document.getElementById("intake-upload-box").classList.toggle("hidden", mode !== "upload");
}

function loadSample(key) {
  if (SAMPLES[key]) {
    switchIntakeMode("paste");
    const input = document.getElementById("raw-email-input");
    input.value = SAMPLES[key];
    input.dispatchEvent(new Event("input"));
  }
}

function clearIntake() {
  document.getElementById("raw-email-input").value = "";
  document.getElementById("raw-email-input").dispatchEvent(new Event("input"));
  uploadedFileObject = null;
  const fileInput = document.getElementById("file-input");
  if (fileInput) fileInput.value = "";
  const info = document.getElementById("selected-file-info");
  if (info) {
    info.textContent = "";
    info.classList.add("hidden");
  }
  document.getElementById("submit-error").classList.add("hidden");
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
  btn.disabled = true;
  btn.setAttribute("aria-busy", "true");
  btn.textContent = "Checking email…";

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
    renderAssessment(data);
    loadIncidentsList();
  } catch (err) {
    errBox.textContent = err.message;
    errBox.classList.remove("hidden");
  } finally {
    btn.disabled = false;
    btn.removeAttribute("aria-busy");
    btn.innerHTML = '<span aria-hidden="true">◉</span> Check this email';
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
  tsrBadge.className = `badge sev-badge-${data.threat_assessment.level}`;
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
  reasonsList.innerHTML = "";

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

  // Findings Counts & Table
  updateFindingsCounters(data);
  renderFindingsTable(data.findings);

  // Audit Events
  renderAuditTrail(data.incident_id);

  // Scroll to results
  resContainer.scrollIntoView({ behavior: "smooth" });
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
    const isTarget = btn.getAttribute("onclick").includes(`'${category}'`);
    btn.classList.toggle("active", isTarget);
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
    row.innerHTML = '<td colspan="4">No findings in this category.</td>';
    tbody.appendChild(row);
    return;
  }

  findings.forEach(f => {
    const tr = document.createElement("tr");

    // Category badge class
    let catClass = "cat-claim";
    if (f.category === "VERIFIED_FACT") catClass = "cat-fact";
    else if (f.category === "HEURISTIC_FINDING") catClass = "cat-heuristic";
    else if (f.category === "UNKNOWN_INFORMATION") catClass = "cat-unknown";

    tr.innerHTML = `
      <td>
        <span class="badge badge-dim">${escapeHtml(f.dimension)}</span><br><span class="badge ${catClass}">${escapeHtml(f.category)}</span> <span class="badge sev-badge-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
      </td>
      <td>
        <strong>${escapeHtml(f.title)}</strong>
        <p style="color: var(--text-secondary); margin-top: 4px;">${escapeHtml(f.description)}</p>
        <p class="ledger-reference"><strong>Rule/reference:</strong> ${escapeHtml(f.id)}</p>
      </td>
      <td>
        ${f.evidence ? `<code class="evidence-code">${escapeHtml(f.evidence)}</code>` : '<span class="limitations-text">No evidence snippet recorded.</span>'}
        ${(f.observations || []).map(observation => `
          <p class="ledger-observation"><strong>Observed (${escapeHtml(observation.type)}):</strong> ${escapeHtml(observation.value)}</p>
          <p class="ledger-location">${observation.source_location && observation.source_location.available
            ? `Source: ${escapeHtml(observation.source_location.source)}${observation.source_location.start !== null && observation.source_location.start !== undefined ? `, characters ${escapeHtml(observation.source_location.start)}–${escapeHtml(observation.source_location.end)}` : ""}`
            : `Source location unavailable: ${escapeHtml(observation.source_location?.unavailable_reason || "No precise source location was recorded.")}`}</p>
        `).join("")}
        ${f.observations && f.observations.length ? '<p class="ledger-interpretation"><strong>Interpretation:</strong> The rule flagged this observation as suspicious; this is a heuristic indicator, not proof of malicious intent.</p>' : ""}
      </td>
      <td><span class="limitations-text">${escapeHtml(f.limitations || "No specific limitation recorded.")}</span>${f.review_guidance ? `<p class="ledger-review"><strong>Review next:</strong> ${escapeHtml(f.review_guidance)}</p>` : ""}</td>
    `;
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

    if (!res.ok) throw new Error("Failed to update incident review status.");

    const resBadge = document.getElementById("res-review-badge");
    resBadge.textContent = status;
    resBadge.className = `badge ${status === "CONFIRMED_THREAT" ? "badge-alert" : "badge-info"}`;

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
      alert(err.message);
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
    const res = await fetch(`/api/incidents/${currentIncidentId}/verify-evidence`, {
      method: "POST",
    });
    const data = await res.json();

    if (data.status === "VERIFIED") {
      resultBox.classList.add("alert-success");
      resultBox.innerHTML = `<strong>INTEGRITY VERIFIED:</strong> On-disk bytes exactly match the intake SHA-256 digest (<code>${escapeHtml(data.recomputed_hash)}</code>).`;
    } else if (data.status === "TAMPER_DETECTED") {
      resultBox.classList.add("alert-error");
      resultBox.innerHTML = `<strong>TAMPER DETECTED:</strong> On-disk bytes have been altered! Expected: <code>${escapeHtml(data.expected_hash)}</code> | Found: <code>${escapeHtml(data.recomputed_hash)}</code>.`;
    } else {
      resultBox.classList.add("alert-info");
      resultBox.textContent = data.message;
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
    if (!res.ok) return;
    const incident = await res.json();

    container.innerHTML = "";
    if (!incident.audit_events || incident.audit_events.length === 0) {
      container.innerHTML = '<p style="color: var(--text-muted); font-size: 0.8rem;">No audit events recorded.</p>';
      return;
    }

    incident.audit_events.forEach(evt => {
      const item = document.createElement("div");
      item.className = "audit-item";
      item.innerHTML = `
        <div>
          <span class="badge badge-neutral" style="margin-right: 8px;">${escapeHtml(evt.event_type)}</span>
          <span>${escapeHtml(JSON.stringify(evt.details))}</span>
        </div>
        <div class="audit-meta">${escapeHtml(new Date(evt.timestamp).toUTCString())}</div>
      `;
      container.appendChild(item);
    });
  } catch (err) {
    console.error("Failed to fetch audit trail:", err);
  }
}

// Load Incidents Table
async function loadIncidentsList() {
  const tbody = document.getElementById("incidents-table-body");
  const countEl = document.getElementById("incident-count");
  const errorBox = document.getElementById("incident-list-error");
  if (errorBox) errorBox.classList.add("hidden");

  try {
    const res = await fetch("/api/incidents?limit=50");
    if (!res.ok) throw new Error(`Could not load incident history (server error ${res.status}).`);
    const list = await res.json();

    countEl.textContent = list.length;
    tbody.replaceChildren();

    if (list.length === 0) {
      const row = document.createElement("tr");
      row.className = "empty-row";
      row.innerHTML = '<td colspan="7">No incidents recorded yet. Check an email to start a history.</td>';
      tbody.appendChild(row);
      return;
    }

    list.forEach(inc => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><small>${escapeHtml(new Date(inc.created_at).toLocaleString())}</small></td>
        <td><code>${escapeHtml(inc.claimed_sender)}</code></td>
        <td>${escapeHtml(inc.subject)}</td>
        <td><span class="badge sev-badge-${escapeHtml(inc.tsr_level)}">Threat ${escapeHtml(inc.tsr_level)}</span><br><small>Identity ${escapeHtml(inc.ial_level)} · Authenticity ${escapeHtml(inc.mal_level)} · Trust ${escapeHtml(inc.sti_level)}</small></td>
        <td><span class="badge ${inc.human_review_status === "PENDING" ? "badge-warning" : "badge-neutral"}">${escapeHtml(inc.human_review_status)}</span></td>
        <td><small>${inc.evidence_retained ? "Copy kept" : "Not retained"}</small></td>
      `;
      const actionCell = document.createElement("td");
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
    console.error("Failed to load incidents:", err);
    if (errorBox) {
      errorBox.textContent = err.message || "Incident history could not be loaded.";
      errorBox.classList.remove("hidden");
    }
  }
}

// View an Incident from the Log
async function viewIncidentDetail(incidentId) {
  try {
    const res = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}`);
    if (!res.ok) throw new Error("Could not load incident details.");
    const inc = await res.json();
    switchView("analyze");
    if (inc.assessment) {
      inc.assessment.human_review_status = inc.human_review_status;
      inc.assessment.analyst_notes = inc.analyst_notes || "";
      renderAssessment(inc.assessment);
    }
  } catch (err) {
    alert(err.message);
  }
}
