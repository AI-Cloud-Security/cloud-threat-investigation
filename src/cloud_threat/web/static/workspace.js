"use strict";

const state = { cases: [], current: null, selected: null, tab: "overview", preview: null };
const token = document.querySelector('meta[name="workspace-token"]').content;
const el = (id) => document.getElementById(id);
const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
}[character]));
const pretty = (value) => escapeHtml(JSON.stringify(value, null, 2));
const date = (value) => new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
const plural = (count, noun) => `${count} ${noun}${count === 1 ? "" : "s"}`;

const statusLabels = { open: "Open", needs_evidence: "Awaiting evidence", reviewed_expected: "Expected activity", reviewed_threat: "Suspected threat", response_approved: "Response approved", response_recorded: "Response recorded", closed: "Closed" };
const assessmentLabels = { expected: "Expected activity", needs_evidence: "More evidence required", threat: "Suspected threat" };
const dispositionLabels = { expected: "Expected activity", resolved: "Resolved", escalated: "Escalated" };
const featureLabels = { public_access: "Public access", unusual_region: "Unusual region", large_read: "Large data read", baseline: "Baseline" };
const actionLabels = { disable_public_access: "Disable public access", limit_read_volume: "Limit read volume" };
const outcomeLabels = { completed: "Completed", failed: "Failed", not_applied: "Not applied" };
const historyLabels = { imported: "Records imported", assessed: "Assessment recorded", note_added: "Note added", evidence_added: "Evidence revision added", response_previewed: "Response previewed", response_approved: "Response approved", response_outcome_recorded: "Change outcome recorded", closed: "Investigation closed" };
const nodeLabels = { raw: "Source record", normalized: "Normalized event", features: "Indicators", model: "Scoring profile", policy: "Permission policy", decision: "Decision", attribution: "Score breakdown", counterfactual: "Response analysis", evidence: "Evidence root" };
const labelFrom = (labels, value) => labels[value] || String(value ?? "").replaceAll("_", " ");
const actionList = (actions) => actions.map((action) => labelFrom(actionLabels, action)).join(" and ");

function message(text, error = false) {
  const box = el("message");
  box.hidden = !text;
  box.className = error ? "error" : "";
  box.textContent = text;
  const importFeedback = el("import-feedback");
  importFeedback.hidden = !error || !el("import-dialog").open;
  importFeedback.textContent = error ? text : "";
  if (error) box.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function actor() {
  const input = el("import-dialog").open ? el("import-actor") : el("analyst");
  const value = input.value.trim();
  if (!value) { input.focus(); throw new Error("Enter an analyst name to record this action."); }
  el("analyst").value = value;
  try { localStorage.setItem("cti-analyst", value); } catch (_) { /* Storage is optional. */ }
  return value;
}

async function api(path, data) {
  const options = data === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json", "X-Workspace-Token": token },
    body: JSON.stringify({ ...data, actor: actor() })
  };
  const response = await fetch(path, { cache: "no-store", ...options });
  const body = await response.json();
  if (!response.ok) {
    if (response.status === 409 && state.selected) await loadCase(state.selected);
    throw new Error(body.error || "The request could not be completed.");
  }
  return body;
}

const icon = (name) => `<svg class="icon" aria-hidden="true"><use href="#i-${name}"></use></svg>`;
const SCORE_SCALE = 100;

function badge(item) {
  const color = item.status === "closed" || item.assessment === "expected" ? "green" : item.assessment === "threat" ? "red" : item.status === "needs_evidence" ? "amber" : "blue";
  return `<span class="badge ${color}">${escapeHtml(labelFrom(statusLabels, item.status))}</span>`;
}

function severityBadge(alert) {
  return alert ? `<span class="badge red">Alert</span>` : `<span class="badge green">No alert</span>`;
}

function entities(item) {
  return `<span class="entity"><span class="entity-label">Principal</span>${escapeHtml(item.principal)}</span><span class="entity-arrow" aria-hidden="true">→</span><span class="entity"><span class="entity-label">Resource</span>${escapeHtml(item.resource)}</span>`;
}

async function refresh(selectId = state.selected) {
  const result = await api("/api/workspace");
  state.cases = result.cases;
  el("key-short").textContent = result.key_fingerprint.slice(0, 24) + "…";
  el("key-short").title = result.key_fingerprint;
  el("case-count").textContent = state.cases.length;
  renderMetrics(); renderList();
  if (selectId) await loadCase(selectId);
  else renderEmpty();
}

function renderMetrics() {
  const values = [
    [state.cases.length, "Total incidents", "folder", ""],
    [state.cases.filter((item) => item.status !== "closed").length, "Open investigations", "activity", "alert"],
    [state.cases.filter((item) => item.status === "needs_evidence").length, "Awaiting evidence", "alert", "warn"],
    [state.cases.filter((item) => item.status === "closed").length, "Closed", "check", "ok"]
  ];
  el("metrics").innerHTML = values.map(([value, title, name, tone]) => `<div class="metric ${tone}"><div class="metric-head"><span>${title}</span><span class="metric-icon">${icon(name)}</span></div><strong>${value}</strong></div>`).join("");
  renderRiskOverview();
}

function renderRiskOverview() {
  const total = state.cases.length;
  if (!total) {
    el("risk-overview").innerHTML = `<h2>Alert distribution</h2><p class="subtle">Import records to see how incidents score against the alert threshold.</p>`;
    return;
  }
  const alertCount = state.cases.filter((item) => item.alert).length;
  const rows = [
    ["Alert raised", alertCount, "alert"],
    ["No alert", total - alertCount, "below"]
  ];
  el("risk-overview").innerHTML = `<h2>Alert distribution</h2><p class="subtle">${plural(total, "incident")} scored against the configured alert threshold</p><ul class="risk-chart">${rows.map(([title, count, kind]) => {
    const percent = Math.round(count / total * 100);
    return `<li class="risk-row"><span>${title}</span><svg class="risk-track" viewBox="0 0 100 10" preserveAspectRatio="none" role="meter" aria-valuemin="0" aria-valuemax="${total}" aria-valuenow="${count}" aria-label="${title}: ${count} of ${total} incidents"><rect class="risk-track-bg" width="100" height="10" rx="2"></rect><rect class="risk-fill ${kind}" width="${percent}" height="10" rx="2"></rect></svg><strong class="risk-count">${count}</strong></li>`;
  }).join("")}</ul>`;
}

function renderList() {
  const query = el("search").value.toLowerCase();
  const filter = el("filter").value;
  const items = state.cases.filter((item) => (!query || `${item.headline || ""} ${item.principal} ${item.resource} ${item.tenant}`.toLowerCase().includes(query)) &&
    (filter === "all" || (filter === "active" ? item.status !== "closed" : item.status === filter)));
  el("case-list").innerHTML = items.length ? items.map((item) => `
    <button class="case-item ${state.selected === item.id ? "selected" : ""}" data-action="select" data-id="${item.id}" aria-current="${state.selected === item.id}" aria-label="${escapeHtml(item.headline || "Incident")}: ${escapeHtml(item.principal)} on ${escapeHtml(item.resource)}, ${item.risk_points} risk points, ${escapeHtml(labelFrom(statusLabels, item.status))}">
      <span class="case-score ${item.alert ? "alert" : ""}">${item.risk_points}</span>
      <span class="case-body"><strong>${escapeHtml(item.headline || "Access activity")}</strong><small class="case-entities" title="${escapeHtml(item.principal)} → ${escapeHtml(item.resource)}">${escapeHtml(item.principal)} → ${escapeHtml(item.resource)}</small>
      <span class="case-foot">${badge(item)}<small title="Tenant ${escapeHtml(item.tenant)}, evidence revision ${item.revision}">${escapeHtml(item.tenant)}</small></span></span>
    </button>`).join("") : `<p class="subtle">${state.cases.length ? "No incidents match the current search or filter." : "No incidents yet. Import records to begin."}</p>`;
}

function renderEmpty() {
  el("case-detail").innerHTML = `<div class="empty-state"><div class="empty-icon">${icon(state.cases.length ? "inbox" : "shield")}</div><h2>${state.cases.length ? "Select an incident" : "Import security records to begin"}</h2><p>${state.cases.length ? "Choose an incident from the inbox to review its evidence and record an assessment." : "Imported records are grouped into incidents by tenant, principal and resource. Review each incident, record your assessment and response, and export signed, independently verifiable evidence."}</p><div class="actions"><button class="primary" data-action="import">${icon("upload")}Import security records</button><button class="secondary" data-action="help">${icon("book")}Workflow guide</button></div></div>`;
}

async function openHighestRisk(caseIds) {
  await refresh(null);
  const created = new Set(caseIds);
  const target = state.cases.find((item) => created.has(item.id)) || state.cases[0];
  if (target) await loadCase(target.id);
}

async function loadCase(id) {
  const result = await api(`/api/cases/${id}`);
  if (state.current && state.current.case.root !== result.case.root) state.preview = null;
  state.current = result; state.selected = id;
  renderList(); renderDetail();
}

function renderDetail() {
  if (!state.current) return renderEmpty();
  const current = state.current; const item = current.case;
  const steps = [true, Boolean(item.assessment), Boolean(item.execution) || item.assessment === "expected" || item.disposition === "escalated", item.status === "closed"];
  const currentStep = steps.indexOf(false);
  const meta = [["Tenant", item.tenant], ["Case ID", item.id.slice(0, 8)], ["Evidence revision", item.revision], ["Last updated", date(item.updated_at)]];
  el("case-detail").innerHTML = `
    <header class="case-header"><div class="case-header-top"><div class="badges">${badge(item)}${severityBadge(current.decision.alert)}</div><span class="subtle mono" title="Evidence root ${escapeHtml(item.root)}">${escapeHtml(current.short_id || item.root.slice(0, 16))}</span></div>
      <h2>${escapeHtml(current.headline || "Access activity")}</h2>
      <div class="entities">${entities(item)}</div>
      <dl class="meta-grid">${meta.map(([term, value]) => `<div><dt>${term}</dt><dd>${escapeHtml(value)}</dd></div>`).join("")}</dl>
      <ol class="stepper" aria-label="Investigation progress">${["Triage", "Assess", "Respond", "Close and export"].map((text, index) => `<li class="step ${steps[index] ? "done" : index === currentStep ? "current" : ""}"><span class="step-dot">${steps[index] ? icon("check") : index + 1}</span><span>${text}</span></li>`).join("")}</ol>
    </header>
    <div class="tabbar" role="tablist" aria-label="Investigation views">${[["overview", "Overview"], ["evidence", "Evidence"], ["response", "Response"], ["history", "Audit trail"]].map(([id, title]) => `<button class="tab ${state.tab === id ? "active" : ""}" role="tab" id="tab-${id}" aria-controls="case-tab-panel" tabindex="${state.tab === id ? 0 : -1}" aria-selected="${state.tab === id}" data-action="tab" data-tab="${id}">${title}</button>`).join("")}</div>
    <div class="tab-content" id="case-tab-panel" role="tabpanel" aria-labelledby="tab-${state.tab}">${({ overview: overview, evidence: evidence, response: responseView, history: historyView })[state.tab]()}</div>`;
}

function scoreGauge(points, threshold, alert) {
  const scale = (value) => Math.max(0, Math.min(SCORE_SCALE, value)) / SCORE_SCALE * 100;
  return `<svg class="gauge" viewBox="0 0 100 30" preserveAspectRatio="none" role="img" aria-label="${points} risk points; alert threshold ${threshold}"><rect class="gauge-bg" y="8" width="100" height="10" rx="2"></rect><rect class="gauge-fill ${alert ? "alert" : ""}" y="8" width="${scale(points)}" height="10" rx="2"></rect><line class="gauge-mark" x1="${scale(threshold)}" x2="${scale(threshold)}" y1="3" y2="23" vector-effect="non-scaling-stroke"></line></svg>`;
}

function contributionBars(attribution, total) {
  const rows = [["baseline", attribution.baseline, "base"], ...Object.entries(attribution.contributions).sort((a, b) => b[1] - a[1]).map(([name, value]) => [name, value, value ? "" : "zero"])];
  return `<ul class="contrib">${rows.map(([name, value, kind]) => `<li><span class="name">${escapeHtml(labelFrom(featureLabels, name))}</span><svg viewBox="0 0 100 10" preserveAspectRatio="none" aria-hidden="true"><rect class="bar-bg" width="100" height="10" rx="2"></rect><rect class="bar-fill ${kind}" width="${Math.min(100, value / SCORE_SCALE * 100)}" height="10" rx="2"></rect></svg><span class="value">${kind === "base" ? "" : "+"}${value}</span></li>`).join("")}</ul><div class="contrib-total"><span>Total</span><span>${total} points</span></div>`;
}

function overview() {
  const data = state.current; const item = data.case;
  return `<div class="two-columns"><section class="card"><h3>Risk score ${severityBadge(data.decision.alert)}</h3><div class="score-line"><span class="score ${data.decision.alert ? "alert" : ""}">${item.risk_points}</span><span class="score-unit">points · alert threshold ${data.decision.threshold}</span></div>${scoreGauge(item.risk_points, data.decision.threshold, data.decision.alert)}<p class="sr-only">${item.risk_points} risk points. Alert threshold ${data.decision.threshold}. ${data.decision.alert ? "Alert raised." : "No alert."}</p><p class="hint">Calculated with a transparent, configured scoring profile. The score is not a probability of compromise and does not replace analyst judgement.</p></section>
    <section class="card"><h3>Score breakdown</h3>${contributionBars(data.attribution, item.risk_points)}<p class="hint">Each indicator adds its configured weight when it is observed in at least one source record.</p></section></div>
    ${techniqueSection(data.techniques || [])}
    ${item.assessment ? `<div class="callout ${item.assessment === "expected" ? "green" : "amber"}">${icon(item.assessment === "expected" ? "check" : "alert")}<div><strong>Assessment: ${escapeHtml(labelFrom(assessmentLabels, item.assessment))}</strong><p>${escapeHtml(item.rationale)}</p></div></div>` : `<div class="callout">${icon("activity")}<div><strong>Recommended next step</strong><p>Review the source events on the Evidence tab, then record whether the activity is expected, requires more evidence or indicates a threat.</p></div></div>`}
    ${item.status === "closed" ? `<div class="callout green">${icon("lock")}<div>This investigation is closed and read-only.</div></div>` : item.approval ? `<div class="callout">${icon("activity")}<div>A response has been approved. Continue on the Response tab, or add evidence on the Evidence tab to start a new assessment.</div></div>` : `<form id="assessment-form" class="form-card"><h3>${item.assessment ? "Update assessment" : "Record assessment"}</h3><p class="hint">The conclusion and rationale are signed into the audit trail.</p><label for="assessment">Conclusion</label><select id="assessment" required><option value="">Select a conclusion</option><option value="expected">Expected activity</option><option value="needs_evidence">More evidence required</option><option value="threat">Suspected threat</option></select><label for="rationale">Rationale</label><textarea id="rationale" maxlength="4000" required placeholder="Summarize the evidence and context that support this conclusion."></textarea><button class="primary" type="submit">Save assessment</button></form>`}
    ${item.status === "closed" ? "" : `<form id="note-form" class="form-card"><h3>Investigation note</h3><label class="sr-only" for="investigation-note">Investigation note</label><textarea id="investigation-note" maxlength="4000" required placeholder="Context, open questions or external references."></textarea><button class="secondary" type="submit">Add note</button></form>`}`;
}

function techniqueSection(techniques) {
  if (!techniques.length) return "";
  return `<section class="techniques"><h3>Related MITRE ATT&amp;CK techniques</h3><ul class="technique-list">${techniques.map((item) => `<li><a href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer"><span class="technique-id">${escapeHtml(item.id)}</span>${escapeHtml(item.name)}</a><span class="subtle">${escapeHtml(item.tactic)} · ${escapeHtml(item.indicators.map((name) => labelFrom(featureLabels, name)).join(", "))}</span></li>`).join("")}</ul><p class="hint">Provided as analytical context. An observed indicator does not confirm that a technique occurred.</p></section>`;
}

function indicator(value) {
  return `<span class="chip ${value ? "on" : ""}">${value ? "Yes" : "No"}</span>`;
}

function evidence() {
  const data = state.current; const item = data.case;
  return `<h3>Event timeline</h3><div class="table-wrap"><table class="data-table"><thead><tr><th>Time (source)</th><th>Event ID</th><th>Action</th><th>Public access</th><th>Unusual region</th><th>Large data read</th></tr></thead><tbody>${data.events.map((event) => `<tr><td class="mono">${escapeHtml(event.timestamp)}</td><td class="mono">${escapeHtml(event.event_id)}</td><td>${escapeHtml(event.action)}</td><td>${indicator(event.public_access)}</td><td>${indicator(event.unusual_region)}</td><td>${indicator(event.large_read)}</td></tr>`).join("")}</tbody></table></div>
    <p class="hint">${plural(data.events.length, "event")} for this principal and resource. Indicator values come from the source data or the import adapter; this application does not infer them.</p>
    <details><summary>Original source records (${data.original_records.length})</summary>${data.original_records.map((raw) => `<pre>${escapeHtml(raw)}</pre>`).join("")}</details>
    <details><summary>Provenance and signature verification</summary><p class="hint">Signature and graph integrity verified with workspace key <code>${escapeHtml(data.key_fingerprint)}</code>.</p><p class="subtle">Evidence root</p><pre>${escapeHtml(data.verification.root)}</pre><div class="table-wrap"><table class="data-table"><thead><tr><th>Node</th><th>Hash</th><th>Inputs</th></tr></thead><tbody>${data.provenance.map((node) => `<tr><td>${escapeHtml(labelFrom(nodeLabels, node.kind))}</td><td><code title="${node.hash}">${node.hash.slice(0, 18)}…</code></td><td>${node.parents.length}</td></tr>`).join("")}</tbody></table></div></details>
    <details><summary>Permission policy and revision history</summary><pre>${pretty(data.policy)}</pre><p class="hint">Every revision root is preserved. Earlier evidence is never replaced.</p><pre>${pretty(data.revisions)}</pre></details>
    ${item.status === "closed" ? `<div class="callout green">${icon("lock")}<div>This investigation is closed. Its evidence and audit trail are read-only.</div></div>` : `<form id="evidence-form" class="form-card"><h3>Add evidence or update policy</h3><p class="hint">Saving creates a new signed evidence revision and clears the current assessment and approval. Earlier decisions remain in the audit trail.</p><label for="additional-events">Additional events <span class="optional">optional</span></label><input id="additional-events" type="file" accept=".csv,.jsonl,.json"><label for="updated-policy">Permission policy <span class="optional">optional</span></label><input id="updated-policy" type="file" accept=".json"><label for="evidence-reason">Reason for update</label><textarea id="evidence-reason" maxlength="4000" required placeholder="Describe the new evidence or policy change."></textarea><button class="primary" type="submit">Save evidence revision</button></form>`}`;
}

function latestPreview() {
  if (state.preview && state.preview.root === state.current.case.root) return state.preview;
  const events = [...state.current.history].reverse();
  return events.find((entry) => entry.payload.kind === "response_previewed" && entry.payload.data.preview.root === state.current.case.root)?.payload.data.preview || null;
}

function responseView() {
  const data = state.current; const item = data.case;
  if (item.status === "closed") return `<div class="callout green">${icon("lock")}<div><strong>Closed: ${escapeHtml(labelFrom(dispositionLabels, item.disposition))}</strong><p>${escapeHtml(item.closing_note)}</p></div></div>${exportSection()}`;
  let content = "";
  if (item.assessment === "needs_evidence" || !item.assessment) {
    content = `<div class="callout amber">${icon("alert")}<div>${item.assessment ? "Add the required evidence on the Evidence tab, then record a new assessment." : "Record an assessment on the Overview tab before planning a response or closing the investigation."}</div></div>`;
  } else if (item.assessment === "expected") {
    content = `<div class="callout green">${icon("check")}<div>Assessed as expected activity. Provide a closure summary to close the investigation.</div></div>`;
  } else {
    content = `<h3>Plan a response</h3><p class="hint">Only actions permitted by the current permission policy are listed. Previewing or approving a response does not change any cloud resource.</p>`;
    if (!item.approval) {
      if (data.response_options.length) content += `<form id="preview-form" class="form-card"><label for="response-option">Response action</label><select id="response-option">${data.response_options.map((option, index) => `<option value="${index}">${escapeHtml(actionList(option.actions))} (projected score ${option.risk_points}, effort ${option.cost})</option>`).join("")}</select><button class="secondary" type="submit">Preview response</button></form>`;
      else content += `<div class="callout amber">${icon("alert")}<div>The current permission policy does not permit a response for this incident. Attach a policy on the Evidence tab, gather more evidence or escalate the investigation.</div></div>`;
      const preview = latestPreview();
      if (preview) content += `<div class="section"><h3>Response preview</h3><div class="preview-card"><div class="preview-delta"><span class="from">${item.risk_points}</span><span class="arrow">→</span><span class="to">${preview.risk_points}</span><span class="score-unit">projected points</span></div><strong>${escapeHtml(actionList(preview.actions))}</strong><p class="hint">Effort rating ${preview.cost}. The projected score is ${preview.below_threshold ? "below" : "still above"} the alert threshold. This is a model projection, not confirmation that the change is effective.</p></div><form id="approval-form">${data.policy.separation_of_duties ? `<div class="callout amber">${icon("user")}<div><strong>Separation of duties</strong><p>This policy requires approval by a different analyst than the one who recorded the assessment. Update the analyst name before approving.</p></div></div>` : ""}<label for="approval-note">Approval rationale</label><textarea id="approval-note" maxlength="4000" required placeholder="Explain why this response is appropriate."></textarea><button class="primary" type="submit">Approve response</button></form></div>`;
    } else {
      content += `<div class="callout green">${icon("check")}<div><strong>Response approved: ${escapeHtml(actionList(item.approval.preview.actions))}</strong><p>Approved by ${escapeHtml(item.approval.actor)}. ${escapeHtml(item.approval.rationale)}</p></div></div>`;
      if (!item.execution) content += `<form id="execution-form" class="form-card"><h3>Record change outcome</h3><p class="hint">Apply the approved change through your organization's change-management process, then record the result here.</p><label for="outcome">Outcome</label><select id="outcome"><option value="completed">Completed</option><option value="failed">Failed</option><option value="not_applied">Not applied</option></select><label for="execution-reference">Change or ticket reference</label><input id="execution-reference" maxlength="500" required placeholder="For example, CHG-1042 or a ticket URL"><label for="execution-note">Verification notes</label><textarea id="execution-note" maxlength="4000" required placeholder="Describe what was changed and how the result was verified."></textarea><button class="primary" type="submit">Record outcome</button></form>`;
      else content += `<div class="callout">${icon("activity")}<div><strong>Change outcome: ${escapeHtml(labelFrom(outcomeLabels, item.execution.outcome))}</strong><p>${escapeHtml(item.execution.note)}</p><p>Reference: ${escapeHtml(item.execution.reference)}</p><p class="hint">Outcome attested by the analyst. This application does not execute cloud changes.</p></div></div>`;
    }
  }
  if (item.assessment === "expected" || item.assessment === "threat") {
    const options = item.assessment === "expected" ? `<option value="expected">Expected activity</option>` : `${item.execution?.outcome === "completed" ? '<option value="resolved">Resolved</option>' : ""}<option value="escalated">Escalated</option>`;
    content += `<form id="closure-form" class="form-card"><h3>Close investigation</h3><p class="hint">Closed investigations are read-only. Evidence revisions and the signed audit trail remain available for export.</p><label for="disposition">Disposition</label><select id="disposition">${options}</select><label for="closure-reference">Escalation reference <span class="optional">required for escalation</span></label><input id="closure-reference" maxlength="500" placeholder="Incident, change or handoff reference"><label for="closure-note">Closure summary</label><textarea id="closure-note" maxlength="4000" required placeholder="Summarize the outcome of the investigation."></textarea><button class="primary" type="submit">Close investigation</button></form>`;
  }
  return content + exportSection();
}

function exportSection() {
  const item = state.current.case;
  return `<div class="section"><h3>${item.status === "closed" ? "Export the completed investigation" : "Export an interim snapshot"}</h3><p class="hint">The archive contains the signed report, source records, permission policy, every evidence revision, the audit trail and a signed file manifest.${item.status === "closed" ? "" : " Snapshots of open investigations are marked as interim."}</p><div class="actions"><a class="primary-link" href="/api/cases/${item.id}/export">${icon("download")}Download archive</a><a href="/api/public-key" download>${icon("key")}Download public key</a><button class="secondary" data-action="verify">${icon("shield")}Verify integrity</button></div><p class="hint">Verify exported archives against an independently trusted copy of the public key. The key included in the archive is provided for convenience only.</p></div>`;
}

function historyView() {
  return `<h3>Audit trail</h3><p class="hint">Each entry is signed and linked to the previous entry by hash. Analyst names are self-asserted on this workstation.</p><ol class="activity">${[...state.current.history].reverse().map((entry) => { const event = entry.payload; const summary = event.data.note || event.data.rationale || event.data.reason || (event.kind === "imported" ? `Imported ${plural(event.data.records, "source record")} from ${event.data.filename}.` : event.kind === "response_previewed" ? `${actionList(event.data.preview.actions)}: projected score ${event.data.preview.risk_points}.` : `Recorded against evidence revision ${event.state.revision}.`); return `<li><time>${escapeHtml(date(event.occurred_at))}</time><strong>${escapeHtml(labelFrom(historyLabels, event.kind))} <span class="actor">· ${escapeHtml(event.actor)}</span></strong><p>${escapeHtml(summary)}</p><details><summary>Signed entry</summary><pre>${pretty(entry)}</pre></details></li>`; }).join("")}</ol>`;
}

async function fileData(inputId, sourceFormat = "auto") {
  const file = el(inputId).files[0];
  if (!file) return null;
  if (file.size > 16 * 1024 * 1024) throw new Error("Files must be 16 MiB or smaller.");
  const content = await new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result.split(",")[1]);
    reader.onerror = () => reject(new Error("The selected file could not be read."));
    reader.readAsDataURL(file);
  });
  const extension = file.name.split(".").pop().toLowerCase();
  if (sourceFormat && sourceFormat !== "auto") {
    if (!["json", "jsonl"].includes(extension)) throw new Error("Provider log exports must be JSON or JSONL files.");
    return { filename: file.name, format: sourceFormat, content };
  }
  if (!["csv", "jsonl", "json"].includes(extension)) throw new Error("Choose a CSV, JSONL or JSON file.");
  return { filename: file.name, format: extension, content };
}

async function jsonFile(inputId, description) {
  const file = el(inputId).files[0];
  if (!file) return null;
  if (file.size > 1024 * 1024) throw new Error(`${description} files must be 1 MiB or smaller.`);
  try { return JSON.parse(await file.text()); }
  catch (_) { throw new Error(`The ${description.toLowerCase()} file is not valid JSON.`); }
}
const policyData = (inputId) => jsonFile(inputId, "Permission policy");

async function mutate(command, data) {
  const result = await api(`/api/cases/${state.selected}/${command}`, { version: state.current.case.version, ...data });
  if (result.preview) state.preview = result.preview;
  if (command === "evidence") state.preview = null;
  state.current = result.incident || result;
  const workspace = await api("/api/workspace"); state.cases = workspace.cases;
  renderMetrics(); renderList(); renderDetail();
  message(({ assessment: "Assessment saved.", note: "Note added to the audit trail.", evidence: "Evidence revision saved. Record a new assessment.", preview: "Response preview ready for approval.", approve: "Response approved. Apply the change through your change-management process, then record the outcome.", execution: "Change outcome recorded. The investigation can now be closed.", close: "Investigation closed. The final archive is ready to export." })[command]);
}

async function submit(form) {
  switch (form.id) {
    case "import-form": {
      const sourceFormat = el("source-format").value || "auto";
      const file = await fileData("event-file", sourceFormat); if (!file) throw new Error("Select an event file to import.");
      const adapterSettings = await jsonFile("adapter-file", "Adapter settings");
      if (adapterSettings && sourceFormat === "auto") throw new Error("Adapter settings apply only to provider logs. Choose the record format.");
      const result = await api("/api/import", { ...file, policy: await policyData("policy-file"), ...(adapterSettings ? { adapter_settings: adapterSettings } : {}) });
      el("import-dialog").close(); state.tab = "overview";
      await openHighestRisk(result.case_ids);
      message(`${plural(result.created, "investigation")} created${result.reused ? `, ${result.reused} already in the workspace` : ""}. Showing the highest-risk incident.`);
      break;
    }
    case "assessment-form": await mutate("assessment", { assessment: el("assessment").value, rationale: el("rationale").value }); break;
    case "note-form": await mutate("note", { note: el("investigation-note").value }); break;
    case "evidence-form": {
      const file = await fileData("additional-events");
      await mutate("evidence", { ...(file || {}), policy: await policyData("updated-policy"), reason: el("evidence-reason").value });
      break;
    }
    case "preview-form": await mutate("preview", { actions: state.current.response_options[Number(el("response-option").value)].actions }); break;
    case "approval-form": await mutate("approve", { preview_id: latestPreview().id, rationale: el("approval-note").value }); break;
    case "execution-form": await mutate("execution", { outcome: el("outcome").value, reference: el("execution-reference").value, note: el("execution-note").value }); break;
    case "closure-form": await mutate("close", { disposition: el("disposition").value, reference: el("closure-reference").value, note: el("closure-note").value }); break;
    default: throw new Error("Unsupported form.");
  }
}

document.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  const buttons = [...form.querySelectorAll('button[type="submit"]')];
  buttons.forEach((button) => { button.disabled = true; });
  try { await submit(form); }
  catch (error) { message(error.message, true); }
  finally { buttons.forEach((button) => { button.disabled = false; }); }
});

document.addEventListener("click", async (event) => {
  const target = event.target.closest("[data-action]");
  if (!target) return;
  const action = target.dataset.action;
  target.disabled = true;
  try {
    if (action === "import") {
      el("import-actor").value = el("analyst").value;
      el("import-feedback").hidden = true;
      el("import-dialog").showModal();
    } else if (action === "dismiss-import") el("import-dialog").close();
    else if (action === "help") el("help-dialog").showModal();
    else if (action === "dismiss-help") el("help-dialog").close();
    else if (action === "select") { state.tab = "overview"; state.preview = null; await loadCase(target.dataset.id); message(""); }
    else if (action === "tab") { state.tab = target.dataset.tab; renderDetail(); }
    else if (action === "refresh" || action === "inbox") await refresh();
    else if (action === "examples") {
      const result = await api("/api/examples", target.dataset.dataset ? { dataset: target.dataset.dataset } : {});
      el("import-dialog").close(); state.tab = "overview";
      await openHighestRisk(result.case_ids); message(`Sample data loaded: ${plural(result.case_ids.length, "incident")}. Showing the highest-risk incident.`);
    } else if (action === "verify") {
      await loadCase(state.selected); message("Evidence signatures, source records and the audit trail passed integrity verification with this workspace key.");
    }
  } catch (error) { message(error.message, true); }
  finally { target.disabled = false; }
});

el("search").addEventListener("input", renderList);
el("filter").addEventListener("change", renderList);
el("analyst").addEventListener("change", () => { try { localStorage.setItem("cti-analyst", el("analyst").value); } catch (_) { /* Optional. */ } });
try { el("analyst").value = localStorage.getItem("cti-analyst") || ""; } catch (_) { /* Optional. */ }
refresh().catch((error) => message(error.message, true));

document.addEventListener("keydown", (event) => {
  const tab = event.target.closest('[role="tab"]');
  if (!tab || !["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  event.preventDefault();
  const tabs = ["overview", "evidence", "response", "history"];
  const index = tabs.indexOf(tab.dataset.tab);
  state.tab = event.key === "Home" ? tabs[0] : event.key === "End" ? tabs.at(-1) : tabs[(index + (event.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
  renderDetail();
  el(`tab-${state.tab}`).focus();
});
