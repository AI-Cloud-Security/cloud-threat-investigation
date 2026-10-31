"use strict";

const state = { cases: [], current: null, selected: null, tab: "overview", preview: null };
const token = document.querySelector('meta[name="workspace-token"]').content;
const el = (id) => document.getElementById(id);
const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
}[character]));
const pretty = (value) => escapeHtml(JSON.stringify(value, null, 2));
const label = (value) => String(value ?? "").replaceAll("_", " ");
const date = (value) => new Date(value).toLocaleString();
const statusLabels = { open: "Awaiting review", needs_evidence: "Needs evidence", reviewed_expected: "Expected activity", reviewed_threat: "Suspected threat", response_approved: "Response approved", response_recorded: "Outcome recorded", closed: "Closed" };

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
  if (!value) { input.focus(); throw new Error("Enter your analyst name to record this action."); }
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

function badge(item) {
  const color = item.status === "closed" || item.assessment === "expected" ? "green" : item.assessment === "threat" ? "red" : item.status === "needs_evidence" ? "amber" : "";
  return `<span class="badge ${color}">${escapeHtml(statusLabels[item.status] || item.status)}</span>`;
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
    [state.cases.length, "Total incidents"],
    [state.cases.filter((item) => item.status !== "closed").length, "Active investigations"],
    [state.cases.filter((item) => item.status === "needs_evidence").length, "Need more evidence"],
    [state.cases.filter((item) => item.status === "closed").length, "Closed cases"]
  ];
  el("metrics").innerHTML = values.map(([value, title]) => `<div class="metric"><strong>${value}</strong><span>${title}</span></div>`).join("");
}

function renderList() {
  const query = el("search").value.toLowerCase();
  const filter = el("filter").value;
  const items = state.cases.filter((item) => (!query || `${item.principal} ${item.resource} ${item.tenant}`.toLowerCase().includes(query)) &&
    (filter === "all" || (filter === "active" ? item.status !== "closed" : item.status === filter)));
  el("case-list").innerHTML = items.length ? items.map((item) => `
    <button class="case-item ${state.selected === item.id ? "selected" : ""}" data-action="select" data-id="${item.id}" aria-current="${state.selected === item.id}">
      <div class="case-item-top"><span class="score-small">${item.risk_points}</span>${badge(item)}</div>
      <strong>${escapeHtml(item.principal)}</strong><small>${escapeHtml(item.resource)}</small>
      <small>${escapeHtml(item.tenant)} · Rev ${item.revision}</small>
    </button>`).join("") : `<p class="subtle">${state.cases.length ? "No matching incidents." : "No incidents yet. Import records to begin."}</p>`;
}

function renderEmpty() {
  el("case-detail").innerHTML = `<div class="empty-state"><div class="step-number">01</div><h2>${state.cases.length ? "Select an incident" : "Start with the activity you need to investigate"}</h2><p>${state.cases.length ? "Choose an identity and resource from the inbox to inspect the evidence and record your assessment." : "Upload security records to create incident cases. Review who accessed what, decide whether the activity is expected, and preserve your conclusion with signed evidence."}</p><div class="actions"><button class="primary" data-action="import">Import security records</button><button class="secondary" data-action="help">View the workflow</button></div></div>`;
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
  el("case-detail").innerHTML = `
    <header class="case-header"><div class="case-header-top">${badge(item)}<span class="subtle">Evidence revision ${item.revision}</span></div>
      <h2>${escapeHtml(item.principal)} accessing ${escapeHtml(item.resource)}</h2>
      <div class="meta">Tenant ${escapeHtml(item.tenant)} · Case ${item.id.slice(0, 8)} · Updated ${escapeHtml(date(item.updated_at))}</div>
      <div class="stepper">${["1 Review activity", "2 Record assessment", "3 Track response", "4 Close & export"].map((text, index) => `<div class="step ${steps[index] ? "done" : ""}">${text}</div>`).join("")}</div>
    </header>
    <div class="tabbar" role="tablist" aria-label="Investigation views">${[["overview", "Review & assess"], ["evidence", "Evidence & timeline"], ["response", "Response & closure"], ["history", "Activity record"]].map(([id, title]) => `<button class="tab ${state.tab === id ? "active" : ""}" role="tab" id="tab-${id}" aria-controls="case-tab-panel" tabindex="${state.tab === id ? 0 : -1}" aria-selected="${state.tab === id}" data-action="tab" data-tab="${id}">${title}</button>`).join("")}</div>
    <div class="tab-content" id="case-tab-panel" role="tabpanel" aria-labelledby="tab-${state.tab}">${({ overview: overview, evidence: evidence, response: responseView, history: historyView })[state.tab]()}</div>`;
}

function overview() {
  const data = state.current; const item = data.case;
  return `<div class="two-columns"><section><h3>Understand the activity score</h3><div class="score">${item.risk_points}</div><p class="subtle">Risk points · threshold ${data.decision.threshold} · ${data.decision.alert ? "At or above alert threshold" : "Below alert threshold"}</p><p class="hint">A transparent configured score. It is not a threat probability or an automatic analyst conclusion.</p></section>
    <section><h3>Decision contributions</h3><table class="data-table"><tbody><tr><td>Baseline</td><td>${data.attribution.baseline}</td></tr>${Object.entries(data.attribution.contributions).map(([name, value]) => `<tr><td>${escapeHtml(label(name))}</td><td>+${value}</td></tr>`).join("")}</tbody></table></section></div>
    <div class="callout"><strong>Your next step:</strong> Review the source events, then record whether the activity is expected, requires more evidence, or suggests a threat.</div>
    ${item.assessment ? `<div class="callout ${item.assessment === "expected" ? "green" : "amber"}"><strong>Recorded assessment: ${escapeHtml(label(item.assessment))}</strong><p>${escapeHtml(item.rationale)}</p></div>` : ""}
    ${item.status === "closed" ? `<p>This investigation is closed and read-only.</p>` : item.approval ? `<p>An approved response is pending or recorded. Continue under Response & closure, or attach new evidence for a fresh assessment.</p>` : `<form id="assessment-form"><h3>Record your assessment</h3><label for="assessment">Analyst conclusion</label><select id="assessment" required><option value="">Choose a conclusion</option><option value="expected">Expected activity</option><option value="needs_evidence">More evidence needed</option><option value="threat">Suspected threat</option></select><label for="rationale">What led you to this conclusion?</label><textarea id="rationale" maxlength="4000" required placeholder="Describe the source events and context supporting your decision."></textarea><button class="primary" type="submit">Save assessment</button></form>`}
    ${item.status === "closed" ? "" : `<div class="section"><form id="note-form"><h3>Add an investigation note</h3><label class="sr-only" for="investigation-note">Investigation note</label><textarea id="investigation-note" maxlength="4000" required placeholder="Context, questions, or references to preserve in the activity record."></textarea><button class="secondary" type="submit">Save note</button></form></div>`}`;
}

function evidence() {
  const data = state.current; const item = data.case;
  return `<h3>Who accessed what and when?</h3><div class="scroll"><table class="data-table"><thead><tr><th>Source time</th><th>Event</th><th>Action</th><th>Public / region / volume</th></tr></thead><tbody>${data.events.map((event) => `<tr><td>${escapeHtml(event.timestamp)}</td><td>${escapeHtml(event.event_id)}</td><td>${escapeHtml(event.action)}</td><td>${event.public_access} / ${event.unusual_region} / ${event.large_read}</td></tr>`).join("")}</tbody></table></div>
    <p class="hint">The activity belongs to the selected principal and resource. Indicators are supplied by your normalized data source; they are not inferred by this application.</p>
    <details><summary>Inspect original source records (${data.original_records.length})</summary>${data.original_records.map((raw) => `<pre>${escapeHtml(raw)}</pre>`).join("")}</details>
    <details><summary>Inspect provenance and verification</summary><p>Signature and graph integrity checked under workspace key <code>${escapeHtml(data.key_fingerprint)}</code>.</p><p>Evidence root</p><pre>${escapeHtml(data.verification.root)}</pre><div class="scroll"><table class="data-table"><thead><tr><th>Node</th><th>Hash prefix</th><th>Parents</th></tr></thead><tbody>${data.provenance.map((node) => `<tr><td>${escapeHtml(node.kind)}</td><td><code title="${node.hash}">${node.hash.slice(0, 18)}…</code></td><td>${node.parents.length}</td></tr>`).join("")}</tbody></table></div></details>
    <details><summary>Permission policy and prior revisions</summary><pre>${pretty(data.policy)}</pre><p>Revision roots are preserved; earlier evidence is never replaced.</p><pre>${pretty(data.revisions)}</pre></details>
    ${item.status === "closed" ? `<div class="callout green">This case is closed. Evidence and its activity record are read-only.</div>` : `<div class="section"><h3>Collect more evidence or update the permission policy</h3><p class="hint">An update creates a new signed revision and resets the assessment and current approval. Earlier decisions and outcomes remain in the activity record.</p><form id="evidence-form"><label for="additional-events">Additional events <span class="optional">optional</span></label><input id="additional-events" type="file" accept=".csv,.jsonl,.json"><label for="updated-policy">Permission policy <span class="optional">optional</span></label><input id="updated-policy" type="file" accept=".json"><label for="evidence-reason">Why is this update needed?</label><textarea id="evidence-reason" maxlength="4000" required></textarea><button class="primary" type="submit">Save new evidence revision</button></form></div>`}`;
}

function latestPreview() {
  if (state.preview && state.preview.root === state.current.case.root) return state.preview;
  const events = [...state.current.history].reverse();
  return events.find((entry) => entry.payload.kind === "response_previewed" && entry.payload.data.preview.root === state.current.case.root)?.payload.data.preview || null;
}

function responseView() {
  const data = state.current; const item = data.case;
  if (item.status === "closed") return `<div class="callout green"><strong>Investigation closed: ${escapeHtml(label(item.disposition))}</strong><p>${escapeHtml(item.closing_note)}</p></div>${exportSection()}`;
  let content = "";
  if (item.assessment === "needs_evidence" || !item.assessment) {
    content = `<div class="callout amber">${item.assessment ? "Collect additional records or policy context under Evidence & timeline, then reassess the case." : "Record an analyst assessment under Review & assess before planning a response or closing this incident."}</div>`;
  } else if (item.assessment === "expected") {
    content = `<div class="callout green">You classified this activity as expected. Record a closure rationale to finish the investigation.</div>`;
  } else {
    content = `<h3>Plan a permitted response</h3><p class="hint">Each option is checked against the current versioned capability policy. Previewing and approving an option do not execute a cloud change.</p>`;
    if (!item.approval) {
      if (data.response_options.length) content += `<form id="preview-form"><label for="response-option">Response option</label><select id="response-option">${data.response_options.map((option, index) => `<option value="${index}">${escapeHtml(option.actions.map(label).join(" + "))} · score ${option.risk_points} · cost ${option.cost}</option>`).join("")}</select><button class="secondary" type="submit">Preview response</button></form>`;
      else content += `<div class="callout amber">No response change is permitted for these features under the current policy. Attach an appropriate permission policy, collect more evidence, or escalate the case.</div>`;
      const preview = latestPreview();
      if (preview) content += `<div class="section"><h3>Response preview</h3><p><strong>${item.risk_points} → ${preview.risk_points} risk points</strong></p><p>${escapeHtml(preview.actions.map(label).join(" + "))}</p><p class="hint">Relative action cost: ${preview.cost}. ${preview.below_threshold ? "Below" : "Above"} the alert threshold. Hypothetical model result, not proof of security effectiveness.</p><form id="approval-form"><label for="approval-note">Why do you approve this response?</label><textarea id="approval-note" maxlength="4000" required></textarea><button class="primary" type="submit">Record response approval</button></form></div>`;
    } else {
      content += `<div class="callout green"><strong>Response approved</strong><p>${escapeHtml(item.approval.preview.actions.map(label).join(" + "))}</p><p>${escapeHtml(item.approval.rationale)}</p></div>`;
      if (!item.execution) content += `<h3>Record what happened outside this application</h3><p>Carry out the approved change in your cloud or security console using your organization's change process. Then record the outcome here.</p><form id="execution-form"><label for="outcome">External action outcome</label><select id="outcome"><option value="completed">Completed externally</option><option value="failed">Failed</option><option value="not_applied">Not applied</option></select><label for="execution-reference">Change or ticket reference</label><input id="execution-reference" maxlength="500" required placeholder="Example: CHG-1042 or incident ticket URL"><label for="execution-note">What was done and how was it checked?</label><textarea id="execution-note" maxlength="4000" required></textarea><button class="primary" type="submit">Record external outcome</button></form>`;
      else content += `<div class="callout"><strong>Recorded outcome: ${escapeHtml(label(item.execution.outcome))}</strong><p>${escapeHtml(item.execution.note)}</p><p>Reference: ${escapeHtml(item.execution.reference)}</p><p class="hint">This is an analyst-attested external outcome. No cloud API execution is claimed.</p></div>`;
    }
  }
  if (item.assessment === "expected" || item.assessment === "threat") {
    const options = item.assessment === "expected" ? `<option value="expected">Close as expected activity</option>` : `${item.execution?.outcome === "completed" ? '<option value="resolved">Close as resolved</option>' : ""}<option value="escalated">Close as escalated</option>`;
    content += `<div class="section"><h3>Close the investigation</h3><form id="closure-form"><label for="disposition">Disposition</label><select id="disposition">${options}</select><label for="closure-reference">Escalation reference <span class="optional">required when escalating</span></label><input id="closure-reference" maxlength="500" placeholder="Incident, change, or handoff reference"><label for="closure-note">Closure rationale</label><textarea id="closure-note" maxlength="4000" required></textarea><button class="primary" type="submit">Close investigation</button></form><p class="hint">Closed cases are read-only. Their evidence revisions and signed activity history remain available.</p></div>`;
  }
  return content + exportSection();
}

function exportSection() {
  const item = state.current.case;
  return `<div class="section"><h3>${item.status === "closed" ? "Export the completed investigation" : "Export the current investigation snapshot"}</h3><p class="hint">The archive contains the signed evidence, report, original records, policy, full revision history, and a signed file manifest. Open cases are labeled interim.</p><div class="actions"><a href="/api/cases/${item.id}/export">Download investigation archive</a><a href="/api/public-key" download>Download public key</a><button class="secondary" data-action="verify">Recheck loaded investigation</button></div><p class="hint">Verify an exported archive against a separately trusted key. The archive includes a public key for convenience, not independent identity proof.</p></div>`;
}

function historyView() {
  return `<h3>Signed investigation activity</h3><p class="hint">Each entry records the local analyst name, previous entry hash, action details and case state. Identity is self-asserted on this workstation.</p><ol class="activity">${[...state.current.history].reverse().map((entry) => { const event = entry.payload; const summary = event.data.note || event.data.rationale || event.data.reason || (event.kind === "imported" ? `${event.data.records} source records imported from ${event.data.filename}` : "Recorded against the current evidence revision."); return `<li><time>${escapeHtml(date(event.occurred_at))}</time><strong>${escapeHtml(label(event.kind))} · ${escapeHtml(event.actor)}</strong><p>${escapeHtml(summary)}</p><details><summary>Signed event details</summary><pre>${pretty(entry)}</pre></details></li>`; }).join("")}</ol>`;
}

async function fileData(inputId) {
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
  if (!["csv", "jsonl", "json"].includes(extension)) throw new Error("Choose a CSV, JSONL or JSON file.");
  return { filename: file.name, format: extension, content };
}

async function policyData(inputId) {
  const file = el(inputId).files[0];
  if (!file) return null;
  if (file.size > 1024 * 1024) throw new Error("Policy files must be 1 MiB or smaller.");
  try { return JSON.parse(await file.text()); }
  catch (_) { throw new Error("The permission policy is not valid JSON."); }
}

async function mutate(command, data) {
  const result = await api(`/api/cases/${state.selected}/${command}`, { version: state.current.case.version, ...data });
  if (result.preview) state.preview = result.preview;
  if (command === "evidence") state.preview = null;
  state.current = result.incident || result;
  const workspace = await api("/api/workspace"); state.cases = workspace.cases;
  renderMetrics(); renderList(); renderDetail();
  message(({ assessment: "Assessment saved. Continue with evidence collection or response and closure.", note: "Investigation note saved.", evidence: "New evidence revision saved. Review the updated activity and record a fresh assessment.", preview: "Response preview recorded. Review it before approving.", approve: "Approval recorded. Apply the change in your cloud or security console, then record its outcome.", execution: "External outcome recorded. Review the closure options.", close: "Investigation closed. You can now export the completed case." })[command]);
}

async function submit(form) {
  switch (form.id) {
    case "import-form": {
      const file = await fileData("event-file"); if (!file) throw new Error("Select an event file.");
      const result = await api("/api/import", { ...file, policy: await policyData("policy-file") });
      el("import-dialog").close(); state.tab = "overview";
      await refresh(result.case_ids[0]);
      message(`${result.created} investigation(s) created; ${result.reused} existing case(s) reused. Select an incident and review its activity.`);
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
      const result = await api("/api/examples", {});
      el("import-dialog").close(); state.tab = "overview";
      await refresh(result.case_ids[0]); message("Included records loaded. Review the activity, then record your assessment.");
    } else if (action === "verify") {
      await loadCase(state.selected); message("Evidence signature, source records and signed workflow history passed integrity verification under this workspace key.");
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
