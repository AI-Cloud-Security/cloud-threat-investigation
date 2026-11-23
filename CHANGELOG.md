# Changelog

## 0.3.0

### Integration
- AWS CloudTrail, Azure Monitor (Activity Log and Storage logs), Google Cloud Audit Logs and OCSF API Activity adapters with explicit, documented indicator rules and adapter settings (expected regions, large-read threshold, public resources, principal aliases, failed-event handling). Original provider events are preserved in the signed raw evidence; settings are recorded in signed import activity.
- `convert` command (`cloud-threat-convert`) with a `--summary` preview, plus synthetic samples, settings and policies for each provider.
- Import dialog record-format selector, adapter settings upload and AWS, Azure and Google Cloud sample datasets.
- `GET /api/summary.jsonl` and an inbox download for SIEM/ticketing ingestion (`investigation-summary-v1`).
- Dockerfile and docker-compose with loopback-only publishing; `--host` and `--allowed-host` options.

### Analysis and governance
- MITRE ATT&CK technique context per case in the UI, API and exported report (outside the signed graph).
- Optional `separation_of_duties` policy flag: approval requires a different analyst than the latest assessment.
- Model-agnostic attribution module and `explain` command (`cloud-threat-explain`) for linear, logistic and tree-ensemble models with completeness checks and intervals where available.
- Report includes the short ID and indicator summary; case header shows the short ID.
- After an import, the highest-risk new incident opens first.

### Documentation
- Integration guide, evidence format specification, compliance mapping and JSON Schemas for records, policies, adapter settings and summary rows.

### Interface and maintenance
- Incidents are titled by their observed indicators (e.g. "Large data read from an unusual region"), with the principal → resource pair shown as labelled entities, in the UI, report, case state and summary export.
- Professional terminology throughout the interface, report and error messages: Overview / Evidence / Response / Audit trail tabs, consistent status, assessment, disposition and action labels, and a restructured Markdown report.
- Redesigned analyst workspace: dark navigation sidebar, light and dark themes that follow the system setting, icon set, and a workflow stepper.
- Score gauge with the alert-threshold marker, per-indicator contribution bars, and score-coloured inbox entries.
- Evidence table shows indicators as Yes/No chips; response previews show the before → after score.
- Added an SVG favicon (served at `/static/favicon.svg` and `/favicon.ico`).
- Rewrote the README for evaluators: value proposition, audiences, five-minute trial, data schema, archive contents, security model and roadmap.
- License statement made consistent with the MIT `LICENSE` file.
- Fixed two workflow tests that left SQLite connections open and failed on Windows.

## 0.2.0

- Empty persistent workspace with incident inbox, search, filters and counts.
- JSONL, CSV and JSON imports, explicit included dataset and optional capability policies.
- Analyst assessments, notes, evidence revisions and reassessment loop.
- Policy-bound response previews and approval, external outcome recording, gated closure and escalation.
- Persistent local signing identity, transactional SQLite state, signed activity chains and optimistic concurrency.
- Signed investigation archives with reports, source records, all evidence revisions and offline trusted-key verification.
- Updated VS Code launch profiles, operating guidance and full lifecycle checks.

## 0.1.0

- Modular validation, scoring, provenance, encoding and signing components.
- Local investigation dashboard with separate HTML, CSS and JavaScript assets.
- Signed evidence export, trusted-key verification and tamper checks.
- Strict JSON and capability-policy validation with bounded inputs.
- Baseline, restricted-policy and denied-policy fixtures.
- Case publication safeguards, cross-platform launchers, package metadata and CI configuration.
