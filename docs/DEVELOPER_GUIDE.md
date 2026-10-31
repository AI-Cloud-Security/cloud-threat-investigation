# Developer guide

## Scope and setup

Version 0.2.0 implements the complete local analyst journey: import, review, assessment, evidence revision, response preview/approval, external outcome recording, closure and export. Provider connectors, automatic cloud execution, trained models and enterprise access control remain extension work.

Use Python 3.12 or newer. Run `python bootstrap.py --setup-only`, select `.venv` in VS Code, and use `run.py` for launch and checks. No editable install or frontend build is required. `cloud-threat-investigation.code-workspace` and `.vscode/` provide editor settings, tasks and launch profiles.

## Package boundaries

| Package or module | Responsibility |
|---|---|
| `app.py` | Startup, workspace path, loopback port and process lifecycle |
| `workflow/imports.py` | File limits, CSV/JSONL/JSON contracts, grouping and default-deny policy |
| `workflow/store.py` | Transactional case state, transition invariants, revision storage and signed events |
| `workflow/crypto.py` | Workspace key lifecycle and canonical Ed25519 documents |
| `workflow/exports.py` | Portable archive, signed report/manifest and offline verifier |
| `core/validation.py` | Strict parsing, normalized event fields and finite capability schema |
| `core/scoring.py` | Feature profile, point score and constrained action enumeration |
| `core/canonical.py` | Restricted canonical encoding, SHA-256 and short identifiers |
| `core/provenance.py` | Content-addressed dependency graph |
| `core/signing.py` | Evidence bundle signatures and graph integrity verification |
| `core/evidence.py` | Standalone single-bundle engineering CLI |
| `web/application.py` | HTTP routes, origin/token checks, request bounds and response headers |
| `web/templates/`, `web/static/` | HTML, CSS and JavaScript controller |

## Record and scoring contract

| Field | Type | Meaning |
|---|---|---|
| tenant | Nonempty string | Tenant boundary |
| event_id | Nonempty string | Source identity scoped to tenant |
| timestamp | Timezone-aware ISO string | Source time retained as supplied |
| principal | Nonempty string | Identity performing the activity |
| resource | Nonempty string | Resource being investigated |
| action | Nonempty string | Observed operation |
| public_access | Integer 0 or 1 | Supplied public-access indicator |
| unusual_region | Integer 0 or 1 | Supplied region indicator |
| large_read | Integer 0 or 1 | Supplied volume indicator |

JSONL preserves record bytes excluding line separators and an initial BOM. CSV and JSON-container records are canonicalized; JSON uses `{"events":[...]}`. Each record is limited to 1 MiB, each upload to 16 MiB and 10000 records. The original file digest is included in import history. Additional evidence must remain within the selected incident; old IDs cannot be assigned conflicting bytes.

Grouping uses `(tenant, principal, resource)`. Exact initial evidence-root reimports reuse the case, including a closed case. Changed datasets imported through the import dialog create separate cases; use the selected case's Evidence & timeline form to extend an existing investigation. A policy has tenant, version and capability edges; a supplied policy must match every group, so multi-tenant files should be imported without policy or split by tenant.

The configured score is `10 + 35*public_access + 20*unusual_region + 30*large_read`; threshold 70. Indicators aggregate by maximum across source records. They are not inferred from logs. Exact coefficient contributions explain the arithmetic, not causation or empirical detection quality.

The finite actions are `disable_public_access` (sets its indicator to 0, relative cost 1) and `limit_read_volume` (sets its indicator to 0, relative cost 2). Candidates require a matching principal/resource/action capability. The core recommendation chooses the minimum-cost feasible candidate below threshold within this action space; the dashboard exposes permitted previews with their below-threshold flag. Every preview has `applied:false`. A lower hypothetical score does not establish a successful real-world response.

## State and concurrency

SQLite schema version 1 stores cases, observations, revisions, previews, history and schema metadata. Commands run under `BEGIN IMMEDIATE` and foreign-key checks; failed changes roll back. Reads verify signed state and current evidence. Revision/history UPDATE and DELETE are blocked through triggers. These are local controls, not WORM storage.

Every mutation requires `actor` and integer `version`; import requires actor but no case version. A successful case command increments version and signs an event containing its resulting state, sequence, previous-event hash and action data. Notes also advance the version. Current state must match the last signed history event.

| Transition | Preconditions and result |
|---|---|
| assess | Open case without current approval; expected, needs_evidence or threat plus rationale |
| add evidence/policy | Open case; new evidence root; append revision and reset current assessment/approval/outcome |
| preview | Suspected threat without approval; exact permitted action combination; sign root/revision-bound preview |
| approve | Current suspected threat; stored preview belongs to case and current root/revision |
| record external outcome | Current approval, no prior current outcome; completed/failed/not_applied plus reference and note |
| close expected | Assessment is expected |
| close resolved | Assessment is threat and approved external outcome is completed |
| close escalated | Assessment is threat and escalation reference is nonempty |
| mutate closed case | Rejected; export and review remain available |

A stale client receives HTTP 409. New evidence keeps previous roots and all prior decisions in signed history while invalidating the current approval/outcome. The application does not dispatch provider jobs or claim provider execution. Case-version checks support multiple local browser tabs, not authenticated multi-user access.

## HTTP contract

All routes bind to loopback. GETs do not mutate investigation state. POSTs require `Content-Type: application/json`, `X-Workspace-Token` from the current HTML meta tag, a same-origin Origin when provided, actor and command fields. Request bodies are limited to 24 MiB including base64 overhead. Uploaded `content` is base64, `format` is jsonl/csv/json; `policy` is an optional JSON object. Missing policy grants no capabilities.

| Method and path | Purpose and principal payload fields |
|---|---|
| GET / | Workspace HTML with process request token |
| GET /health | Process liveness |
| GET /api/workspace | Verified case summaries and signing fingerprint |
| GET /api/cases/{id} | Verified case, evidence, options, history and revision summaries |
| GET /api/cases/{id}/export | Signed investigation ZIP |
| GET /api/public-key | Raw 32-byte public key |
| GET /api/template.csv | Normalized CSV template |
| GET /api/example-policy | Policy matching the CSV template |
| POST /api/import | filename, format, content, optional policy, actor |
| POST /api/examples | actor; explicitly load included three-case fixtures |
| POST /api/cases/{id}/assessment | version, actor, assessment, rationale |
| POST /api/cases/{id}/note | version, actor, note |
| POST /api/cases/{id}/evidence | version, actor, optional content/format/policy, reason |
| POST /api/cases/{id}/preview | version, actor, actions array |
| POST /api/cases/{id}/approve | version, actor, preview_id, rationale |
| POST /api/cases/{id}/execution | version, actor, outcome, reference, note |
| POST /api/cases/{id}/close | version, actor, disposition, note, reference when escalating |

Unknown routes return 404, invalid Host 421, failed token/origin checks 403, unsupported request encoding 415, excessive bodies 413, stale/forbidden transitions 409 and validation errors 422. Unexpected internal errors return a generic 500 and log locally. No API route executes a cloud change. `/health` is liveness, not an exhaustive database integrity check.

## Evidence and archive verification

Graph nodes contain kind, data and sorted parent hashes. Raw nodes retain base64 record bytes plus their byte digest. Normalized nodes reference raw nodes; features reference normalized nodes; decisions and attributions bind the feature/model path; counterfactuals also bind policy. The evidence root joins explanation paths. The short reference is a convenience prefix with checksum; the full SHA-256 root is authoritative.

Canonical encoding sorts ASCII object keys, emits compact UTF-8 JSON, preserves arrays and permits integers. It is a restricted project encoding, not RFC 8785. Cross-language vectors and independent replay remain future work.

The workspace signs every evidence revision and workflow event using its persistent local Ed25519 key. Timestamps use the untrusted host clock. Export creates a signed report binding current state/root/history tip, all revisions and activity, a readable report, original records and policy. The signed file manifest covers the complete archive file set except itself. Offline verification requires a separately selected key and checks file bounds/hashes, signatures, graph integrity, all revisions and report/history consistency.

Verification does not replay the detector, prove source truth, authenticate the analyst or reconcile a cloud change. A complete older workspace snapshot may still verify; there is no external freshness checkpoint. See SECURITY.md for key custody and rollback limits.

## Checks and packaging

```bash
python run.py test
python run.py check
python scripts/check_repository.py
python -m compileall -q src tests scripts
node --check src/cloud_threat/web/static/workspace.js
node scripts/ui_checks.mjs
python -m pip install build
python -m build
```

The JavaScript controller harness requires Node.js 20 or newer and uses its standard library only. It drives UI handlers against a real temporary Python HTTP workspace. It checks rendered content and state transitions with a small DOM substitute; browser layout, native form behavior and assistive-technology conformance still require browser testing. Node is optional for users running the application.

CI is configured for Windows/Linux and Python 3.12/3.13, plus the Node controller check. Local checks do not establish that the remote matrix passed. Validate an installed wheel outside the source checkout and confirm HTML/CSS/JS and included resources are packaged. Keep private workspace files out of wheel, sdist, ZIP and git. Public-release licensing and publication remain owner decisions.

## Extension work

Keep source adapters, model adapters, authorization, provider response dispatch, signing, clock and storage behind explicit contracts. A provider executor needs idempotent requests, status reconciliation, failure handling and independently checked postconditions before replacing external attestation. Introduce authentication and authorization before any network exposure or multi-user operation. Evaluate detector quality, analyst outcomes and operational impact separately from integrity and workflow tests.
