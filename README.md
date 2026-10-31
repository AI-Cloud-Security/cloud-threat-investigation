# Cloud Threat Investigation

A local analyst workspace that covers record import, incident review, evidence collection, response approval, outcome recording, closure and signed export. Cases persist across restarts. The dashboard starts with an empty inbox and guides the analyst through the work.

## Run in VS Code

Requires Python 3.12 or newer; Python 3.12 is tested locally.

1. Extract the archive and open `cloud-threat-investigation` in VS Code.
2. Open the terminal in that folder.
3. Run the launcher :

Windows PowerShell:

```powershell
.\start.bat
```

macOS or Linux:

```bash
bash start.sh
```

Open **http://127.0.0.1:8765** if the browser does not open automatically. The launcher creates `.venv` and installs the pinned Python dependency on first use; initial setup needs package-download access. There is no frontend build. Stop with Ctrl+C and run the same command to reopen your cases.

Use `python bootstrap.py --setup-only` to prepare the environment without starting the application. Select `.venv` with **Python: Select Interpreter**, install the recommended debugger extension, and press F5 with **Investigation workspace** selected.

## Your first complete investigation

1. Click **Import records**, enter your analyst name, and upload a normalized JSONL, CSV or JSON file. Optionally attach its permission policy. A downloadable CSV template and policy example are available in the dialog.
2. Select an incident in the inbox. Review its principal, resource, source timeline, original records and score contributions.
3. Under **Review & assess**, save a conclusion and rationale: **Expected activity**, **More evidence needed**, or **Suspected threat**.
4. For more evidence, attach records or a policy under **Evidence & timeline**. This creates a new signed revision and requires reassessment; prior evidence, decisions and outcomes remain in the history.
5. For a suspected threat, use **Response & closure** to preview an option permitted by the saved policy and record approval. Perform the approved change through your organization's cloud/change process, then record the external outcome and ticket reference here.
6. Close as **expected**, **resolved**, or **escalated**, as appropriate. Resolved closure requires a completed approved external response; escalation requires a handoff reference.
7. Download the investigation archive and public key. Closed cases are read-only. Open-case exports are labeled interim.

To explore the workflow before importing your own data, choose **Load included dataset** in the import dialog. This explicitly loads three synthetic incidents: payments activity (95 points), a scheduled backup (10), and analytics activity (60). Loading it again reuses existing cases rather than duplicating them.

## Input and operating scope

Events must contain `tenant`, `event_id`, `timestamp` with timezone, `principal`, `resource`, `action`, `public_access`, `unusual_region`, and `large_read`. The three indicators must be integers 0 or 1. JSON uses an object containing an `events` array. Imports are limited to 16 MiB and 10000 records and are grouped by tenant, principal and resource. A supplied policy must match the imported tenant; omit the policy to import multiple tenants with no response permissions.

JSONL retains original record bytes excluding line separators and an initial UTF-8 BOM. CSV and JSON-container records are converted to the project's canonical JSON encoding; the signed import activity also retains the original uploaded file's SHA-256 digest. Conflicting event identities are rejected, and invalid imports create no cases.

Scoring uses `10 + 35*public_access + 20*unusual_region + 30*large_read`, with an alert threshold of 70. These are configured risk points, not probabilities or measured effectiveness. Inputs already contain their indicators; this version does not infer anomalies from provider telemetry. The two response actions are `disable_public_access` and `limit_read_volume`; no policy means no permitted response change.

This version accepts normalized exports. Live cloud connectors, automatic cloud changes, trained detectors and enterprise authentication are not configured. External response completion and analyst identity are explicitly self-asserted. See [security boundaries](SECURITY.md).

## Persistence and backup

`workspace/` contains `investigations.sqlite3` and the unencrypted local software signing key, `signing-key.bin`. Keep both private and back up the complete directory together while the service is stopped. Do not commit it to GitHub. The application refuses to replace a missing key for an existing database. Changing `--workspace` selects a separate workspace, rather than migrating cases.

The service binds to loopback and uses a per-process request token, same-origin checks, version guards and signed activity history. This is a single-workstation application. SQLite append-only triggers and signatures detect or prevent specified application-level modifications; they do not enforce WORM retention against an administrator or prevent full workspace rollback. The public key included in an export is a convenience copy; establish trust separately.

## Commands

After setup, substitute `.venv\Scripts\python.exe` on Windows or `.venv/bin/python` on macOS/Linux for `python` below.

```bash
python run.py
python run.py --workspace path/to/private-workspace --port 8766 --no-browser
python run.py test
python run.py check
python scripts/check_repository.py
python run.py verify-export path/to/investigation.zip --trusted-key path/to/trusted-public-key.bin
```

`test` runs behavioral, import, persistence, signature and HTTP-boundary tests. `check` runs the import-to-closure HTTP lifecycle, verifies the downloaded archive, rejects a changed report and confirms persistence after restart. Optional JavaScript interaction checks use Node.js 20 or newer: `node scripts/ui_checks.mjs`. They exercise the UI controller against the real HTTP service through a minimal DOM harness; they do not establish browser layout or accessibility conformance.

The separate evidence CLI remains available for single-bundle engineering checks:

```bash
python run.py create --out runs/custom-case --events path/to/events.jsonl --policy path/to/policy.json
python run.py verify runs/custom-case/bundle.json --trusted-key runs/custom-case/trusted_public_key.bin
python run.py tamper --data runs/custom-case
```

These standalone artifacts are separate from the dashboard workspace and are not imported automatically. There is no `--scenario` dashboard launch option.

## Source structure

| Location | Responsibility |
|---|---|
| `src/cloud_threat/app.py` | Process lifecycle and persistent workspace selection |
| `src/cloud_threat/workflow/imports.py` | Bounded JSONL, CSV and JSON imports and incident grouping |
| `src/cloud_threat/workflow/store.py` | SQLite transactions, workflow transitions, version guards and signed history |
| `src/cloud_threat/workflow/crypto.py` | Persistent local signing identity and signed documents |
| `src/cloud_threat/workflow/exports.py` | Signed investigation archives and offline trusted-key verification |
| `src/cloud_threat/core/` | Validation, scoring, constrained action search, canonical encoding and provenance |
| `src/cloud_threat/web/` | Loopback HTTP API, HTML, CSS and JavaScript |
| `src/cloud_threat/resources/` | Synthetic fixtures and policy examples |
| `tests/`, `scripts/` | Behavioral, HTTP, integration, UI-controller and repository checks |
| `.vscode/`, `.github/workflows/ci.yml` | Editor configuration and Windows/Linux CI checks |

## Packaging and verification

```bash
python -m pip install build
python -m build
python -m pip install dist/cloud_threat_investigation-0.2.0-py3-none-any.whl
cloud-threat --no-browser
cloud-investigation-verify investigation.zip --trusted-key trusted-public-key.bin
```

The wheel includes the dashboard and resources. Run installed-package checks outside the source directory. Windows launchers and the GitHub Actions Windows/Linux Python 3.12/3.13 matrix are supplied; local Linux results do not establish remote CI or Windows results. The local check record is in [VALIDATION.md](docs/VALIDATION.md).

See [operator guidance](docs/OPERATOR_GUIDE.md), [developer guidance](docs/DEVELOPER_GUIDE.md), [architecture](docs/ARCHITECTURE.md), and [user flow](docs/USER_FLOW.md). Select publication and licensing terms before public release; no open-source or patent license is supplied.
