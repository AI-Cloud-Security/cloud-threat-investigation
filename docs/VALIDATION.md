# Local validation record

Release: 0.2.0. Checked on Linux with Python 3.12.14, cryptography 50.0.2 and Node.js 24.22.1. These are local results, not results from the configured remote CI matrix.

| Check | Result |
|---|---|
| `python run.py test` | 65 tests passed |
| `python run.py check` | HTTP lifecycle passed: empty workspace, import, more-evidence branch, revision/reassessment, permitted preview/approval, external outcome recording, resolved closure, signed export, changed-report rejection and restart persistence |
| `node --check src/cloud_threat/web/static/workspace.js` | Passed |
| `node scripts/ui_checks.mjs` | Passed: empty state, actor error, three-case inbox, search, escaped notes, evidence revision, response/approval/outcome, expected/resolved/escalated closure, public-key export verification, filters and CSV/JSON uploads |
| `python scripts/check_repository.py` | Naming, syntax, configuration and artifact checks passed |
| `python -m compileall -q src tests scripts` | Passed |
| Wheel and source distribution | Built using the setuptools PEP 517 backend |
| Installed wheel outside source checkout | Passed: console startup, empty inbox, packaged assets and three-case fixtures, assessment, expected closure, separate verifier command and restart persistence |

The installed wheel was checked in a separate virtual environment using the already installed pinned runtime dependency; dependency resolution from a fresh network-connected machine was not exercised. The UI-controller harness uses a minimal DOM substitute and the actual HTTP service. It does not render pages or establish browser layout, native form behavior or accessibility conformance.

A Chromium runtime download was attempted, but the environment's network policy rejected it. Visual browser verification remains pending. Windows launchers and Windows/Linux Python 3.12/3.13 GitHub Actions checks are configured but were not executed as a remote matrix in this session.

The suite covers default-deny policy, atomic invalid imports, import reuse, stale-version rejection, required approval, failed-outcome closure rejection, escalation references, closed-case immutability, evidence revision resets, source identity conflicts, timezone ordering, persistence/key retention, state tampering, wrong-key rejection, signed file tampering and prior-revision substitution. These checks establish the stated local behavior, not security certification, provider integration, detection quality or operational adoption.
