# Security model

## Intended operation

Run on a trusted local workstation. The HTTP service binds to 127.0.0.1 and rejects unrecognized Host headers. It is not an internet-facing or multi-user deployment. Local analyst names are self-asserted; the application has no enterprise login, tenant authorization or separation of approver and investigator.

The API uses a random per-process browser request token, same-origin validation, bounded JSON requests, explicit routes and parameterized SQL. Static assets are allowlisted. Responses include no-store, content security policy, anti-framing, no-sniff and no-referrer headers. These controls do not protect a compromised workstation or stop another authorized local process from using the API.

## Data and workflow controls

Imports are bounded and validated before any case is committed. Strict JSON parsing rejects duplicate keys and non-finite constants. Required strings, timezone-aware timestamps and binary integer indicators are validated. Conflicting duplicate event IDs and cross-incident evidence additions are rejected. Absent policy grants no response capability.

SQLite transactions and integer case-version guards protect application updates against partial writes and stale clients. New evidence creates a signed revision and invalidates current assessment, approval and outcome. Approvals bind a case/root/revision. External outcomes require approval; resolved closure requires a completed outcome. Closed cases are read-only through the API.

Evidence revisions and signed history are append-only through database triggers. Current-state reads compare the stored state, policy and original records against signed material. Archive verification checks file hashes, signatures, all revisions, history sequencing and final-report consistency under a separately selected public key.

## Signing identity and backups

The workspace application stores an **unencrypted raw Ed25519 private key** in `workspace/signing-key.bin`. On POSIX, creation requests mode 0600; verify appropriate Windows ACLs when deploying there. Database files rely on workstation and directory permissions. Restrict access to the entire workspace and use an encrypted disk or backup when appropriate. Back up the database and key together with the service stopped. A missing key for an existing database causes startup to fail rather than silently rotating identity.

The public key and its SHA-256 fingerprint are available in the UI. A key bundled with evidence does not establish signer identity. Pin a separately trusted copy before verification. No key rotation, revocation, HSM, hardware attestation or externally trusted timestamp is implemented. Standalone `create` commands use a fresh in-memory private key and publish only its public key; those cases are separate from the persistent workspace.

## Boundaries

Signatures establish integrity relative to a trusted key. They do not establish truthful source records, a correct decision, authenticated analyst identity, verified cloud configuration, security effectiveness or legal admissibility. Scores use a configured additive profile; no trained model, detection accuracy, commercial adoption or operational impact is asserted.

Database triggers are application-level controls, not WORM retention. A workstation administrator can alter database structure, access the key, replace files or restore an older complete workspace. Offline integrity checks cannot establish freshness against such a full rollback. Host-clock timestamps are untrusted. Exports retain sensitive records, identities, resources, notes and references; review them before sharing.

The application performs no cloud API changes. A completed external response is explicitly an analyst attestation. Authenticated live telemetry acquisition, cloud execution/reconciliation, independent post-action verification, enterprise access control, administrator-resistant custody and retention are outside this release.

## Repository and reporting

Keep `workspace/`, `runs/`, local environments, generated records, private keys and credentials out of GitHub. Use synthetic fixtures in public examples. Repository checks are a safeguard, not a comprehensive secret scanner. Select publication and licensing terms before release.

Report security issues through a private channel agreed with the maintainers. Include a minimal synthetic reproduction and version details; never put confidential events, credentials or signing keys in public issues.
