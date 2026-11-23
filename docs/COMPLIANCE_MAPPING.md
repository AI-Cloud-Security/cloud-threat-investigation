# Compliance mapping

This page helps governance, risk and audit teams see where workspace output can serve as **supporting evidence** for common control frameworks. It does not certify compliance. Control ownership, scope and sufficiency remain your organization's decision, and you should confirm each mapping with your auditor.

## What the workspace produces

| Artifact | Description |
|---|---|
| Signed investigation archive | Source records, evidence graph, every revision, signed activity history, signed report and manifest |
| Activity history | Hash-chained, signed record of who assessed, approved, recorded outcomes and closed, with rationale and timestamps |
| Explanation | Per-indicator score contributions and related ATT&CK techniques for each case |
| Policy record | The permission policy in force, bound into the signed evidence; optional separation of duties |
| Summary export | One row per case for metrics, SIEM correlation and ticket linkage |

## Framework mapping

| Framework | Control area | How the output can help | Gaps you must cover elsewhere |
|---|---|---|---|
| **ISO/IEC 27001:2022** | A.5.25 Assessment and decision on information security events | Recorded assessment with rationale per case | Organization-wide event triage process |
| | A.5.26 Response to information security incidents | Policy-bound response approval and recorded outcome with change reference | Executing and verifying the change |
| | A.5.27 Learning from information security incidents | Closed-case archives and summary export for post-incident review | Review meetings and corrective actions |
| | A.5.28 Collection of evidence | Signed source records, provenance graph and verifiable archives | Legal hold, chain-of-custody procedures, trusted time |
| | A.8.15 Logging | Tamper-evident activity history for investigation actions | Platform-wide logging |
| **SOC 2 (2017 TSC)** | CC7.3 Evaluate security events | Scored and explained cases with analyst conclusions | Detection coverage |
| | CC7.4 Respond to identified incidents | Approval, outcome and closure records | Containment execution, communications |
| | CC7.5 Recover from incidents | Closure records with references | Recovery activities |
| **NIST SP 800-53 Rev. 5** | IR-4 Incident handling; IR-5 Incident monitoring | Per-case records and summary export | Program-level procedures |
| | AU-9 Protection of audit information; AU-10 Non-repudiation | Signed, hash-chained history and offline verification | Hardware-protected keys, separation of administrator duties |
| | AC-5 Separation of duties | Policy-enforced distinct approver | Authenticated identities (names are self-asserted) |
| **NIST CSF 2.0** | RS.AN (Incident analysis); RS.MA (Incident management) | Explanations, assessments and response records | Organization-wide response plan |
| **EU NIS2 / DORA** | Incident handling and reporting records | Structured case history and archive for regulator inquiries | Reporting timelines and submissions |

## Strengthening evidentiary value

The current release uses a local software key and the host clock. For high-assurance environments, plan for:

1. **Managed keys**: signing in an HSM or cloud KMS, with key rotation and revocation.
2. **Trusted time**: RFC 3161 timestamps or a transparency log for each revision and export.
3. **Immutable retention**: copying archives to WORM storage (e.g. S3 Object Lock in compliance mode, Azure immutable blob, GCS bucket lock).
4. **Authenticated identity**: SSO-based analyst identity, so that separation of duties is enforced against real accounts.

These items are on the project roadmap. Until they are in place, describe the assurance level honestly in audit narratives. Every report already declares it in its `assurance` field.
