# Operator guide

## Start and choose your records

Extract the source archive, open `cloud-threat-investigation` in VS Code, and run `.\start.bat` in the terminal on Windows or `bash start.sh` on macOS/Linux. Python 3.12 or newer is required; first setup needs package-download access. Open http://127.0.0.1:8765 if necessary.

The first start shows an empty inbox. Click **Import records**, enter your local analyst name, and upload normalized JSONL, CSV or JSON data. Download the CSV template and permission-policy example if needed. An absent policy permits investigation but grants no response changes. For AWS CloudTrail, Azure Monitor, Google Cloud Audit Log or OCSF API Activity exports, choose the record format and optionally attach adapter settings (expected regions, large-read threshold, principal aliases); see the integration guide. Other provider logs need conversion to the displayed schema before import. Do not upload credentials.

To learn the screens with synthetic records, click **Normalized sample** (three incidents) or one of the **AWS CloudTrail**, **Microsoft Azure** and **Google Cloud** samples (cases converted from synthetic provider logs; the AWS and Azure policies require separation of duties). After any import, the highest-risk new incident opens first. Loading samples never changes cloud resources, and loading the same sample again reuses the existing investigations.

## Review and assess

Select an incident. Its title describes the observed indicators (for example, *Large data read from an unusual region*). The header shows the principal → resource pair, tenant, status and evidence revision. The **Overview** tab shows the risk score, score breakdown and related ATT&CK techniques. The **Evidence** tab shows the event timeline, original records, permission policy, revision history and provenance. The **Audit trail** tab lists every signed action.

Risk points come from the configured formula, not a trained detector. A score above 70 is an alert in that profile, not proof of a threat. Use the records and your operating context to make an analyst assessment, with a rationale.

| Conclusion | Next step |
|---|---|
| Expected activity | On the **Response** tab, enter a closure summary and close as expected |
| More evidence required | On the **Evidence** tab, attach further records or a policy and state the reason; then reassess the new revision |
| Suspected threat | On the **Response** tab, preview a permitted response or escalate with a reference |

You can add investigation notes while the case is open. New evidence must use new event IDs and belong to the same tenant, principal and resource. Prior observations cannot be overwritten. Policy-only updates are allowed. Every new revision clears the current assessment, approval and outcome; their earlier versions remain in the audit trail.

## Approve and record a response

For a suspected threat, choose a policy-permitted option and click **Preview response**. Review the projected score and effort rating, enter an approval rationale and click **Approve response**. Previewing and approving do not execute a cloud change.

Apply the approved change through your organization's external cloud or security console and normal change process. Then select **Completed**, **Failed** or **Not applied**, add the change or ticket reference and verification notes, and click **Record outcome**. The record explicitly states that the outcome is analyst-attested.

If the policy requires separation of duties, a different analyst name must record the approval than the one that recorded the assessment; change the name in the top bar before approving.

A completed approved outcome allows **Close as resolved**. A failed or unapplied change cannot be closed as resolved; escalate with an incident/handoff reference or continue investigation with a new evidence revision. A suspected threat can be escalated without a permitted response. No policy is an explicit denial of response changes, not a system failure.

## Closure and export

The download icon in the incident inbox exports a JSONL summary with one row per case (status, risk, indicators, ATT&CK techniques, evidence root and external reference) for SIEM or ticketing ingestion.


Select the disposition, enter a closure summary and click **Close investigation**. Closure is read-only; review the selected case before submitting. Later activity belongs in a new investigation. Click **Download archive** on the **Response** tab. Open-case archives are interim; closed-case archives are final.

The archive includes a readable report, signed report and file manifest, original records, policy, complete signed activity history, every evidence revision, current bundle and public key. Download and establish trust in the public key separately. Verify with the environment's Python:

```bash
python run.py verify-export path/to/investigation.zip --trusted-key path/to/trusted-public-key.bin
```

Verification confirms integrity under that key and internal archive consistency. It does not establish source truth, authenticated analyst identity, independently verified external execution or current cloud state.

## Persistence, errors and recovery

Stop with Ctrl+C. Restart using the same launcher to reopen saved cases. Back up the entire private `workspace/` directory with the service stopped; keep the database and signing key together. Never put this directory in GitHub. Changing `--workspace` chooses a separate workspace. Do not copy only the database or delete the key.

| Message or condition | Action |
|---|---|
| No incidents yet | Import records or explicitly load the included dataset |
| Validation error | Correct the specified record, timestamp, field, policy or file format; the failed batch creates no cases |
| No permitted response | Supply an appropriate policy through a new evidence revision, collect context, or escalate |
| Incident changed | Review the refreshed case and resubmit against its latest version |
| Workspace token rejected | Reload after a service restart, then review before resubmitting |
| Missing signing key | Stop and restore the matching key and database backup; do not generate a replacement identity |
| Port in use | Stop the old process or run `python bootstrap.py --port 8766` |
| Integrity failure | Stop edits and preserve the workspace for investigation; restore only from a trusted matching backup |

This is a local analyst workflow. It has no live provider connector, enterprise login or automatic cloud execution. See SECURITY.md for precise trust boundaries.
