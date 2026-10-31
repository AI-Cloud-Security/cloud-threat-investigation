# Cloud Threat Investigation — quick start

## Start the application

1. Stop any older instance with Ctrl+C.
2. Extract `Cloud_Threat_Investigation_Source.zip` into a fresh folder.
3. Open `cloud-threat-investigation` in VS Code.
4. Open its terminal and run:

```powershell
.\start.bat
```

Requires Python 3.12 or newer. First setup downloads the pinned Python dependency. There is no frontend build. On macOS/Linux use `bash start.sh`.

The browser opens at http://127.0.0.1:8765. First start shows an empty inbox. Later starts reopen saved cases. If the port is already in use, stop the earlier process or use `python bootstrap.py --port 8766`.

## Follow a complete analyst journey

**Import → review → assess → investigate or respond → close → export.**

Click **Import records** and enter your analyst name. Upload your normalized CSV, JSONL or JSON records, plus an optional permission policy. The dialog provides a CSV template and policy example. Without a policy, no response change is permitted.

To explore the screens first, click **Load included dataset**. This explicitly loads three synthetic incidents: payments activity, scheduled backup and analytics activity. No case is loaded automatically.

For the payments incident:

1. Select **service-payments accessing storage-invoices**.
2. Review the 95-point configured score under **Review & assess** and inspect source records under **Evidence & timeline**.
3. Save **Suspected threat**, with your rationale.
4. Open **Response & closure**, select **disable public access**, and click **Preview response**. The hypothetical score becomes 60.
5. Review the preview, enter an approval rationale and click **Record response approval**.
6. Perform the approved change in your external cloud/security console through your normal change process. Then record its actual outcome, ticket reference and verification note in the application. For synthetic records, use an explicitly synthetic exercise reference and make no claim of a real cloud change.
7. A recorded completed outcome permits **Close as resolved**. A failed or unapplied response can be escalated with a reference.
8. Download the final investigation archive and public key. Closed cases are read-only.

Other paths: classify the scheduled backup as **Expected activity**, then close as expected. Choose **More evidence needed** to attach same-incident records or a policy; the application creates a new revision and requires reassessment. A suspected threat can be escalated with a handoff reference when no response is appropriate.

## Verify an export

Download the workspace public key and establish trust in a separate copy. With the environment's Python, run:

```powershell
.\.venv\Scripts\python.exe run.py verify-export "C:\path\investigation.zip" --trusted-key "C:\path\trusted-public-key.bin"
```

An open-case export is interim; a closed-case export is final. The archive contains the signed report, readable report, file manifest, original records, policy, complete signed activity history and all evidence revisions.

Verification checks integrity under the selected key. It does not establish source truth, authenticated analyst identity, independently verified external execution or current cloud state.

## Keep your cases

Stop with Ctrl+C. Restart with `.\start.bat` to reopen saved work. Back up the complete private `workspace/` directory with the service stopped. Keep its database and unencrypted local signing key together and out of GitHub. Do not delete the key to fix a startup error.

This release completes the local analyst workflow. Live cloud connectors, automatic cloud changes, trained detection and enterprise login are not configured. Use the packaged README, operator guide, developer guide and security model for detailed contracts and boundaries.
