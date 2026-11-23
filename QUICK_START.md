# Cloud Threat Investigation — quick start

## Start the application

1. Stop any older instance with Ctrl+C.
2. Clone the repository: `git clone https://github.com/AI-Cloud-Security/cloud-threat-investigation.git`
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

To explore the screens first, click **Normalized sample** under **Explore with sample data**. This loads three synthetic incidents. Nothing is loaded automatically. The **AWS CloudTrail**, **Microsoft Azure** and **Google Cloud** buttons load incidents converted from synthetic provider logs instead.

For the highest-risk incident:

1. Select **Large read of a publicly exposed resource from an unusual region** (principal `service-payments`, resource `storage-invoices`). It opens automatically after the import.
2. On the **Overview** tab, review the 95-point score and its breakdown. On the **Evidence** tab, inspect the event timeline and source records.
3. Record the assessment **Suspected threat** with a rationale.
4. On the **Response** tab, select **Disable public access** and click **Preview response**. The projected score is 60.
5. Enter an approval rationale and click **Approve response**.
6. Apply the approved change through your normal change process, then click **Record outcome** with the result, a change or ticket reference and verification notes. For synthetic data, use an exercise reference and do not claim a real cloud change.
7. A completed outcome enables the **Resolved** disposition. A failed or unapplied response can be escalated with a reference.
8. Click **Download archive** and **Download public key**. Closed investigations are read-only.

Other paths: assess the scheduled backup as **Expected activity**, then close it as expected. Choose **More evidence required** to attach further records or a policy on the **Evidence** tab; this creates a new evidence revision and requires a new assessment. A suspected threat can be escalated with a handoff reference when no response is appropriate.

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
