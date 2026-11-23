# Integration guide

This guide is for security engineers who connect the workspace to their organization's own logs, policies and tools.

| Goal | Section |
|---|---|
| Import AWS CloudTrail, Azure, Google Cloud or OCSF exports | [Provider adapters](#provider-adapters) |
| Import data from any other source | [Normalized records](#normalized-records) |
| Restrict which responses can be approved | [Permission policies](#permission-policies) |
| Feed results to a SIEM or ticketing system | [Summary export](#summary-export-for-siem-and-ticketing) |
| Run in a container | [Container deployment](#container-deployment) |
| Explain your own detection model | [Model attribution](#model-attribution) |

## Provider adapters

Built-in adapters convert provider exports into normalized records. Each converted record keeps the **original provider event** in a `source_event` field. Because the record's raw bytes are a leaf of the signed evidence graph, the exact provider event remains part of the verifiable evidence.

| Provider | `format` value | Accepted input | How to export |
|---|---|---|---|
| AWS CloudTrail (management and S3 data events) | `cloudtrail` | `{"Records": [...]}`, a JSON array, or JSONL | Trail files from the S3 bucket, or a CloudTrail Lake / Athena query result |
| Azure Monitor resource logs: Activity Log and Storage read/write logs | `azure` | `{"records": [...]}`, a JSON array, or JSONL | Diagnostic-settings archive in a storage account, an Event Hubs capture, or a Log Analytics export |
| Google Cloud Audit Logs (Admin Activity and Data Access) | `gcp` | A JSON array, `{"entries": [...]}`, or JSONL | `gcloud logging read '<filter>' --format=json`, or a Cloud Storage / Pub/Sub log sink |
| OCSF API Activity (`class_uid` 6003), e.g. Amazon Security Lake | `ocsf` | A JSON array, a single event, or JSONL. Other OCSF classes are skipped. | Security Lake or SIEM export |

The indicators are deterministic and come only from your adapter settings. The adapters use no hidden heuristics and no machine learning. Each indicator falls back to `public_resources`, `expected_regions` and `large_read_bytes` from the settings.

### AWS CloudTrail

| Normalized field | Source |
|---|---|
| tenant | `tenant` setting, else `recipientAccountId`, else `userIdentity.accountId` |
| event_id · timestamp · action | `eventID` · `eventTime` · `eventName` |
| principal | role name (`sessionContext.sessionIssuer.userName`), else `userName`, else last ARN segment, else `principalId`, else `anonymous` |
| resource | `requestParameters.bucketName`, else first `resources[].ARN`, else `eventSource` |
| public_access | caller is `ANONYMOUS_PRINCIPAL`; request sets a `public-read`/`public-read-write` ACL, grants `AllUsers`/`AuthenticatedUsers`, or attaches a policy allowing `"Principal": "*"` |
| unusual_region | `awsRegion` not in `expected_regions` |
| large_read | `additionalEventData.bytesTransferredOut` ≥ `large_read_bytes` |
| failed events | records with `errorCode` |

### Azure Monitor resource logs

| Normalized field | Source |
|---|---|
| tenant | `tenant` setting, else the subscription ID in `resourceId` |
| event_id | `eventDataId`, else `correlationId/time` |
| timestamp · action | `time` · `operationName` |
| principal | UPN or name claim, else `appid` claim (Activity Log); `requester.upn`, else `appId`, else `objectId` (Storage logs); `anonymous` for anonymous requests. Map GUIDs to readable names with `principal_aliases`. |
| resource | `properties.accountName`, else the resource name in `resourceId` (e.g. the storage account) |
| public_access | identity type `Anonymous`; request body sets `"publicAccess": "Blob"`/`"Container"` or `"allowBlobPublicAccess": true` |
| unusual_region | `location` not in `expected_regions` |
| large_read | `properties.responseBodySize` ≥ `large_read_bytes` |
| failed events | `resultType` Failure/Failed, or `statusCode` ≥ 400 |

### Google Cloud Audit Logs

| Normalized field | Source |
|---|---|
| tenant | `tenant` setting, else `resource.labels.project_id`, else the project in `logName` |
| event_id · timestamp · action | `insertId` · `timestamp` · `protoPayload.methodName` |
| principal | `protoPayload.authenticationInfo.principalEmail`, else `anonymous` |
| resource | `resource.labels.bucket_name`, else `protoPayload.resourceName` |
| public_access | no authenticated principal, or an IAM policy delta that ADDs `allUsers`/`allAuthenticatedUsers` |
| unusual_region | `protoPayload.resourceLocation.currentLocations[0]`, else `resource.labels.location`, not in `expected_regions` |
| large_read | `httpRequest.responseSize` ≥ `large_read_bytes`. Standard audit entries do not carry a size, so they are never large unless your sink adds `httpRequest`. |
| failed events | nonzero `protoPayload.status.code` |

Google Cloud does not write Data Access audit entries for requests to publicly readable objects, so public exposure normally appears as the IAM change that granted it.

### OCSF API Activity

| Normalized field | Source |
|---|---|
| tenant | `tenant` setting, else `cloud.account.uid` |
| event_id · timestamp · action | `metadata.uid` · `time_dt`, else `time` (epoch ms) · `api.operation` |
| principal | `actor.user.name`, else `actor.user.uid`, else `anonymous` |
| resource | first `resources[].name`/`uid`, else `api.service.name` |
| public_access | `actor.user.type` is `Anonymous` |
| unusual_region | `cloud.region` not in `expected_regions` |
| large_read | `traffic.bytes_out` ≥ `large_read_bytes` |
| failed events | `status_id` 2 |

### Adapter settings

Settings are a JSON object. Without settings, no region is ever flagged as unusual, and reads are large at 100 MiB or more. The schema is in [schemas/adapter-settings.schema.json](schemas/adapter-settings.schema.json).

```json
{
  "tenant": "acme-prod",
  "expected_regions": ["us-east-1", "us-west-2"],
  "public_resources": ["marketing-assets"],
  "large_read_bytes": 104857600,
  "include_failed": true,
  "principal_aliases": {"6a1b2c3d-0000-4000-8000-0000000e7150": "etl-sync-app"}
}
```

Region names follow each provider's own convention (`us-east-1`, `eastus`, `us-central1`). The settings used for an import are recorded in its signed import activity, so reviewers can see exactly which rules produced the indicators.

### Samples

Each provider has a synthetic sample with matching settings and policy in `src/cloud_threat/resources/samples/`:

| Sample | Incidents (risk points) |
|---|---|
| `cloudtrail_*` | anonymous → finance-reports (75), etl-pipeline → analytics-lake (60), ops-admin → finance-reports (45), nightly-backup → backup-archive (10) |
| `azure_*` | anonymous → finreportsprod (75), etl-sync-app → analyticslake (60), ops-admin@contoso.example → finreportsprod (45), backup-agent-identity → backupvault01 (10) |
| `gcp_*` | svc-reporting → hr-exports (60), ops-admin@acme.example → press-assets (45), backup-runner → db-backups (10) |
| `ocsf_*` | svc-reporting → hr-exports (60), public → press-kit (45) |

In the browser, use **Import records → AWS CloudTrail sample / Azure sample / Google Cloud sample**. The CloudTrail and Azure policies require separation of duties.

### Converting from the command line

Use `convert` to check the mapping before importing:

```bash
python run.py convert cloudtrail trail.json --settings settings.json --summary
python run.py convert azure PT1H.json --settings settings.json --out events.jsonl
python run.py convert gcp audit-logs.json --settings settings.json --out events.jsonl
python run.py convert ocsf security-lake.jsonl --settings settings.json --out events.jsonl
```

`--summary` prints the incidents and indicator counts the file would produce. The installed package provides the same command as `cloud-threat-convert`. In the browser, choose the **Record format** in the import dialog and attach the settings file.

## Normalized records

Any source can be imported once it is mapped to the nine-field schema ([schemas/normalized-event.schema.json](schemas/normalized-event.schema.json)). Typical options:

- A scheduled SIEM search (Splunk, Elastic, Sentinel, Chronicle) that writes JSONL or CSV with the three indicators computed by your existing detection rules.
- An adapter added to `src/cloud_threat/adapters/`. See the developer guide's "Adding a source adapter" section.

Extra fields in JSONL records are preserved in the signed raw evidence but ignored for scoring.

## Permission policies

A policy lists which response actions each principal/resource pair may receive ([schemas/permission-policy.schema.json](schemas/permission-policy.schema.json)). Without a policy, no response is offered.

```json
{
  "tenant": "acme-prod",
  "version": "storage-response-policy-2026-11",
  "separation_of_duties": true,
  "edges": [
    {"principal": "etl-pipeline", "resource": "analytics-lake", "action": "limit_read_volume"},
    {"principal": "anonymous", "resource": "finance-reports", "action": "disable_public_access"}
  ]
}
```

With `"separation_of_duties": true`, a response can only be approved by a different analyst name than the one who recorded the current assessment. Analyst names are self-asserted on a single workstation, so this enforces your process. It is not an identity control. The policy is part of the signed evidence, so later reviewers can see which rules applied.

## Summary export for SIEM and ticketing

`GET /api/summary.jsonl` (the download icon in the incident inbox) returns one JSON object per case:

```json
{"schema":"investigation-summary-v1","case_id":"…","tenant":"111122223333","principal":"anonymous","resource":"finance-reports","risk_points":75,"alert":true,"status":"closed","assessment":"threat","disposition":"resolved","revision":1,"evidence_root":"…","short_id":"…","indicators":{"public_access":1,"unusual_region":0,"large_read":1},"techniques":["T1530","T1537"],"external_reference":"CHG-1042","history_events":7,"created_at":"…","updated_at":"…"}
```

Splunk, Elastic, Sentinel and most ticketing tools ingest JSONL directly. Use `evidence_root`, or the shorter `short_id`, to link a ticket to the signed archive. The schema is in [schemas/investigation-summary.schema.json](schemas/investigation-summary.schema.json).

## Container deployment

```bash
docker build -t cloud-threat-investigation .
docker run --rm -p 127.0.0.1:8765:8765 -v cti-workspace:/workspace cloud-threat-investigation
# or
docker compose up --build
```

Then open http://127.0.0.1:8765. The workspace (database and signing key) lives in the `cti-workspace` volume, so back up the volume as a whole.

The container listens on all interfaces **inside** the container only. Always publish the port to `127.0.0.1` on the host: the workspace is single-user and has no login. To publish on a different host port, also allow that Host header:

```bash
docker run --rm -p 127.0.0.1:9000:8765 -v cti-workspace:/workspace cloud-threat-investigation --allowed-host 127.0.0.1:9000 --allowed-host localhost:9000
```

Arguments placed after the image name are appended to the entrypoint, so `--allowed-host` reaches the application.

## Model attribution

If your team runs its own detector, `explain` produces per-feature contributions in one common format for three model families:

```bash
python run.py explain --features features.json                          # built-in additive profile
python run.py explain --model model_logistic.json --features features.json
python run.py explain --model model_tree.json --features features.json
```

| Family | Contributions | Interval |
|---|---|---|
| `linear` / `additive` | weight × value | 95% interval from optional `weight_stderr` |
| `logistic` | weight × value in log-odds; also reports `probability` | as linear |
| `tree_ensemble` | path-based (Saabas) decomposition across trees; internal nodes must carry their mean `value` | none |

Each result includes `complete: true` when the baseline plus all contributions exactly equals the model output. Example models are in `src/cloud_threat/resources/samples/`. Their coefficients are illustrative, not trained values. Signed workspace evidence currently uses the built-in additive profile. See the developer guide for how another model family would be added to signed evidence.
