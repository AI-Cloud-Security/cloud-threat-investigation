# Evidence format

This document specifies the signed structures the workspace produces, so that independent tools can verify or consume them without this codebase. All identifiers below appear verbatim in the data.

## Canonical encoding (`integer-json-v1`)

Everything that is hashed or signed is first encoded as:

- UTF-8 JSON with object keys sorted, no insignificant whitespace (`separators=(',', ':')`)
- object keys must be ASCII; values may be strings, integers, booleans, `null`, arrays and objects
- floating-point numbers are **rejected**, and non-ASCII string content is emitted as UTF-8, not `\u` escapes

This is a restricted project encoding, not RFC 8785. `digest(x)` is the lowercase hex SHA-256 of the encoding.

## Evidence graph (`evidence-v1`)

A content-addressed directed acyclic graph. Each node is:

```json
{"kind": "<kind>", "data": { ... }, "parents": ["<sorted parent hashes>"]}
```

and is stored under the key `digest(node)`.

| Kind | Data | Parents |
|---|---|---|
| `raw` | `bytes_b64`: the exact source record bytes; `sha256`: their digest | none |
| `normalized` | the nine normalized fields | its `raw` node |
| `features` | `values` (max of each indicator over all records), `transform: binary-max-v1` | all `normalized` nodes |
| `model` | scoring profile (`id`, `baseline`, `weights`, `threshold`, `score_unit`, `trained`) | none |
| `policy` | the permission policy in force | none |
| `decision` | `risk_points`, `threshold`, `alert`, `probability: false` | `features`, `model` |
| `attribution` | `baseline`, `unit`, per-indicator `contributions`, `summary` | `decision`, `features`, `model` |
| `counterfactual` | minimum-cost permitted change, or `no_change_required` / `no_feasible_candidate` | `policy`, `decision`, `features`, `model` |
| `evidence` (root) | `tenant`, `schema: evidence-v1`, `encoding: integer-json-v1` | `attribution`, `counterfactual` |

Every node must be reachable from the root, and the graph must be acyclic. The root hash identifies the complete explanation state.

### Short identifier

`short_id = base32(root[0:15] ‖ SHA-256(root[0:15])[0:3])` with padding removed. `root` is the raw 32-byte root. The 3-byte checksum catches transcription errors. The full root remains authoritative.

## Signed evidence bundle

```json
{
  "algorithm": "Ed25519",
  "signature": "<base64 Ed25519 signature over canonical(payload)>",
  "payload": {
    "graph": {"root": "<hex>", "short_id": "<base32>", "nodes": { "<hash>": <node>, ... }},
    "issued_at": "<ISO 8601, host clock>",
    "clock": {"mode": "untrusted-host", "process_epoch": "<uuid>", "monotonic_ns": <int>},
    "assurance": {"signing": "software-ed25519", "retention": "<declared retention mode>"}
  }
}
```

### Verifying a bundle

1. Check `algorithm == "Ed25519"`, then verify `signature` over `canonical(payload)` with a **separately trusted** 32-byte public key.
2. Check `short_id` against `root` as defined above.
3. Starting at `root`, recursively check that each referenced node exists, that `digest(node)` equals its key, and that no cycle is reached. For `raw` nodes, check that SHA-256 of the decoded `bytes_b64` equals `sha256`.
4. Check that every node was reached and that the root's kind is `evidence`.

## Workflow history event (`workflow-event-v1`)

Every case action is a signed document `{"payload", "algorithm", "signature"}` with this payload:

| Field | Meaning |
|---|---|
| `case_id`, `sequence` | Case and 1-based position in its history |
| `previous` | `digest` of the previous signed document, or `null` for the first |
| `occurred_at`, `actor`, `identity_assurance` | Host time, analyst name, `self-asserted-local-analyst` |
| `kind` | `imported`, `assessed`, `note_added`, `evidence_added`, `response_previewed`, `response_approved`, `response_outcome_recorded`, `closed` |
| `data` | Action details (e.g. rationale, preview, reference, source file digest, adapter settings) |
| `state` | Complete case state after the action |

The chain is valid when every signature verifies, the sequence numbers are contiguous from 1, and each `previous` matches the prior document's digest.

## Export archive (`investigation-export-v1`)

| File | Content |
|---|---|
| `manifest.json` | Signed `{schema, case_id, key_fingerprint, files: {name: sha256}}` covering every other file |
| `report.json` | Signed `investigation-report-v1`: case state, `final`, `history_tip`, `evidence_root`, assurance declarations |
| `report.md` | Human-readable summary, indicators and related ATT&CK techniques |
| `bundle.json` | Current signed evidence bundle |
| `revisions/NNNN.json` | Every signed evidence bundle, in order |
| `history.json` | `{"events": [...]}`: the signed workflow history |
| `policy.json`, `original-records.jsonl` | Policy in force and the source records |
| `public-key.bin` | Convenience copy of the signer's key. Do not use it as the trust anchor. |

`python run.py verify-export archive.zip --trusted-key key.bin` (or `cloud-investigation-verify`) checks archive bounds and membership, all hashes and signatures, every revision graph, the history chain, and consistency between the report, the latest history state and the current bundle.

## What verification establishes

Verification proves that the content is intact and was signed by the holder of the trusted key. It does not prove that the source telemetry was true, that the analyst's identity is genuine, that an external change really happened, or that the archive is the latest one (an older complete workspace could also verify).
