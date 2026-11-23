"""Google Cloud Audit Logs (Admin Activity and Data Access) LogEntry exports.

Accepts a JSON array (``gcloud logging read --format=json``), a single entry,
or JSONL (e.g. a Cloud Storage or Pub/Sub log sink).

Indicator rules:

* public_access: the request has no authenticated principal, an IAM policy change
  adds ``allUsers`` or ``allAuthenticatedUsers``, or the resource is listed in
  ``public_resources``.
* unusual_region: ``protoPayload.resourceLocation.currentLocations[0]`` (else
  ``resource.labels.location``) is not in the configured ``expected_regions``.
* large_read: ``httpRequest.responseSize`` is at least ``large_read_bytes``.
  Audit entries without a response size are never flagged as large.
"""
from typing import Any

from .base import AdapterConfig, unusual_region

PUBLIC_MEMBERS = ('allUsers', 'allAuthenticatedUsers')


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _payload(entry: dict[str, Any]) -> dict[str, Any]:
    payload = entry.get('protoPayload')
    if not isinstance(payload, dict):
        raise ValueError('Cloud Audit Log entry requires protoPayload')
    return payload


def _public(payload: dict[str, Any]) -> bool:
    if not _text((payload.get('authenticationInfo') or {}).get('principalEmail')):
        return True
    deltas = ((payload.get('serviceData') or {}).get('policyDelta') or {}).get('bindingDeltas') \
        or ((payload.get('metadata') or {}).get('datasetChange') or {}).get('bindingDeltas') or []
    for delta in deltas if isinstance(deltas, list) else []:
        if isinstance(delta, dict) and delta.get('action') == 'ADD' and delta.get('member') in PUBLIC_MEMBERS:
            return True
    return False


def _region(entry: dict[str, Any], payload: dict[str, Any]) -> str | None:
    locations = (payload.get('resourceLocation') or {}).get('currentLocations')
    if isinstance(locations, list) and locations and _text(locations[0]):
        return locations[0]
    return _text(((entry.get('resource') or {}).get('labels') or {}).get('location'))


def _tenant(entry: dict[str, Any], config: AdapterConfig) -> str | None:
    if config.tenant:
        return config.tenant
    project = _text(((entry.get('resource') or {}).get('labels') or {}).get('project_id'))
    log_name = _text(entry.get('logName')) or ''
    if not project and log_name.startswith('projects/'):
        project = log_name.split('/')[1]
    return project


def to_record(entry: dict[str, Any], config: AdapterConfig) -> dict[str, Any] | None:
    """Map one audit LogEntry, or return None when configured to skip it."""
    payload = _payload(entry)
    status = payload.get('status') or {}
    if isinstance(status, dict) and status.get('code') not in (None, 0) and not config.include_failed:
        return None
    tenant = _tenant(entry, config)
    if not tenant:
        raise ValueError('No tenant: set "tenant" in adapter settings or include resource.labels.project_id')
    labels = (entry.get('resource') or {}).get('labels') or {}
    size = (entry.get('httpRequest') or {}).get('responseSize', 0)
    size = int(size) if isinstance(size, (int, str)) and str(size).isdigit() else 0
    return {
        'tenant': tenant,
        'event_id': entry['insertId'],
        'timestamp': entry['timestamp'],
        'principal': _text((payload.get('authenticationInfo') or {}).get('principalEmail')) or 'anonymous',
        'resource': _text(labels.get('bucket_name')) or _text(payload.get('resourceName')) or 'unknown-resource',
        'action': payload['methodName'],
        'public_access': int(_public(payload)),
        'unusual_region': unusual_region(_region(entry, payload), config),
        'large_read': int(size >= config.large_read_bytes),
        'source_format': 'gcp-cloud-audit-log',
        'source_event': entry,
    }

