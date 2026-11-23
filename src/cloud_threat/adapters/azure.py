"""Azure Monitor resource-log exports: Activity Log and Storage read/write logs.

Accepts the ``{"records": [...]}`` documents that diagnostic settings write to a
storage account, a JSON array, or JSONL (e.g. an Event Hubs or Log Analytics export).

Indicator rules:

* public_access: the caller identity type is ``Anonymous``, the request enables
  container public access (``"publicAccess": "Blob"`` or ``"Container"``) or
  ``"allowBlobPublicAccess": true``, or the resource is listed in ``public_resources``.
* unusual_region: ``location`` is not in the configured ``expected_regions``.
* large_read: ``properties.responseBodySize`` is at least ``large_read_bytes``.
"""
import json
import re
from typing import Any

from .base import AdapterConfig, unusual_region

UPN_CLAIM = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn'
NAME_CLAIM = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'
PUBLIC_REQUEST = re.compile(r'"publicAccess"\s*:\s*"(Blob|Container)"|"allowBlobPublicAccess"\s*:\s*true', re.IGNORECASE)


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _resource_parts(resource_id: str) -> list[str]:
    return [part for part in resource_id.split('/') if part]


def _subscription(resource_id: str) -> str | None:
    parts = _resource_parts(resource_id)
    lowered = [part.lower() for part in parts]
    if 'subscriptions' in lowered and lowered.index('subscriptions') + 1 < len(parts):
        return parts[lowered.index('subscriptions') + 1]
    return None


def _resource_name(record: dict[str, Any]) -> str:
    properties = record.get('properties') or {}
    if isinstance(properties, dict) and _text(properties.get('accountName')):
        return properties['accountName']
    resource_id = _text(record.get('resourceId')) or ''
    parts = _resource_parts(resource_id)
    lowered = [part.lower() for part in parts]
    if 'providers' in lowered:
        index = lowered.index('providers') + 3  # providers/<namespace>/<type>/<name>
        if index < len(parts):
            return parts[index]
    return resource_id or 'unknown-resource'


def _principal(identity: Any) -> str:
    if not isinstance(identity, dict):
        return 'unknown'
    claims = identity.get('claims') or {}
    requester = identity.get('requester') or {}
    kind = _text(identity.get('type'))
    if kind and kind.lower() == 'anonymous':
        return 'anonymous'
    return (_text(claims.get(UPN_CLAIM)) or _text(claims.get(NAME_CLAIM)) or _text(claims.get('appid'))
            or _text(requester.get('upn')) or _text(requester.get('appId')) or _text(requester.get('objectId'))
            or (kind.lower() if kind else None) or 'unknown')


def _public(record: dict[str, Any]) -> bool:
    identity = record.get('identity') or {}
    if isinstance(identity, dict) and str(identity.get('type', '')).lower() == 'anonymous':
        return True
    properties = record.get('properties') or {}
    body = (properties.get('requestbody') or properties.get('requestBody')) if isinstance(properties, dict) else None
    if body is not None and not isinstance(body, str):
        body = json.dumps(body)
    return bool(body and PUBLIC_REQUEST.search(body))


def to_record(record: dict[str, Any], config: AdapterConfig) -> dict[str, Any] | None:
    """Map one Azure resource-log record, or return None when configured to skip it."""
    result = str(record.get('resultType') or record.get('statusText') or '')
    status = record.get('statusCode')
    failed = result.lower() in {'failure', 'failed'} or (type(status) is int and status >= 400)
    if failed and not config.include_failed:
        return None
    resource_id = _text(record.get('resourceId')) or ''
    tenant = config.tenant or _subscription(resource_id)
    if not tenant:
        raise ValueError('No tenant: set "tenant" in adapter settings or include a subscription resourceId')
    event_id = _text(record.get('eventDataId')) or (
        f"{record['correlationId']}/{record['time']}" if _text(record.get('correlationId')) else None)
    if not event_id:
        raise ValueError('Azure record requires eventDataId or correlationId')
    properties = record.get('properties') or {}
    size = properties.get('responseBodySize', 0) if isinstance(properties, dict) else 0
    size = int(size) if isinstance(size, (int, float, str)) and str(size).isdigit() else 0
    return {
        'tenant': tenant,
        'event_id': event_id,
        'timestamp': record['time'],
        'principal': _principal(record.get('identity')),
        'resource': _resource_name(record),
        'action': record['operationName'],
        'public_access': int(_public(record)),
        'unusual_region': unusual_region(_text(record.get('location')), config),
        'large_read': int(size >= config.large_read_bytes),
        'source_format': 'azure-resource-log',
        'source_event': record,
    }
