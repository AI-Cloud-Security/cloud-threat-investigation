"""OCSF API Activity events (class_uid 6003), e.g. from Amazon Security Lake.

Indicator rules:

* public_access: the actor user type is ``Anonymous`` or the resource is listed
  in ``public_resources``.
* unusual_region: ``cloud.region`` is not in the configured ``expected_regions``.
* large_read: ``traffic.bytes_out`` is at least ``large_read_bytes``.
"""
from datetime import datetime, timezone
from typing import Any

from .base import AdapterConfig, unusual_region

API_ACTIVITY = 6003


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _timestamp(event: dict[str, Any]) -> str:
    if _text(event.get('time_dt')):
        return event['time_dt']
    value = event.get('time')
    if type(value) is not int:
        raise ValueError('OCSF event requires an integer time (epoch milliseconds) or time_dt')
    return datetime.fromtimestamp(value / 1000, tz=timezone.utc).isoformat().replace('+00:00', 'Z')


def to_record(event: dict[str, Any], config: AdapterConfig) -> dict[str, Any] | None:
    """Map one OCSF API Activity event; other classes are skipped."""
    if event.get('class_uid') != API_ACTIVITY:
        return None
    if not config.include_failed and event.get('status_id') == 2:
        return None
    cloud = event.get('cloud') or {}
    user = (event.get('actor') or {}).get('user') or {}
    api = event.get('api') or {}
    resources = [item for item in event.get('resources') or [] if isinstance(item, dict)]
    resource = next((_text(item.get('name')) or _text(item.get('uid')) for item in resources
                     if _text(item.get('name')) or _text(item.get('uid'))), None)
    tenant = config.tenant or _text((cloud.get('account') or {}).get('uid'))
    if not tenant:
        raise ValueError('No tenant: set "tenant" in adapter settings or include cloud.account.uid')
    event_id = _text((event.get('metadata') or {}).get('uid'))
    if not event_id:
        raise ValueError('OCSF event requires metadata.uid')
    bytes_out = (event.get('traffic') or {}).get('bytes_out', 0)
    bytes_out = bytes_out if type(bytes_out) is int else 0
    return {
        'tenant': tenant,
        'event_id': event_id,
        'timestamp': _timestamp(event),
        'principal': _text(user.get('name')) or _text(user.get('uid')) or 'anonymous',
        'resource': resource or _text((api.get('service') or {}).get('name')) or 'unknown-resource',
        'action': _text(api.get('operation')) or 'unknown',
        'public_access': int(user.get('type') == 'Anonymous'),
        'unusual_region': unusual_region(_text(cloud.get('region')), config),
        'large_read': int(bytes_out >= config.large_read_bytes),
        'source_format': 'ocsf-api-activity',
        'source_event': event,
    }
