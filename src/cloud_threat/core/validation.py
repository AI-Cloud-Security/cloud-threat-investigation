"""Strict parsing and validation at the event and policy boundaries."""
import json
from datetime import datetime
from typing import Any
from .scoring import FEATURES
MAX_RECORD_BYTES = 1048576
ALLOWED_ACTIONS = frozenset({'disable_public_access', 'limit_read_volume'})

def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate JSON key: {key}')
        result[key] = value
    return result

def _reject_constant(value: str) -> None:
    raise ValueError(f'Non-finite JSON number: {value}')

def parse_record(raw: bytes, max_bytes: int = MAX_RECORD_BYTES) -> dict[str, Any]:
    """Reject oversized records, duplicate fields and non-object JSON."""
    if len(raw) > max_bytes:
        raise ValueError('JSON input exceeds its configured size limit')
    value = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    if not isinstance(value, dict):
        raise ValueError('Record must be a JSON object')
    return value

def _required_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise ValueError(f'{field} must be a nonempty string of at most 4096 characters')
    return value

def normalize(raw: bytes) -> dict[str, Any]:
    """Select stable fields while preserving the original record separately."""
    event = parse_record(raw)
    fields = ('tenant', 'event_id', 'timestamp', 'principal', 'resource', 'action')
    for field in fields:
        _required_string(event.get(field), field)
    timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
    if timestamp.tzinfo is None:
        raise ValueError('Timestamp requires an explicit timezone')
    for feature in FEATURES:
        if type(event.get(feature)) is not int or event[feature] not in (0, 1):
            raise ValueError(f'{feature} must be the integer 0 or 1')
    return {field: event[field] for field in (*fields, *FEATURES)}

def validate_policy(policy: dict[str, Any]) -> None:
    """Validate the finite capability policy before evaluating actions."""
    if not isinstance(policy, dict):
        raise ValueError('Policy must be an object')
    for field in ('tenant', 'version'):
        _required_string(policy.get(field), field)
    edges = policy.get('edges')
    if not isinstance(edges, list) or len(edges) > 10000:
        raise ValueError('Policy edges must be a list of at most 10000 capabilities')
    for edge in edges:
        if not isinstance(edge, dict):
            raise ValueError('Each capability must be an object')
        for field in ('principal', 'resource', 'action'):
            _required_string(edge.get(field), field)
        if edge['action'] not in ALLOWED_ACTIONS:
            raise ValueError('Unsupported policy action')
