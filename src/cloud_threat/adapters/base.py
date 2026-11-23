"""Shared adapter configuration, dispatch and JSONL output."""
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from cloud_threat.core.validation import normalize, parse_record

MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_SOURCE_EVENTS = 10000
DEFAULT_LARGE_READ_BYTES = 100 * 1024 * 1024


@dataclass(frozen=True)
class AdapterConfig:
    """Explicit rules for deriving the three investigation indicators.

    Nothing is inferred from undocumented heuristics: a region is unusual only
    when ``expected_regions`` is configured and the event region is absent from
    it, and a read is large only above ``large_read_bytes``.
    """
    tenant: str | None = None
    expected_regions: frozenset[str] = frozenset()
    public_resources: frozenset[str] = frozenset()
    large_read_bytes: int = DEFAULT_LARGE_READ_BYTES
    include_failed: bool = True
    principal_aliases: dict[str, str] = field(default_factory=dict)


def _string_set(value: Any, name: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f'Adapter setting {name} must be a list of strings')
    return frozenset(value)


def load_config(data: dict[str, Any] | None) -> AdapterConfig:
    """Validate a user-supplied adapter configuration object."""
    if data is None:
        return AdapterConfig()
    if not isinstance(data, dict):
        raise ValueError('Adapter settings must be a JSON object')
    known = {'tenant', 'expected_regions', 'public_resources', 'large_read_bytes',
             'include_failed', 'principal_aliases', 'description'}
    unknown = set(data) - known
    if unknown:
        raise ValueError(f'Unknown adapter settings: {", ".join(sorted(unknown))}')
    tenant = data.get('tenant')
    if tenant is not None and (not isinstance(tenant, str) or not tenant.strip()):
        raise ValueError('Adapter setting tenant must be a nonempty string')
    threshold = data.get('large_read_bytes', DEFAULT_LARGE_READ_BYTES)
    if type(threshold) is not int or threshold < 1:
        raise ValueError('Adapter setting large_read_bytes must be a positive integer')
    include_failed = data.get('include_failed', True)
    if not isinstance(include_failed, bool):
        raise ValueError('Adapter setting include_failed must be true or false')
    aliases = data.get('principal_aliases', {})
    if not isinstance(aliases, dict) or not all(isinstance(k, str) and isinstance(v, str) and v for k, v in aliases.items()):
        raise ValueError('Adapter setting principal_aliases must map strings to strings')
    return AdapterConfig(tenant=tenant, expected_regions=_string_set(data.get('expected_regions'), 'expected_regions'),
                         public_resources=_string_set(data.get('public_resources'), 'public_resources'),
                         large_read_bytes=threshold, include_failed=include_failed, principal_aliases=dict(aliases))


def unusual_region(region: str | None, config: AdapterConfig) -> int:
    return int(bool(config.expected_regions) and bool(region) and region not in config.expected_regions)


def finish(record: dict[str, Any], config: AdapterConfig) -> dict[str, Any]:
    """Apply aliases and public-resource overrides, then validate the result."""
    record['principal'] = config.principal_aliases.get(record['principal'], record['principal'])
    if record['resource'] in config.public_resources:
        record['public_access'] = 1
    return record


def _events(content: bytes, list_key: str | None) -> list[Any]:
    """Accept a provider JSON document, a JSON array, or JSONL."""
    if not content or len(content) > MAX_SOURCE_BYTES:
        raise ValueError('Source file must contain between 1 byte and 16 MiB')
    try:
        text = content.decode('utf-8-sig').strip()
    except UnicodeError as error:
        raise ValueError('Source file must be UTF-8 JSON') from error
    if text.startswith('{') or text.startswith('['):
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            value = None
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            if list_key and isinstance(value.get(list_key), list):
                return value[list_key]
            return [value]
    return [parse_record(line.encode('utf8')) for line in text.splitlines() if line.strip()]


def convert(content: bytes, source_format: str, config: AdapterConfig | None = None) -> list[dict[str, Any]]:
    """Convert a provider export into validated normalized records."""
    from . import azure, cloudtrail, gcp, ocsf
    adapters: dict[str, tuple[str | None, Callable[[dict, AdapterConfig], dict | None]]] = {
        'cloudtrail': ('Records', cloudtrail.to_record),
        'azure': ('records', azure.to_record),
        'gcp': ('entries', gcp.to_record),
        'ocsf': (None, ocsf.to_record),
    }
    if source_format not in adapters:
        raise ValueError(f'Unsupported source format. Choose one of: {", ".join(SUPPORTED_FORMATS)}')
    config = config or AdapterConfig()
    list_key, adapter = adapters[source_format]
    events = _events(content, list_key)
    if len(events) > MAX_SOURCE_EVENTS:
        raise ValueError(f'Source file exceeds {MAX_SOURCE_EVENTS} events')
    records = []
    for index, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            raise ValueError(f'Source event {index} must be a JSON object')
        try:
            record = adapter(event, config)
            if record is None:
                continue
            record = finish(record, config)
            normalize(json.dumps(record).encode('utf8'))
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f'Source event {index}: {error}') from error
        records.append(record)
    if not records:
        raise ValueError('No importable events were found in the source file')
    return records


def convert_to_jsonl(content: bytes, source_format: str, config: AdapterConfig | None = None) -> bytes:
    """Return normalized JSONL bytes ready for the standard importer."""
    return _jsonl(convert(content, source_format, config))


def _jsonl(records: Iterable[dict[str, Any]]) -> bytes:
    return b'\n'.join(json.dumps(record, ensure_ascii=False, separators=(',', ':')).encode('utf8')
                      for record in records) + b'\n'


SUPPORTED_FORMATS = ('cloudtrail', 'azure', 'gcp', 'ocsf')
