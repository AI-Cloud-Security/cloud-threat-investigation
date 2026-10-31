"""Bounded imports of normalized JSONL, JSON and CSV security records."""
import csv
import io
import json
from collections import defaultdict
from typing import Any

from cloud_threat.core.canonical import canonical
from cloud_threat.core.validation import normalize, parse_record, validate_policy

MAX_UPLOAD_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 10000
FIELDS = ('tenant', 'event_id', 'timestamp', 'principal', 'resource', 'action',
          'public_access', 'unusual_region', 'large_read')


def read_records(content: bytes, format_name: str) -> list[bytes]:
    """Validate all records before any incident is committed."""
    if not content or len(content) > MAX_UPLOAD_BYTES:
        raise ValueError('Import must contain between 1 byte and 16 MiB')
    try:
        text = content.decode('utf-8-sig')
        if format_name == 'jsonl':
            records = [line.removesuffix('\r').encode('utf8') for line in text.split('\n') if line.strip()]
        elif format_name == 'json':
            container = parse_record(content, max_bytes=MAX_UPLOAD_BYTES)
            values = container.get('events')
            if not isinstance(values, list):
                raise ValueError('JSON import requires an object with an events array')
            records = [canonical(value) for value in values]
        elif format_name == 'csv':
            reader = csv.DictReader(io.StringIO(text, newline=''))
            if reader.fieldnames is None or len(set(reader.fieldnames)) != len(reader.fieldnames):
                raise ValueError('CSV requires unique column headers')
            if not set(FIELDS).issubset(reader.fieldnames):
                raise ValueError('CSV is missing required columns. Download the template.')
            records = []
            for index, row in enumerate(reader, start=2):
                if index > MAX_RECORDS + 1:
                    raise ValueError('Import exceeds 10000 records')
                if None in row or any(row.get(field) is None for field in FIELDS):
                    raise ValueError(f'CSV row {index} has inconsistent columns')
                for field in FIELDS[-3:]:
                    if row[field] not in ('0', '1'):
                        raise ValueError(f'CSV row {index}: {field} must be 0 or 1')
                    row[field] = int(row[field])
                records.append(canonical(row))
        else:
            raise ValueError('Supported formats are jsonl, csv and json')
    except (UnicodeError, csv.Error) as error:
        raise ValueError('Input must be valid UTF-8 text in the selected format') from error
    if not 1 <= len(records) <= MAX_RECORDS:
        raise ValueError('Import must contain 1 to 10000 records')
    for index, record in enumerate(records, start=1):
        try:
            normalize(record)
        except (ValueError, TypeError) as error:
            raise ValueError(f'Record {index}: {error}') from error
    return records


def group_records(records: list[bytes]) -> dict[tuple[str, str, str], list[bytes]]:
    """Use explicit tenant, principal and resource incident boundaries."""
    groups: dict[tuple[str, str, str], list[bytes]] = defaultdict(list)
    identities: dict[tuple[str, str], bytes] = {}
    for record in records:
        event = normalize(record)
        identity = (event['tenant'], event['event_id'])
        if identity in identities:
            if identities[identity] != record:
                raise ValueError('Conflicting duplicate event ID in the import')
            continue
        identities[identity] = record
        groups[(event['tenant'], event['principal'], event['resource'])].append(record)
    return dict(groups)


def policy_for(tenant: str, policy: dict[str, Any] | None) -> dict[str, Any]:
    """Default to no response permissions when no policy is supplied."""
    if policy is None:
        return {'tenant': tenant, 'version': 'no-capabilities-v1', 'edges': []}
    validate_policy(policy)
    if policy['tenant'] != tenant:
        raise ValueError('Uploaded policy tenant does not match the incident tenant')
    return policy
