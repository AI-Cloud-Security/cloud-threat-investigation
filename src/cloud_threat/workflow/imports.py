"""Bounded imports of normalized JSONL, JSON and CSV security records."""
import csv
import io
import json
from collections import defaultdict
from typing import Any

from cloud_threat.adapters import SUPPORTED_FORMATS, convert_to_jsonl, load_config
from cloud_threat.core.canonical import canonical
from cloud_threat.core.validation import normalize, parse_record, validate_policy

MAX_UPLOAD_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 10000
FIELDS = ('tenant', 'event_id', 'timestamp', 'principal', 'resource', 'action',
          'public_access', 'unusual_region', 'large_read')


def read_records(content: bytes, format_name: str, adapter_settings: dict[str, Any] | None = None) -> list[bytes]:
    """Validate all records before any incident is committed.

    Provider formats (``cloudtrail``, ``azure``, ``gcp``, ``ocsf``) are converted to normalized
    JSONL first; each record then carries its original provider event.
    """
    if not content or len(content) > MAX_UPLOAD_BYTES:
        raise ValueError('The import file must be between 1 byte and 16 MiB.')
    if format_name in SUPPORTED_FORMATS:
        content = convert_to_jsonl(content, format_name, load_config(adapter_settings))
        format_name = 'jsonl'
    elif adapter_settings is not None:
        raise ValueError('Adapter settings apply only to provider log imports (AWS CloudTrail, Azure, Google Cloud or OCSF).')
    try:
        text = content.decode('utf-8-sig')
        if format_name == 'jsonl':
            records = [line.removesuffix('\r').encode('utf8') for line in text.split('\n') if line.strip()]
        elif format_name == 'json':
            container = parse_record(content, max_bytes=MAX_UPLOAD_BYTES)
            values = container.get('events')
            if not isinstance(values, list):
                raise ValueError('JSON imports require an object with an "events" array.')
            records = [canonical(value) for value in values]
        elif format_name == 'csv':
            reader = csv.DictReader(io.StringIO(text, newline=''))
            if reader.fieldnames is None or len(set(reader.fieldnames)) != len(reader.fieldnames):
                raise ValueError('CSV column headers must be unique.')
            if not set(FIELDS).issubset(reader.fieldnames):
                raise ValueError('The CSV file is missing required columns. Download the CSV template for the expected format.')
            records = []
            for index, row in enumerate(reader, start=2):
                if index > MAX_RECORDS + 1:
                    raise ValueError('The import exceeds the limit of 10,000 records.')
                if None in row or any(row.get(field) is None for field in FIELDS):
                    raise ValueError(f'CSV row {index} has an unexpected number of columns.')
                for field in FIELDS[-3:]:
                    if row[field] not in ('0', '1'):
                        raise ValueError(f'CSV row {index}: {field} must be 0 or 1.')
                    row[field] = int(row[field])
                records.append(canonical(row))
        else:
            raise ValueError('Unsupported format. Supported formats: jsonl, csv, json, cloudtrail, azure, gcp and ocsf.')
    except (UnicodeError, csv.Error) as error:
        raise ValueError('The file must be UTF-8 text in the selected format.') from error
    if not 1 <= len(records) <= MAX_RECORDS:
        raise ValueError('An import must contain between 1 and 10,000 records.')
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
                raise ValueError('The import contains the same event ID with different content.')
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
        raise ValueError('The permission policy tenant does not match the tenant of the imported records.')
    return policy
