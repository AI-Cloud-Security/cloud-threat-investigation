"""Threat-technique context for investigation indicators.

Annotations are display and report context only. They are not part of the
signed evidence graph, so mapping updates never change evidence roots.
"""
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

MAPPING_PATH = Path(__file__).resolve().parents[1] / 'resources' / 'techniques.json'


@lru_cache(maxsize=1)
def mapping() -> dict[str, Any]:
    return json.loads(MAPPING_PATH.read_text(encoding='utf8'))


def technique_url(technique_id: str) -> str:
    return 'https://attack.mitre.org/techniques/' + technique_id.replace('.', '/') + '/'


HEADLINES = {
    ('large_read', 'public_access', 'unusual_region'): 'Large read of a publicly exposed resource from an unusual region',
    ('large_read', 'public_access'): 'Large data read from a publicly exposed resource',
    ('public_access', 'unusual_region'): 'Public resource access from an unusual region',
    ('large_read', 'unusual_region'): 'Large data read from an unusual region',
    ('public_access',): 'Public access to a cloud resource',
    ('unusual_region',): 'Access from an unusual region',
    ('large_read',): 'Large data read',
    (): 'Routine access activity',
}


def headline(features: dict[str, int]) -> str:
    """Describe an incident by its observed indicators, e.g. for titles and tickets."""
    present = tuple(sorted(name for name, value in features.items() if value))
    return HEADLINES.get(present, 'Access activity requiring review')


def annotate(features: dict[str, int]) -> list[dict[str, Any]]:
    """Return related techniques for each present indicator, de-duplicated by ID."""
    seen: dict[str, dict[str, Any]] = {}
    for feature, techniques in mapping()['features'].items():
        if not features.get(feature):
            continue
        for technique in techniques:
            entry = seen.setdefault(technique['id'], {**technique, 'url': technique_url(technique['id']), 'indicators': []})
            entry['indicators'].append(feature)
    return sorted(seen.values(), key=lambda item: item['id'])
