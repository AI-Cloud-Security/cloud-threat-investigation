"""Convert AWS CloudTrail, Azure, Google Cloud or OCSF exports into normalized investigation JSONL.

Example:
    python run.py convert cloudtrail trail.json --settings settings.json --out events.jsonl
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from cloud_threat.core.validation import parse_record
from .base import SUPPORTED_FORMATS, convert, convert_to_jsonl, load_config


def main() -> None:
    parser = argparse.ArgumentParser(prog='convert', description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('format', choices=SUPPORTED_FORMATS, help='Source log format')
    parser.add_argument('source', type=Path, help='Provider export: JSON document, JSON array or JSONL')
    parser.add_argument('--settings', type=Path, help='Adapter settings JSON (expected regions, thresholds, aliases)')
    parser.add_argument('--out', type=Path, help='Write normalized JSONL here (default: standard output)')
    parser.add_argument('--summary', action='store_true', help='Print incident groups and indicator counts instead of records')
    args = parser.parse_args()
    try:
        settings = load_config(parse_record(args.settings.read_bytes()) if args.settings else None)
        content = args.source.read_bytes()
        if args.summary:
            records = convert(content, args.format, settings)
            groups = Counter((r['tenant'], r['principal'], r['resource']) for r in records)
            print(json.dumps({'records': len(records), 'incidents': [
                {'tenant': t, 'principal': p, 'resource': r, 'records': n} for (t, p, r), n in sorted(groups.items())],
                'indicators': {name: sum(r[name] for r in records) for name in ('public_access', 'unusual_region', 'large_read')}},
                indent=2))
            return
        output = convert_to_jsonl(content, args.format, settings)
    except (OSError, ValueError) as error:
        parser.exit(1, f'Conversion failed: {error}\n')
    if args.out:
        if args.out.exists():
            parser.exit(1, f'Conversion failed: {args.out} already exists\n')
        args.out.write_bytes(output)
        print(f'Wrote {output.count(chr(10).encode())} normalized records to {args.out}', file=sys.stderr)
    else:
        sys.stdout.buffer.write(output)


if __name__ == '__main__':
    main()
