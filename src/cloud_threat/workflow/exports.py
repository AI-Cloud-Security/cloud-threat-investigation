"""Portable investigation archives and offline trusted-key verification."""
import argparse
import base64
import re
import hashlib
import io
import json
import zipfile
from pathlib import Path
from typing import Any

from cloud_threat.core.canonical import canonical, digest
from cloud_threat.core.signing import verify
from cloud_threat.core.validation import parse_record
from .crypto import fingerprint, sign_document, verify_document
from .store import InvestigationStore, now

MAX_ARCHIVE_BYTES = 96 * 1024 * 1024
MAX_EXPANDED_BYTES = 256 * 1024 * 1024


def export_archive(store: InvestigationStore, case_id: str) -> bytes:
    material = store.export_material(case_id)
    state = material['case']
    report_payload = {
        'schema': 'investigation-report-v1', 'case': state,
        'final': state['status'] == 'closed', 'issued_at': now(),
        'history_tip': digest(material['history'][-1]),
        'evidence_root': state['root'],
        'assurance': {'signing': 'local-software-key', 'time': 'host-clock',
                      'analyst_identity': 'self-asserted', 'response_execution': 'externally-attested'},
    }
    report = sign_document(report_payload, store.key)
    def text(value: Any) -> str:
        return re.sub(r'([\\`*_{}\[\]()<>!#|])', r'\\\1', str(value).replace('\r', ' ').replace('\n', ' '))
    markdown = '\n'.join([
        '# Cloud threat investigation', '', f"Case: {state['id']}",
        f"Status: {state['status']}", f"Disposition: {state['disposition'] or 'Not closed'}",
        f"Principal: {text(state['principal'])}", f"Resource: {text(state['resource'])}",
        f"Risk points: {state['risk_points']}", f"Assessment: {state['assessment'] or 'Not assessed'}",
        f"Assessment rationale: {text(state['rationale'])}",
        f"Closure note: {text(state['closing_note'])}", '',
        '## Evidence', f"Root: {state['root']}", f"Revision: {state['revision']}",
        f"Signing key fingerprint: {fingerprint(store.public_key)}", '',
        '## Scope',
        'This report records an analyst investigation using explicit risk scoring. '
        'Response execution is recorded from an analyst statement; the application does not execute cloud changes. '
        'A signature establishes integrity under a trusted key, not source truth, identity proof, or security effectiveness.',
        '', 'Verify the archive against an independently selected public key before relying on its contents.', '',
    ])
    files = {
        'bundle.json': canonical(material['bundle']),
        'report.json': canonical(report),
        'report.md': markdown.encode('utf8'),
        'history.json': canonical({'events': material['history']}),
        'policy.json': canonical(material['policy']),
        'original-records.jsonl': b'\n'.join(material['raw_records']) + b'\n',
        'public-key.bin': store.public_key,
    }
    for index, bundle in enumerate(material['revisions'], start=1):
        files[f'revisions/{index:04d}.json'] = canonical(bundle)
    manifest_payload = {
        'schema': 'investigation-export-v1', 'case_id': case_id,
        'key_fingerprint': fingerprint(store.public_key),
        'files': {name: hashlib.sha256(content).hexdigest() for name, content in files.items()},
    }
    files['manifest.json'] = canonical(sign_document(manifest_payload, store.key))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    content = buffer.getvalue()
    verify_archive(content, store.public_key)
    return content


def verify_archive(content: bytes, trusted_key: bytes) -> dict:
    """Check every file, signed history, revision and final report without extraction."""
    if len(content) > MAX_ARCHIVE_BYTES:
        raise ValueError('Archive exceeds the size limit')
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        members = archive.infolist()
        if len(members) > 1000 or sum(item.file_size for item in members) > MAX_EXPANDED_BYTES:
            raise ValueError('Archive expanded size or member count exceeds its limit')
        names = [item.filename for item in members]
        if len(names) != len(set(names)) or any(name.startswith('/') or '..' in name.split('/') for name in names):
            raise ValueError('Unsafe or duplicate archive member')
        files = {name: archive.read(name) for name in names}
    decode = lambda raw: parse_record(raw, max_bytes=MAX_EXPANDED_BYTES)
    manifest = verify_document(decode(files['manifest.json']), trusted_key)
    if manifest['schema'] != 'investigation-export-v1' or manifest['key_fingerprint'] != fingerprint(trusted_key):
        raise ValueError('Export trust metadata mismatch')
    if set(manifest['files']) != set(files) - {'manifest.json'}:
        raise ValueError('Export file set does not match the signed manifest')
    for name, expected in manifest['files'].items():
        if hashlib.sha256(files[name]).hexdigest() != expected:
            raise ValueError(f'Export integrity check failed for {name}')
    if files['public-key.bin'] != trusted_key:
        raise ValueError('Exported key does not match the trusted key')
    bundle = decode(files['bundle.json'])
    result = verify(bundle, trusted_key)
    report = verify_document(decode(files['report.json']), trusted_key)
    history = decode(files['history.json'])['events']
    previous = None
    for index, document in enumerate(history, start=1):
        event = verify_document(document, trusted_key)
        if event['sequence'] != index or event['previous'] != previous or event['case_id'] != manifest['case_id']:
            raise ValueError('Signed history chain mismatch')
        previous = digest(document)
    if not history or report['history_tip'] != previous or canonical(history[-1]['payload']['state']) != canonical(report['case']):
        raise ValueError('Report does not match signed workflow history')
    if report['schema'] != 'investigation-report-v1':
        raise ValueError('Unexpected report schema')
    if report['evidence_root'] != result['root'] or report['case']['root'] != result['root']:
        raise ValueError('Report evidence root mismatch')
    if report['case']['id'] != manifest['case_id'] or report['final'] != (report['case']['status'] == 'closed'):
        raise ValueError('Report state metadata mismatch')
    revisions = sorted(name for name in files if name.startswith('revisions/'))
    count = report['case']['revision']
    if type(count) is not int or count < 1 or revisions != [f'revisions/{index:04d}.json' for index in range(1, count + 1)]:
        raise ValueError('Evidence revision history is incomplete')
    roots = {}
    for index, name in enumerate(revisions, start=1):
        roots[index] = verify(decode(files[name]), trusted_key)['root']
    for document in history:
        event = document['payload']
        state = event['state']
        if (event['schema'] != 'workflow-event-v1' or state['id'] != manifest['case_id']
                or state['version'] != event['sequence'] or roots.get(state['revision']) != state['root']):
            raise ValueError('Workflow state does not match its evidence revision')
    if canonical(decode(files[revisions[-1]])) != canonical(bundle):
        raise ValueError('Latest revision differs from exported evidence')
    nodes = bundle['payload']['graph']['nodes'].values()
    bound_policy = next(node['data'] for node in nodes if node['kind'] == 'policy')
    if canonical(decode(files['policy.json'])) != canonical(bound_policy):
        raise ValueError('Exported policy differs from signed evidence')
    bound_raw = sorted(base64.b64decode(node['data']['bytes_b64'], validate=True) for node in nodes if node['kind'] == 'raw')
    exported_raw = sorted(line for line in files['original-records.jsonl'].split(b'\n') if line.strip())
    if bound_raw != exported_raw:
        raise ValueError('Exported source records differ from signed evidence')
    return {'verified': True, 'case_id': manifest['case_id'], 'final': report['final'],
            'status': report['case']['status'], 'evidence_root': result['root'],
            'history_entries': len(history), 'revisions': len(revisions),
            'scope': 'export file integrity, signed history and report consistency under the selected key'}


def main() -> None:
    parser = argparse.ArgumentParser(description='Verify a complete investigation export')
    parser.add_argument('archive')
    parser.add_argument('--trusted-key', required=True)
    args = parser.parse_args()
    try:
        result = verify_archive(Path(args.archive).read_bytes(), Path(args.trusted_key).read_bytes())
    except Exception as error:
        parser.exit(1, f'Archive verification rejected: {type(error).__name__}: {error}\n')
    print(json.dumps(result, indent=2))
