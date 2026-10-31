"""Exercise the complete analyst journey through HTTP and offline verification."""
import base64
import io
import json
import re
import sys
import tempfile
import threading
import zipfile
from pathlib import Path
from urllib.request import Request, urlopen
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from cloud_threat.core.evidence import RESOURCE_ROOT
from cloud_threat.web.application import make_application
from cloud_threat.workflow.exports import verify_archive


def main() -> None:
    checks = []
    with tempfile.TemporaryDirectory() as folder:
        server = make_application(folder, 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        base = f'http://127.0.0.1:{server.server_port}'
        try:
            html = urlopen(base).read().decode()
            token = re.search(r'name="workspace-token" content="([^"]+)"', html)[1]
            def get(path):
                return json.load(urlopen(base + path, timeout=10))
            def post(path, data):
                request = Request(base + path, data=json.dumps({'actor': 'Integration Analyst', **data}).encode(),
                                  headers={'Content-Type': 'application/json', 'X-Workspace-Token': token})
                return json.load(urlopen(request, timeout=10))
            assert get('/api/workspace')['cases'] == []
            records = (RESOURCE_ROOT / 'sample_events.jsonl').read_bytes()
            policy = json.loads((RESOURCE_ROOT / 'policy.json').read_text())
            imported = post('/api/import', {'filename': 'events.jsonl', 'format': 'jsonl',
                                            'content': base64.b64encode(records).decode(), 'policy': policy})
            case_id = imported['case_ids'][0]; route = f'/api/cases/{case_id}'
            detail = get(route)
            assert detail['case']['risk_points'] == 95
            detail = post(route + '/assessment', {'version': detail['case']['version'], 'assessment': 'needs_evidence', 'rationale': 'Need another source observation.'})
            event = json.loads(records.splitlines()[0]); event['event_id'] = 'additional-003'
            detail = post(route + '/evidence', {'version': detail['case']['version'], 'format': 'jsonl',
                                                'content': base64.b64encode(json.dumps(event).encode()).decode(), 'reason': 'Collected additional context.'})
            assert detail['case']['revision'] == 2 and detail['case']['assessment'] is None
            detail = post(route + '/assessment', {'version': detail['case']['version'], 'assessment': 'threat', 'rationale': 'Activity is outside the approved operating context.'})
            preview = post(route + '/preview', {'version': detail['case']['version'], 'actions': ['disable_public_access']})
            assert preview['preview']['risk_points'] == 60
            detail = post(route + '/approve', {'version': preview['incident']['case']['version'], 'preview_id': preview['preview']['id'], 'rationale': 'Approved within the saved capability policy.'})
            detail = post(route + '/execution', {'version': detail['case']['version'], 'outcome': 'completed', 'reference': 'CHG-1042', 'note': 'Analyst records completion in the external console.'})
            detail = post(route + '/close', {'version': detail['case']['version'], 'disposition': 'resolved', 'note': 'Reviewed the recorded response and closed the case.'})
            assert detail['case']['status'] == 'closed'
            archive = urlopen(base + route + '/export', timeout=10).read()
            key = urlopen(base + '/api/public-key', timeout=10).read()
            verified = verify_archive(archive, key)
            assert verified['final'] and verified['revisions'] == 2
            checks.extend(['Empty workspace and normalized import', 'More-evidence branch and versioned reassessment',
                           'Policy-bound preview and approval', 'Externally attested outcome and closure',
                           'Signed archive and full revision-history verification'])
            changed = io.BytesIO()
            with zipfile.ZipFile(io.BytesIO(archive)) as source, zipfile.ZipFile(changed, 'w') as target:
                for name in source.namelist():
                    target.writestr(name, b'altered' if name == 'report.md' else source.read(name))
            try:
                verify_archive(changed.getvalue(), key)
            except ValueError:
                checks.append('Changed report rejected by signed manifest')
            else:
                raise AssertionError('Altered export was accepted')
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)
        restarted = make_application(folder, 0)
        try:
            assert restarted.store.detail(case_id)['case']['status'] == 'closed'
            checks.append('Closed investigation retained after restart')
        finally:
            restarted.server_close()
    print(json.dumps({'status': 'passed', 'checks': checks}, indent=2))


if __name__ == '__main__':
    main()
