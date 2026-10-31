"""HTTP workflow, browser assets and local request-boundary checks."""
import base64
import json
import re
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from cloud_threat.core.evidence import RESOURCE_ROOT
from cloud_threat.web.application import make_application


class WebTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.server = make_application(self.temp.name, 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f'http://127.0.0.1:{self.server.server_port}'
        self.html = urlopen(self.base).read().decode()
        self.token = re.search(r'name="workspace-token" content="([^"]+)"', self.html)[1]

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(); self.temp.cleanup()

    def post(self, route, data, token=True, extra_headers=None):
        headers = {'Content-Type': 'application/json'}
        if token: headers['X-Workspace-Token'] = self.token
        headers.update(extra_headers or {})
        request = Request(self.base + route, data=json.dumps({'actor': 'Analyst Example', **data}).encode(), headers=headers)
        return json.load(urlopen(request))

    def test_workspace_starts_empty(self):
        self.assertEqual(json.load(urlopen(self.base + '/api/workspace'))['cases'], [])

    def test_assets_and_template(self):
        self.assertNotIn('{{csrf_token}}', self.html)
        self.assertIn('Import security records', self.html)
        for path, kind in [('/static/workspace.css', 'text/css'), ('/static/workspace.js', 'javascript')]:
            response = urlopen(self.base + path)
            self.assertIn(kind, response.headers['Content-Type']); self.assertGreater(len(response.read()), 100)

    def test_missing_token_is_rejected(self):
        with self.assertRaises(HTTPError) as caught: self.post('/api/examples', {}, token=False)
        self.assertEqual(caught.exception.code, 403)

    def test_cross_origin_mutation_is_rejected(self):
        with self.assertRaises(HTTPError) as caught: self.post('/api/examples', {}, extra_headers={'Origin': 'https://unexpected.invalid'})
        self.assertEqual(caught.exception.code, 403)

    def test_unknown_host_is_rejected(self):
        with self.assertRaises(HTTPError) as caught: urlopen(Request(self.base, headers={'Host': 'unexpected.invalid'}))
        self.assertEqual(caught.exception.code, 421)

    def test_path_traversal_is_rejected(self):
        with self.assertRaises(HTTPError) as caught: urlopen(self.base + '/static/../../signing-key.bin')
        self.assertEqual(caught.exception.code, 404)

    def test_health_security_headers(self):
        response = urlopen(self.base + '/health')
        self.assertEqual(json.load(response)['status'], 'ok')
        self.assertEqual(response.headers['X-Frame-Options'], 'DENY')
        self.assertIn("script-src 'self'", response.headers['Content-Security-Policy'])

    def test_jsonl_import_and_assessment(self):
        result = self.post('/api/import', {'filename': 'records.jsonl', 'format': 'jsonl',
            'content': base64.b64encode((RESOURCE_ROOT / 'sample_events.jsonl').read_bytes()).decode()})
        self.assertEqual(result['created'], 1)
        case_id = result['case_ids'][0]
        result = self.post(f'/api/cases/{case_id}/assessment', {'version': 1, 'assessment': 'expected', 'rationale': 'Authorized operation'})
        self.assertEqual(result['case']['assessment'], 'expected')

    def test_conflict_returns_409(self):
        case_id = self.post('/api/examples', {})['case_ids'][0]
        self.post(f'/api/cases/{case_id}/note', {'version': 1, 'note': 'First note'})
        with self.assertRaises(HTTPError) as caught:
            self.post(f'/api/cases/{case_id}/note', {'version': 1, 'note': 'Stale note'})
        self.assertEqual(caught.exception.code, 409)

    def test_export_is_attachment(self):
        case_id = self.post('/api/examples', {})['case_ids'][0]
        response = urlopen(self.base + f'/api/cases/{case_id}/export')
        self.assertIn('attachment', response.headers['Content-Disposition'])
        self.assertTrue(response.read().startswith(b'PK'))

    def test_analyst_name_required(self):
        with self.assertRaises(HTTPError) as caught: self.post('/api/examples', {'actor': ''})
        self.assertEqual(caught.exception.code, 422)

    def test_template_and_policy(self):
        self.assertIn(b'event_id', urlopen(self.base + '/api/template.csv').read())
        policy = json.load(urlopen(self.base + '/api/example-policy'))
        self.assertEqual(policy['tenant'], 'tenant-example')
