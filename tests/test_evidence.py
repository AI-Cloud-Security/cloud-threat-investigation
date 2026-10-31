import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import base64, copy, json, unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cloud_threat.core.evidence import create_case, load_events
from cloud_threat.core.canonical import canonical
from cloud_threat.core.provenance import build
from cloud_threat.core.signing import seal, verify

class EvidenceTests(unittest.TestCase):

    def setUp(self):
        self.raw = load_events(Path(__file__).resolve().parents[1] / 'src' / 'cloud_threat' / 'resources' / 'sample_events.jsonl')
        self.policy = json.loads((Path(__file__).resolve().parents[1] / 'src' / 'cloud_threat' / 'resources' / 'policy.json').read_text())
        self.key = Ed25519PrivateKey.generate()
        self.pub = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def bundle(self):
        return seal(build(self.raw, self.policy)[0], self.key)

    def test_score_and_minimum(self):
        g, d, a, c = build(self.raw, self.policy)
        self.assertEqual(d['risk_points'], 95)
        self.assertEqual(sum(a['contributions'].values()) + a['baseline'], 95)
        self.assertEqual(c['score'], 60)
        self.assertEqual(c['cost'], 1)
        self.assertFalse(c['applied'])

    def test_order_and_duplicate(self):
        self.assertEqual(build(self.raw, self.policy)[0], build(list(reversed(self.raw)) + self.raw[:1], self.policy)[0])

    def test_valid_signature(self):
        self.assertTrue(verify(self.bundle(), self.pub)['verified'])

    def test_tamper_rejected(self):
        b = self.bundle()
        b['payload']['issued_at'] = 'modified'
        with self.assertRaises(Exception):
            verify(b, self.pub)

    def test_wrong_trust_key(self):
        pub = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        with self.assertRaises(Exception):
            verify(self.bundle(), pub)

    def test_resigned_bad_node(self):
        b = self.bundle()
        n = next((n for n in b['payload']['graph']['nodes'].values() if n['kind'] == 'raw'))
        n['data']['bytes_b64'] = base64.b64encode(b'bad').decode()
        b['signature'] = base64.b64encode(self.key.sign(canonical(b['payload']))).decode()
        with self.assertRaises(ValueError):
            verify(b, self.pub)

    def test_dangling_reference(self):
        g = build(self.raw, self.policy)[0]
        del g['nodes'][next((h for h, n in g['nodes'].items() if n['kind'] == 'raw'))]
        with self.assertRaises(ValueError):
            verify(seal(g, self.key), self.pub)

    def test_no_feasible_action(self):
        p = dict(self.policy, edges=[])
        self.assertEqual(build(self.raw, p)[3]['status'], 'no_feasible_candidate')

    def test_cross_tenant(self):
        e = json.loads(self.raw[0])
        e['tenant'] = 'other'
        with self.assertRaises(ValueError):
            build([self.raw[1], canonical(e)], self.policy)

    def test_conflicting_duplicate(self):
        e = json.loads(self.raw[0])
        e['large_read'] = 1
        with self.assertRaises(ValueError):
            build(self.raw + [canonical(e)], self.policy)

    def test_schema_validation(self):
        e = json.loads(self.raw[0])
        e['public_access'] = 2
        with self.assertRaises(ValueError):
            build([canonical(e)], self.policy)

    def test_refuse_overwrite(self):
        import tempfile, contextlib, io
        with tempfile.TemporaryDirectory() as p, contextlib.redirect_stdout(io.StringIO()):
            create_case(p)
            with self.assertRaises(FileExistsError):
                create_case(p)
if __name__ == '__main__':
    unittest.main()
