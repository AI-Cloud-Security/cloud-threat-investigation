"""Negative boundary cases and no-change scenario semantics."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from cloud_threat.core.evidence import RESOURCE_ROOT, create_case, load_events
from cloud_threat.core.provenance import build
from cloud_threat.core.scoring import counterfactual
from cloud_threat.core.validation import normalize, parse_record, validate_policy

class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.event = json.loads(load_events(RESOURCE_ROOT / 'sample_events.jsonl')[0])
        self.policy = json.loads((RESOURCE_ROOT / 'policy.json').read_text())

    def test_duplicate_json_key(self):
        with self.assertRaises(ValueError): parse_record(b'{"tenant":"a","tenant":"b"}')

    def test_nonfinite_number(self):
        with self.assertRaises(ValueError): parse_record(b'{"score":NaN}')

    def test_array_record(self):
        with self.assertRaises(ValueError): parse_record(b'[]')

    def test_boolean_feature(self):
        self.event['public_access'] = True
        with self.assertRaises(ValueError): normalize(json.dumps(self.event).encode())

    def test_missing_policy_version(self):
        del self.policy['version']
        with self.assertRaises(ValueError): validate_policy(self.policy)

    def test_unknown_capability(self):
        self.policy['edges'][0]['action'] = 'unsupported_operation'
        with self.assertRaises(ValueError): validate_policy(self.policy)

    def test_timezone_required(self):
        self.event['timestamp'] = '2026-10-25T12:00:00'
        with self.assertRaises(ValueError): normalize(json.dumps(self.event).encode())

    def test_oversized_record(self):
        with self.assertRaises(ValueError): parse_record(b' ' * 1_048_577)

    def test_below_threshold_needs_no_change(self):
        result = counterfactual({'public_access': 0, 'unusual_region': 0, 'large_read': 0}, self.policy, 'service-sample', 'storage-sample')
        self.assertEqual(result['status'], 'no_change_required')
        self.assertEqual(result['score'], 10)
        self.assertEqual(result['actions'], [])

    def test_existing_summary_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            summary = Path(folder) / 'summary.json'
            summary.write_text('existing')
            with self.assertRaises(FileExistsError): create_case(folder)
            self.assertEqual(summary.read_text(), 'existing')
            self.assertFalse((Path(folder) / 'bundle.json').exists())

    def test_policy_tenant_isolation(self):
        self.policy['tenant'] = 'different-tenant'
        with self.assertRaises(ValueError): build(load_events(RESOURCE_ROOT / 'sample_events.jsonl'), self.policy)
