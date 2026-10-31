"""Full investigation lifecycle, persistence and immutable evidence invariants."""
import io
import json
import sqlite3
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from cloud_threat.core.canonical import canonical
from cloud_threat.core.evidence import RESOURCE_ROOT
from cloud_threat.workflow.exports import export_archive, verify_archive
from cloud_threat.workflow.imports import read_records
from cloud_threat.workflow.store import ConflictError, InvestigationStore


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = InvestigationStore(self.temp.name)
        self.records = (RESOURCE_ROOT / 'sample_events.jsonl').read_bytes()
        self.policy = json.loads((RESOURCE_ROOT / 'policy.json').read_text())
        self.actor = 'Analyst Example'

    def tearDown(self):
        self.temp.cleanup()

    def imported(self, with_policy=True):
        result = self.store.import_records(self.records, 'jsonl', self.actor, 'events.jsonl', self.policy if with_policy else None)
        return self.store.detail(result['case_ids'][0])

    def assess(self, detail, value='threat'):
        return self.store.assess(detail['case']['id'], detail['case']['version'], self.actor, value, 'Reviewed source events and operational context.')

    def approved(self):
        detail = self.assess(self.imported())
        preview = self.store.preview(detail['case']['id'], detail['case']['version'], self.actor, ['disable_public_access'])
        detail = self.store.approve(detail['case']['id'], preview['incident']['case']['version'], self.actor,
                                    preview['preview']['id'], 'Approved under the supplied policy.')
        return detail

    def test_empty_workspace(self):
        self.assertEqual(self.store.list_cases(), [])

    def test_expected_activity_journey(self):
        detail = self.assess(self.imported(), 'expected')
        detail = self.store.close(detail['case']['id'], detail['case']['version'], self.actor, 'expected', 'Authorized scheduled operation.')
        self.assertEqual(detail['case']['status'], 'closed')
        result = verify_archive(export_archive(self.store, detail['case']['id']), self.store.public_key)
        self.assertTrue(result['verified']); self.assertTrue(result['final'])

    def test_threat_response_to_closure(self):
        detail = self.approved()
        detail = self.store.record_execution(detail['case']['id'], detail['case']['version'], self.actor, 'completed', 'CHG-1042', 'Public access disabled in the external console.')
        detail = self.store.close(detail['case']['id'], detail['case']['version'], self.actor, 'resolved', 'External response recorded and reviewed.')
        result = verify_archive(export_archive(self.store, detail['case']['id']), self.store.public_key)
        self.assertTrue(result['final']); self.assertEqual(result['history_entries'], 6)

    def test_no_policy_denies_actions(self):
        detail = self.assess(self.imported(False))
        self.assertEqual(detail['response_options'], [])
        with self.assertRaises(ValueError):
            self.store.preview(detail['case']['id'], detail['case']['version'], self.actor, ['disable_public_access'])

    def test_requires_assessment_before_response(self):
        detail = self.imported()
        with self.assertRaises(ConflictError):
            self.store.preview(detail['case']['id'], detail['case']['version'], self.actor, ['disable_public_access'])

    def test_unapproved_response_cannot_be_recorded(self):
        detail = self.assess(self.imported())
        with self.assertRaises(ConflictError):
            self.store.record_execution(detail['case']['id'], detail['case']['version'], self.actor, 'completed', 'CHG-1', 'Done')

    def test_failed_action_cannot_close_as_resolved(self):
        detail = self.approved()
        detail = self.store.record_execution(detail['case']['id'], detail['case']['version'], self.actor, 'failed', 'CHG-2', 'Change failed.')
        with self.assertRaises(ConflictError):
            self.store.close(detail['case']['id'], detail['case']['version'], self.actor, 'resolved', 'Should reject')

    def test_escalation_requires_reference(self):
        detail = self.assess(self.imported(False))
        with self.assertRaises(ValueError):
            self.store.close(detail['case']['id'], detail['case']['version'], self.actor, 'escalated', 'Needs review')
        detail = self.store.close(detail['case']['id'], detail['case']['version'], self.actor, 'escalated', 'Assigned to response team', 'INC-10')
        self.assertEqual(detail['case']['disposition'], 'escalated')

    def test_new_evidence_resets_assessment_and_preserves_prior_root(self):
        detail = self.assess(self.imported(), 'needs_evidence')
        first_root = detail['case']['root']
        event = json.loads(self.records.splitlines()[0]); event['event_id'] = 'evt-003'
        detail = self.store.add_evidence(detail['case']['id'], detail['case']['version'], self.actor, canonical(event), 'jsonl', None, 'Collected another source record.')
        self.assertEqual(detail['case']['revision'], 2); self.assertIsNone(detail['case']['assessment'])
        self.assertNotEqual(first_root, detail['case']['root']); self.assertEqual(detail['revisions'][0]['root'], first_root)
        self.assertEqual(verify_archive(export_archive(self.store, detail['case']['id']), self.store.public_key)['revisions'], 2)

    def test_stale_preview_is_rejected_after_policy_revision(self):
        detail = self.assess(self.imported())
        result = self.store.preview(detail['case']['id'], detail['case']['version'], self.actor, ['disable_public_access'])
        policy = dict(self.policy, version='updated-policy')
        detail = self.store.add_evidence(detail['case']['id'], result['incident']['case']['version'], self.actor, None, '', policy, 'Updated authorization snapshot.')
        detail = self.assess(detail)
        with self.assertRaises(ConflictError):
            self.store.approve(detail['case']['id'], detail['case']['version'], self.actor, result['preview']['id'], 'Should reject')

    def test_optimistic_concurrency(self):
        detail = self.imported(); self.assess(detail)
        with self.assertRaises(ConflictError):
            self.store.note(detail['case']['id'], detail['case']['version'], self.actor, 'Stale update')

    def test_closed_case_rejects_mutation(self):
        detail = self.assess(self.imported(), 'expected')
        detail = self.store.close(detail['case']['id'], detail['case']['version'], self.actor, 'expected', 'Reviewed')
        with self.assertRaises(ConflictError):
            self.store.note(detail['case']['id'], detail['case']['version'], self.actor, 'Should reject')

    def test_persistence_across_restart(self):
        detail = self.assess(self.imported())
        restarted = InvestigationStore(self.temp.name)
        self.assertEqual(restarted.public_key, self.store.public_key)
        self.assertEqual(restarted.detail(detail['case']['id'])['case']['assessment'], 'threat')

    def test_import_idempotency(self):
        first = self.imported(); second = self.imported()
        self.assertEqual(first['case']['id'], second['case']['id']); self.assertEqual(len(self.store.list_cases()), 1)

    def test_invalid_batch_rolls_back(self):
        with self.assertRaises(ValueError):
            self.store.import_records(self.records + b'\n{}', 'jsonl', self.actor, 'invalid.jsonl', self.policy)
        self.assertEqual(self.store.list_cases(), [])

    def test_state_tampering_detected(self):
        detail = self.imported()
        with sqlite3.connect(self.store.path) as db:
            changed = dict(detail['case'], risk_points=0)
            db.execute('UPDATE cases SET state=? WHERE id=?', (json.dumps(changed), detail['case']['id']))
        with self.assertRaises(ValueError): self.store.detail(detail['case']['id'])

    def test_evidence_table_rejects_overwrite(self):
        detail = self.imported()
        with sqlite3.connect(self.store.path) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute('UPDATE revisions SET bundle=? WHERE case_id=?', ('{}', detail['case']['id']))

    def test_export_tampering_rejected(self):
        detail = self.imported(); content = export_archive(self.store, detail['case']['id'])
        output = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(content)) as source, zipfile.ZipFile(output, 'w') as changed:
            for name in source.namelist(): changed.writestr(name, b'modified' if name == 'report.md' else source.read(name))
        with self.assertRaises(ValueError): verify_archive(output.getvalue(), self.store.public_key)

    def test_wrong_export_key_rejected(self):
        detail = self.imported()
        with tempfile.TemporaryDirectory() as other:
            with self.assertRaises(Exception):
                verify_archive(export_archive(self.store, detail['case']['id']), InvestigationStore(other).public_key)

    def test_csv_import(self):
        text = b'tenant,event_id,timestamp,principal,resource,action,public_access,unusual_region,large_read\ntenant-1,event-1,2026-10-31T12:00:00Z,service-1,storage-1,read,1,1,1\n'
        records = read_records(text, 'csv'); self.assertEqual(len(records), 1)
        result = self.store.import_records(text, 'csv', self.actor, 'events.csv')
        self.assertEqual(self.store.detail(result['case_ids'][0])['case']['risk_points'], 95)

    def test_additional_evidence_cannot_cross_incidents(self):
        detail = self.imported()
        event = json.loads(self.records.splitlines()[0]); event['principal'] = 'other'
        with self.assertRaises(ValueError):
            self.store.add_evidence(detail['case']['id'], detail['case']['version'], self.actor, canonical(event), 'jsonl', None, 'Invalid scope')

    def test_missing_workspace_key_does_not_rotate_identity(self):
        self.imported()
        (Path(self.temp.name) / 'signing-key.bin').unlink()
        with self.assertRaises(ValueError): InvestigationStore(self.temp.name)

    def test_json_container_import(self):
        records = [json.loads(line) for line in self.records.splitlines()]
        result = self.store.import_records(json.dumps({'events': records}).encode(), 'json', self.actor, 'records.json', self.policy)
        self.assertEqual(self.store.detail(result['case_ids'][0])['case']['risk_points'], 95)

    def test_grouping_creates_three_incidents_without_automatic_seed(self):
        self.assertEqual(self.store.list_cases(), [])
        records = (RESOURCE_ROOT / 'investigation_examples.jsonl').read_bytes()
        policy = json.loads((RESOURCE_ROOT / 'investigation_policy.json').read_text())
        result = self.store.import_records(records, 'jsonl', self.actor, 'included.jsonl', policy)
        self.assertEqual(result['created'], 3)
        self.assertEqual([case['risk_points'] for case in self.store.list_cases()], [95, 60, 10])

    def test_evidence_revision_clears_approval_and_outcome_but_retains_history(self):
        detail = self.approved()
        detail = self.store.record_execution(detail['case']['id'], detail['case']['version'], self.actor, 'completed', 'CHG-3', 'Recorded externally.')
        prior_root = detail['case']['root']
        policy = dict(self.policy, version='policy-reassessment')
        detail = self.store.add_evidence(detail['case']['id'], detail['case']['version'], self.actor, None, '', policy, 'Reassess against updated policy.')
        self.assertIsNone(detail['case']['approval']); self.assertIsNone(detail['case']['execution'])
        self.assertEqual(detail['case']['status'], 'open')
        self.assertTrue(any(item['payload']['kind'] == 'response_outcome_recorded' for item in detail['history']))
        self.assertEqual(detail['revisions'][0]['root'], prior_root)
        with self.assertRaises(ConflictError):
            self.store.close(detail['case']['id'], detail['case']['version'], self.actor, 'resolved', 'Must reject old completion')

    def test_conflicting_event_update_is_atomic(self):
        detail = self.imported(); event = json.loads(self.records.splitlines()[0]); event['action'] = 'changed-action'
        with self.assertRaises(ValueError):
            self.store.add_evidence(detail['case']['id'], detail['case']['version'], self.actor, canonical(event), 'jsonl', None, 'Attempted replacement')
        after = self.store.detail(detail['case']['id'])
        self.assertEqual(after['case'], detail['case']); self.assertEqual(len(after['revisions']), 1)

    def test_timeline_orders_actual_instants_across_timezone_offsets(self):
        event = json.loads(self.records.splitlines()[0]); event['event_id'] = 'later'; event['timestamp'] = '2026-10-31T10:00:00Z'
        earlier = dict(event, event_id='earlier', timestamp='2026-10-31T12:00:00+03:00')
        result = self.store.import_records(canonical(event) + b'\n' + canonical(earlier), 'jsonl', self.actor, 'offsets.jsonl')
        self.assertEqual([item['event_id'] for item in self.store.detail(result['case_ids'][0])['events']], ['earlier', 'later'])

    def test_jsonl_preserves_unicode_line_characters_inside_record(self):
        event = json.loads(self.records.splitlines()[0]); event['context'] = 'first\u0085second'
        raw = json.dumps(event, ensure_ascii=False).encode('utf8')
        self.assertEqual(read_records(raw + b'\r\n', 'jsonl'), [raw])

    def test_open_case_export_is_interim(self):
        detail = self.imported()
        self.assertFalse(verify_archive(export_archive(self.store, detail['case']['id']), self.store.public_key)['final'])

    def test_signed_archive_cannot_substitute_an_unrelated_prior_revision(self):
        import hashlib
        from cloud_threat.workflow.crypto import sign_document
        detail = self.assess(self.imported())
        policy = dict(self.policy, version='revision-two')
        detail = self.store.add_evidence(detail['case']['id'], detail['case']['version'], self.actor, None, '', policy, 'New authorization context.')
        content = export_archive(self.store, detail['case']['id'])
        with zipfile.ZipFile(io.BytesIO(content)) as source:
            members = {name: source.read(name) for name in source.namelist()}
        members['revisions/0001.json'] = members['revisions/0002.json']
        manifest = json.loads(members['manifest.json'])['payload']
        manifest['files']['revisions/0001.json'] = hashlib.sha256(members['revisions/0001.json']).hexdigest()
        members['manifest.json'] = canonical(sign_document(manifest, self.store.key))
        changed = io.BytesIO()
        with zipfile.ZipFile(changed, 'w') as target:
            for name, value in members.items(): target.writestr(name, value)
        with self.assertRaisesRegex(ValueError, 'evidence revision'):
            verify_archive(changed.getvalue(), self.store.public_key)
