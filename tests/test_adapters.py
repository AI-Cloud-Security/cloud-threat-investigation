"""Provider adapters: deterministic indicator rules and provenance preservation."""
import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from cloud_threat.adapters import convert, load_config
from cloud_threat.adapters.cloudtrail import to_record as cloudtrail_record
from cloud_threat.core.evidence import RESOURCE_ROOT
from cloud_threat.workflow.store import InvestigationStore

SAMPLES = RESOURCE_ROOT / 'samples'
MB = 1024 * 1024


def trail_event(**overrides):
    event = {'eventID': 'e-1', 'eventTime': '2026-10-31T02:00:00Z', 'eventName': 'GetObject',
             'eventSource': 's3.amazonaws.com', 'awsRegion': 'us-east-1', 'recipientAccountId': '111122223333',
             'userIdentity': {'type': 'IAMUser', 'userName': 'alice', 'accountId': '111122223333'},
             'requestParameters': {'bucketName': 'reports'}, 'additionalEventData': {'bytesTransferredOut': 10}}
    event.update(overrides)
    return event


class CloudTrailTests(unittest.TestCase):
    config = load_config({'expected_regions': ['us-east-1'], 'large_read_bytes': 100 * MB})

    def test_ordinary_read_has_no_indicators(self):
        record = cloudtrail_record(trail_event(), self.config)
        self.assertEqual((record['principal'], record['resource'], record['action']), ('alice', 'reports', 'GetObject'))
        self.assertEqual((record['public_access'], record['unusual_region'], record['large_read']), (0, 0, 0))
        self.assertEqual(record['source_event']['eventID'], 'e-1')

    def test_anonymous_unexpected_region_large_read(self):
        record = cloudtrail_record(trail_event(
            userIdentity={'type': 'AWSAccount', 'principalId': '', 'accountId': 'ANONYMOUS_PRINCIPAL'},
            awsRegion='eu-west-3', additionalEventData={'bytesTransferredOut': 200 * MB}), self.config)
        self.assertEqual(record['principal'], 'anonymous')
        self.assertEqual((record['public_access'], record['unusual_region'], record['large_read']), (1, 1, 1))

    def test_public_grants_are_detected(self):
        acl = trail_event(eventName='PutBucketAcl', requestParameters={'bucketName': 'r', 'x-amz-acl': ['public-read']})
        grant = trail_event(eventName='PutBucketAcl', requestParameters={'bucketName': 'r', 'AccessControlPolicy': {
            'AccessControlList': {'Grant': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}}]}}})
        policy = trail_event(eventName='PutBucketPolicy', requestParameters={'bucketName': 'r', 'bucketPolicy': {
            'Statement': [{'Effect': 'Allow', 'Principal': '*', 'Action': 's3:GetObject'}]}})
        private = trail_event(eventName='PutBucketPolicy', requestParameters={'bucketName': 'r', 'bucketPolicy': {
            'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::1:root'}}]}})
        self.assertEqual([cloudtrail_record(e, self.config)['public_access'] for e in (acl, grant, policy, private)], [1, 1, 1, 0])

    def test_role_session_uses_role_name_and_alias(self):
        config = load_config({'principal_aliases': {'etl': 'etl-pipeline'}})
        event = trail_event(userIdentity={'type': 'AssumedRole', 'arn': 'arn:aws:sts::1:assumed-role/etl/s',
                                          'sessionContext': {'sessionIssuer': {'userName': 'etl'}}})
        self.assertEqual(convert(json.dumps({'Records': [event]}).encode(), 'cloudtrail', config)[0]['principal'], 'etl-pipeline')

    def test_no_expected_regions_never_flags_region(self):
        record = cloudtrail_record(trail_event(awsRegion='ap-south-2'), load_config(None))
        self.assertEqual(record['unusual_region'], 0)

    def test_failed_events_can_be_skipped(self):
        events = json.dumps({'Records': [trail_event(), trail_event(eventID='e-2', errorCode='AccessDenied')]}).encode()
        self.assertEqual(len(convert(events, 'cloudtrail', load_config({'include_failed': False}))), 1)
        self.assertEqual(len(convert(events, 'cloudtrail', load_config(None))), 2)

    def test_jsonl_input_is_accepted(self):
        lines = b'\n'.join(json.dumps(trail_event(eventID=f'e-{i}')).encode() for i in range(3))
        self.assertEqual(len(convert(lines, 'cloudtrail')), 3)

    def test_missing_required_field_names_the_event(self):
        bad = trail_event(); del bad['eventTime']
        with self.assertRaisesRegex(ValueError, 'Source event 1'):
            convert(json.dumps({'Records': [bad]}).encode(), 'cloudtrail')

    def test_settings_are_validated(self):
        for settings in ({'unknown': 1}, {'large_read_bytes': 0}, {'expected_regions': 'us-east-1'},
                         {'include_failed': 'yes'}, {'tenant': ''}, []):
            with self.assertRaises(ValueError):
                load_config(settings)

    def test_unknown_format_is_rejected(self):
        with self.assertRaises(ValueError):
            convert(b'{}', 'syslog')

    def test_sample_trail_produces_expected_incidents(self):
        records = convert((SAMPLES / 'cloudtrail_sample.json').read_bytes(), 'cloudtrail',
                          load_config(json.loads((SAMPLES / 'cloudtrail_settings.json').read_text())))
        groups = {(r['principal'], r['resource']) for r in records}
        self.assertEqual(groups, {('anonymous', 'finance-reports'), ('ops-admin', 'finance-reports'),
                                  ('etl-pipeline', 'analytics-lake'), ('nightly-backup', 'backup-archive')})


class OcsfTests(unittest.TestCase):
    def test_sample_mapping(self):
        records = convert((SAMPLES / 'ocsf_sample.json').read_bytes(), 'ocsf',
                          load_config(json.loads((SAMPLES / 'ocsf_settings.json').read_text())))
        by_id = {r['event_id']: r for r in records}
        self.assertEqual(by_id['ocsf-0001']['timestamp'], '2026-10-31T05:20:00Z')
        self.assertEqual((by_id['ocsf-0002']['unusual_region'], by_id['ocsf-0002']['large_read']), (1, 1))
        self.assertEqual(by_id['ocsf-0003']['public_access'], 1)
        self.assertEqual(by_id['ocsf-0001']['source_format'], 'ocsf-api-activity')

    def test_other_classes_are_skipped(self):
        events = json.dumps([{'class_uid': 4001, 'metadata': {'uid': 'n'}},
                             {'class_uid': 6003, 'time': 0, 'metadata': {'uid': 'a'}, 'cloud': {'account': {'uid': 't'}},
                              'actor': {'user': {'name': 'u'}}, 'api': {'operation': 'Get'}, 'resources': [{'name': 'r'}]}]).encode()
        self.assertEqual([r['event_id'] for r in convert(events, 'ocsf')], ['a'])


class AdapterImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = InvestigationStore(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_cloudtrail_import_preserves_provider_event_in_provenance(self):
        content = (SAMPLES / 'cloudtrail_sample.json').read_bytes()
        settings = json.loads((SAMPLES / 'cloudtrail_settings.json').read_text())
        policy = json.loads((SAMPLES / 'cloudtrail_policy.json').read_text())
        result = self.store.import_records(content, 'cloudtrail', 'Analyst', 'trail.json', policy, settings)
        self.assertEqual(result['created'], 4)
        cases = {case['principal']: case for case in self.store.list_cases()}
        self.assertEqual(cases['anonymous']['risk_points'], 75)
        self.assertEqual(cases['etl-pipeline']['risk_points'], 60)
        detail = self.store.detail(cases['anonymous']['id'])
        raw = [json.loads(base64.b64decode(node['data']['bytes_b64'])) for node in detail['provenance'] if node['kind'] == 'raw']
        self.assertTrue(all(item['source_event']['eventSource'] == 's3.amazonaws.com' for item in raw))
        imported = detail['history'][0]['payload']['data']
        self.assertEqual((imported['source_format'], imported['adapter_settings']['large_read_bytes']), ('cloudtrail', 100 * MB))
        self.assertEqual([t['id'] for t in detail['techniques']], ['T1530', 'T1537'])

    def test_settings_rejected_for_normalized_formats(self):
        with self.assertRaisesRegex(ValueError, 'Adapter settings'):
            self.store.import_records((RESOURCE_ROOT / 'sample_events.jsonl').read_bytes(), 'jsonl', 'A', 'e.jsonl', None, {})




class SchemaConsistencyTests(unittest.TestCase):
    def test_adapter_settings_schema_lists_every_accepted_setting(self):
        schema = json.loads((Path(__file__).resolve().parents[1] / 'docs/schemas/adapter-settings.schema.json').read_text())
        for name in schema['properties']:
            load_config({name: {'tenant': 't', 'expected_regions': ['r'], 'public_resources': ['p'], 'large_read_bytes': 1,
                                'include_failed': True, 'principal_aliases': {'a': 'b'}, 'description': 'd'}[name]})
        with self.assertRaises(ValueError):
            load_config({'not_in_schema': 1})


if __name__ == '__main__':
    unittest.main()
