"""Azure Monitor and Google Cloud Audit Log adapters."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from cloud_threat.adapters import convert, load_config
from cloud_threat.adapters.azure import to_record as azure_record
from cloud_threat.adapters.gcp import to_record as gcp_record
from cloud_threat.core.evidence import RESOURCE_ROOT
from cloud_threat.workflow.store import InvestigationStore

SAMPLES = RESOURCE_ROOT / 'samples'
MB = 1024 * 1024
SUB = '00000000-aaaa-4bbb-8ccc-111122223333'


def sample(name):
    return (SAMPLES / f'{name}_sample.json').read_bytes(), json.loads((SAMPLES / f'{name}_settings.json').read_text())


def azure_read(**overrides):
    record = {'time': '2026-10-31T02:15:40.1234567Z', 'operationName': 'GetBlob', 'category': 'StorageRead',
              'resourceId': f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct/blobServices/default',
              'correlationId': 'c-1', 'statusCode': 200, 'location': 'eastus',
              'identity': {'type': 'OAuth', 'requester': {'upn': 'alice@contoso.example'}},
              'properties': {'accountName': 'acct', 'responseBodySize': 10}}
    record.update(overrides)
    return record


def gcp_entry(**payload):
    entry = {'insertId': 'g-1', 'timestamp': '2026-10-31T05:21:00.502931840Z', 'logName': 'projects/p1/logs/x',
             'resource': {'type': 'gcs_bucket', 'labels': {'project_id': 'p1', 'bucket_name': 'b1', 'location': 'us-central1'}},
             'protoPayload': {'methodName': 'storage.objects.get', 'authenticationInfo': {'principalEmail': 'bob@acme.example'},
                              'resourceLocation': {'currentLocations': ['us-central1']}}}
    entry['protoPayload'].update(payload)
    return entry


class AzureTests(unittest.TestCase):
    config = load_config({'expected_regions': ['eastus'], 'large_read_bytes': 100 * MB})

    def test_ordinary_read(self):
        record = azure_record(azure_read(), self.config)
        self.assertEqual((record['tenant'], record['principal'], record['resource'], record['action']),
                         (SUB, 'alice@contoso.example', 'acct', 'GetBlob'))
        self.assertEqual((record['public_access'], record['unusual_region'], record['large_read']), (0, 0, 0))
        self.assertEqual(record['event_id'], 'c-1/2026-10-31T02:15:40.1234567Z')

    def test_anonymous_unexpected_region_large_read(self):
        record = azure_record(azure_read(identity={'type': 'Anonymous'}, location='southeastasia',
                                         properties={'accountName': 'acct', 'responseBodySize': 200 * MB}), self.config)
        self.assertEqual(record['principal'], 'anonymous')
        self.assertEqual((record['public_access'], record['unusual_region'], record['large_read']), (1, 1, 1))

    def test_activity_log_public_container_and_claims(self):
        record = azure_record({
            'time': '2026-10-30T21:58:02Z', 'eventDataId': 'evt-9', 'operationName': 'MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE',
            'resourceId': f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/finance/blobServices/default/containers/c',
            'identity': {'claims': {'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn': 'ops@contoso.example'}},
            'properties': {'requestbody': '{"properties":{"publicAccess":"Container"}}'}}, self.config)
        self.assertEqual((record['event_id'], record['principal'], record['resource'], record['public_access']),
                         ('evt-9', 'ops@contoso.example', 'finance', 1))
        private = azure_record({**azure_read(), 'properties': {'accountName': 'acct', 'requestbody': '{"publicAccess":"None"}'}}, self.config)
        self.assertEqual(private['public_access'], 0)

    def test_failed_requests_can_be_skipped(self):
        records = json.dumps({'records': [azure_read(), azure_read(correlationId='c-2', statusCode=403)]}).encode()
        self.assertEqual(len(convert(records, 'azure', load_config({'include_failed': False}))), 1)

    def test_missing_identifier_is_rejected(self):
        bad = azure_read(); del bad['correlationId']
        with self.assertRaisesRegex(ValueError, 'Source event 1'):
            convert(json.dumps([bad]).encode(), 'azure')

    def test_sample_incidents(self):
        content, settings = sample('azure')
        records = convert(content, 'azure', load_config(settings))
        self.assertEqual({(r['principal'], r['resource']) for r in records}, {
            ('ops-admin@contoso.example', 'finreportsprod'), ('anonymous', 'finreportsprod'),
            ('etl-sync-app', 'analyticslake'), ('backup-agent-identity', 'backupvault01')})


class GcpTests(unittest.TestCase):
    config = load_config({'expected_regions': ['us-central1'], 'large_read_bytes': 100 * MB})

    def test_ordinary_read(self):
        record = gcp_record(gcp_entry(), self.config)
        self.assertEqual((record['tenant'], record['principal'], record['resource'], record['action']),
                         ('p1', 'bob@acme.example', 'b1', 'storage.objects.get'))
        self.assertEqual((record['public_access'], record['unusual_region'], record['large_read']), (0, 0, 0))

    def test_public_binding_region_and_size(self):
        entry = gcp_entry(serviceData={'policyDelta': {'bindingDeltas': [{'action': 'ADD', 'member': 'allUsers'}]}},
                          resourceLocation={'currentLocations': ['asia-south2']})
        entry['httpRequest'] = {'responseSize': str(500 * MB)}
        record = gcp_record(entry, self.config)
        self.assertEqual((record['public_access'], record['unusual_region'], record['large_read']), (1, 1, 1))
        removed = gcp_entry(serviceData={'policyDelta': {'bindingDeltas': [{'action': 'REMOVE', 'member': 'allUsers'}]}})
        self.assertEqual(gcp_record(removed, self.config)['public_access'], 0)

    def test_unauthenticated_caller_is_public(self):
        record = gcp_record(gcp_entry(authenticationInfo={}), self.config)
        self.assertEqual((record['principal'], record['public_access']), ('anonymous', 1))

    def test_failed_requests_can_be_skipped(self):
        entries = json.dumps([gcp_entry(), {**gcp_entry(status={'code': 7}), 'insertId': 'g-2'}]).encode()
        self.assertEqual(len(convert(entries, 'gcp', load_config({'include_failed': False}))), 1)
        self.assertEqual(len(convert(entries, 'gcp')), 2)

    def test_non_audit_entry_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'protoPayload'):
            convert(json.dumps([{'insertId': 'x', 'timestamp': '2026-10-31T00:00:00Z'}]).encode(), 'gcp')

    def test_sample_incidents(self):
        content, settings = sample('gcp')
        records = convert(content, 'gcp', load_config(settings))
        self.assertEqual({(r['principal'], r['resource']) for r in records}, {
            ('ops-admin@acme.example', 'press-assets'), ('svc-reporting', 'hr-exports'), ('backup-runner', 'db-backups')})


class ProviderSampleImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = InvestigationStore(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def load(self, name):
        content, settings = sample(name)
        policy = json.loads((SAMPLES / f'{name}_policy.json').read_text())
        self.store.import_records(content, name, 'Analyst', f'{name}.json', policy, settings)
        return {(case['principal'], case['resource']): case['risk_points'] for case in self.store.list_cases()}

    def test_azure_sample_scores(self):
        self.assertEqual(self.load('azure'), {('anonymous', 'finreportsprod'): 75, ('etl-sync-app', 'analyticslake'): 60,
                                              ('ops-admin@contoso.example', 'finreportsprod'): 45,
                                              ('backup-agent-identity', 'backupvault01'): 10})

    def test_gcp_sample_scores(self):
        self.assertEqual(self.load('gcp'), {('svc-reporting', 'hr-exports'): 60, ('ops-admin@acme.example', 'press-assets'): 45,
                                            ('backup-runner', 'db-backups'): 10})


if __name__ == '__main__':
    unittest.main()
