"""SQLite investigation repository with optimistic concurrency and signed history."""
import base64
import hashlib
import itertools
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from cloud_threat.core.canonical import canonical, digest
from cloud_threat.core.provenance import build
from cloud_threat.core.scoring import ACTIONS, MODEL, score
from cloud_threat.core.signing import seal, verify
from cloud_threat.core.techniques import annotate, headline
from cloud_threat.core.validation import normalize
from .crypto import fingerprint, load_identity, public_bytes, sign_document, verify_document
from .imports import group_records, policy_for, read_records


class ConflictError(ValueError):
    """The requested transition or version is no longer valid."""


class NotFoundError(ValueError):
    """No incident exists under the supplied identifier."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def required_text(value: Any, name: str, limit: int = 4000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f'{name} is required (maximum {limit} characters).')
    return value.strip()


class InvestigationStore:
    """Persist a single locally administered analyst workspace."""

    def __init__(self, workspace: str | Path):
        self.workspace = Path(workspace).resolve()
        self.key = load_identity(self.workspace)
        self.public_key = public_bytes(self.key)
        self.path = self.workspace / 'investigations.sqlite3'
        with self.transaction() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS schema_info(version INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS cases(
                    id TEXT PRIMARY KEY, tenant TEXT NOT NULL, principal TEXT NOT NULL,
                    resource TEXT NOT NULL, initial_root TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL, policy TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS observations(
                    case_id TEXT NOT NULL REFERENCES cases(id), event_id TEXT NOT NULL,
                    raw BLOB NOT NULL, PRIMARY KEY(case_id,event_id));
                CREATE TABLE IF NOT EXISTS revisions(
                    case_id TEXT NOT NULL REFERENCES cases(id), number INTEGER NOT NULL,
                    bundle TEXT NOT NULL, PRIMARY KEY(case_id,number));
                CREATE TABLE IF NOT EXISTS history(
                    case_id TEXT NOT NULL REFERENCES cases(id), sequence INTEGER NOT NULL,
                    document TEXT NOT NULL, PRIMARY KEY(case_id,sequence));
                CREATE TABLE IF NOT EXISTS previews(
                    id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
                    document TEXT NOT NULL);
                CREATE TRIGGER IF NOT EXISTS revision_no_update BEFORE UPDATE ON revisions
                    BEGIN SELECT RAISE(ABORT,'Evidence revisions are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS revision_no_delete BEFORE DELETE ON revisions
                    BEGIN SELECT RAISE(ABORT,'Evidence revisions are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS history_no_update BEFORE UPDATE ON history
                    BEGIN SELECT RAISE(ABORT,'Investigation history is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS history_no_delete BEFORE DELETE ON history
                    BEGIN SELECT RAISE(ABORT,'Investigation history is append-only'); END;
            ''')
            version = db.execute('SELECT version FROM schema_info').fetchone()
            if version is None:
                db.execute('INSERT INTO schema_info VALUES(1)')
            elif version['version'] != 1:
                raise ValueError('Unsupported workspace schema version')

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _audit(self, db, case_id: str, state: dict, actor: str, kind: str, data: dict) -> None:
        last = db.execute('SELECT sequence,document FROM history WHERE case_id=? ORDER BY sequence DESC LIMIT 1', (case_id,)).fetchone()
        sequence = last['sequence'] + 1 if last else 1
        previous = digest(json.loads(last['document'])) if last else None
        payload = {'schema': 'workflow-event-v1', 'case_id': case_id, 'sequence': sequence,
                   'previous': previous, 'occurred_at': now(), 'actor': actor,
                   'identity_assurance': 'self-asserted-local-analyst', 'kind': kind,
                   'data': data, 'state': state}
        document = sign_document(payload, self.key)
        db.execute('INSERT INTO history VALUES(?,?,?)', (case_id, sequence, canonical(document).decode()))

    def _load(self, db, case_id: str) -> tuple[dict, dict, dict, list, list[bytes]]:
        row = db.execute('SELECT * FROM cases WHERE id=?', (case_id,)).fetchone()
        if row is None:
            raise NotFoundError('Investigation not found.')
        state, policy = json.loads(row['state']), json.loads(row['policy'])
        entries = [json.loads(item['document']) for item in db.execute(
            'SELECT document FROM history WHERE case_id=? ORDER BY sequence', (case_id,))]
        previous = None
        for index, document in enumerate(entries, start=1):
            payload = verify_document(document, self.public_key)
            if payload['case_id'] != case_id or payload['sequence'] != index or payload['previous'] != previous:
                raise ValueError('Workflow history integrity check failed')
            previous = digest(document)
        if not entries or canonical(entries[-1]['payload']['state']) != canonical(state):
            raise ValueError('Incident state does not match signed history')
        revision = db.execute('SELECT bundle FROM revisions WHERE case_id=? AND number=?',
                              (case_id, state['revision'])).fetchone()
        if revision is None:
            raise ValueError('Missing evidence revision')
        bundle = json.loads(revision['bundle'])
        verify(bundle, self.public_key)
        nodes = bundle['payload']['graph']['nodes'].values()
        if bundle['payload']['graph']['root'] != state['root']:
            raise ValueError('Evidence root mismatch')
        bound_policy = next(node['data'] for node in nodes if node['kind'] == 'policy')
        if canonical(bound_policy) != canonical(policy):
            raise ValueError('Policy does not match signed evidence')
        raw = [bytes(item['raw']) for item in db.execute(
            'SELECT raw FROM observations WHERE case_id=? ORDER BY event_id', (case_id,))]
        bound_raw = [base64.b64decode(node['data']['bytes_b64']) for node in nodes if node['kind'] == 'raw']
        if sorted(raw) != sorted(bound_raw):
            raise ValueError('Source records do not match signed evidence')
        return state, policy, bundle, entries, raw

    @staticmethod
    def _check_version(state: dict, expected: Any) -> None:
        if type(expected) is not int or state['version'] != expected:
            raise ConflictError('This incident was updated elsewhere. The latest version has been loaded; review it and try again.')
        if state['status'] == 'closed':
            raise ConflictError('This investigation is closed and read-only. Import new records to open a new investigation.')

    def _commit(self, db, state: dict, actor: str, kind: str, data: dict) -> None:
        state['version'] += 1
        state['updated_at'] = now()
        db.execute('UPDATE cases SET state=? WHERE id=?', (canonical(state).decode(), state['id']))
        self._audit(db, state['id'], state, actor, kind, data)

    def import_records(self, content: bytes, format_name: str, actor: str,
                       filename: str, policy: dict | None = None,
                       adapter_settings: dict | None = None) -> dict:
        actor = required_text(actor, 'Analyst name', 100)
        filename = required_text(filename, 'Filename', 250)
        groups = group_records(read_records(content, format_name, adapter_settings))
        prepared = []
        for (tenant, principal, resource), records in groups.items():
            selected_policy = policy_for(tenant, policy)
            graph, decision, _, _ = build(records, selected_policy)
            features = next(node['data']['values'] for node in graph['nodes'].values() if node['kind'] == 'features')
            prepared.append((tenant, principal, resource, records, selected_policy, graph, decision, headline(features)))
        ids, reused = [], 0
        with self.transaction() as db:
            for tenant, principal, resource, records, selected_policy, graph, decision, title in prepared:
                existing = db.execute('SELECT id FROM cases WHERE initial_root=?', (graph['root'],)).fetchone()
                if existing:
                    self._load(db, existing['id'])
                    ids.append(existing['id']); reused += 1
                    continue
                case_id = str(uuid.uuid4())
                timestamp = now()
                state = {'id': case_id, 'tenant': tenant, 'principal': principal, 'resource': resource,
                         'title': title, 'status': 'open', 'assessment': None,
                         'rationale': '', 'approval': None, 'execution': None, 'closing_note': '',
                         'disposition': None, 'version': 1, 'revision': 1, 'root': graph['root'],
                         'risk_points': decision['risk_points'], 'alert': decision['alert'],
                         'created_at': timestamp, 'updated_at': timestamp}
                db.execute('INSERT INTO cases VALUES(?,?,?,?,?,?,?)',
                           (case_id, tenant, principal, resource, graph['root'], canonical(state).decode(), canonical(selected_policy).decode()))
                for raw in records:
                    event = normalize(raw)
                    db.execute('INSERT INTO observations VALUES(?,?,?)', (case_id, event['event_id'], raw))
                bundle = seal(graph, self.key, retention='local-sqlite-append-only-not-WORM')
                db.execute('INSERT INTO revisions VALUES(?,?,?)', (case_id, 1, canonical(bundle).decode()))
                self._audit(db, case_id, state, actor, 'imported', {
                    'filename': filename, 'source_file_sha256': hashlib.sha256(content).hexdigest(),
                    'source_format': format_name, 'adapter_settings': adapter_settings,
                    'records': len(records), 'policy_supplied': policy is not None})
                ids.append(case_id)
        return {'case_ids': ids, 'created': len(ids) - reused, 'reused': reused}

    def list_cases(self) -> list[dict]:
        with self.transaction() as db:
            rows = db.execute('SELECT id FROM cases ORDER BY rowid DESC').fetchall()
            cases = []
            for row in rows:
                state, _, bundle, _, _ = self._load(db, row['id'])
                features = self._features(bundle)
                cases.append({**state, 'headline': headline(features), 'indicators': features})
            return sorted(cases, key=lambda case: (case['status'] == 'closed', -case['risk_points'], case['id']))

    def detail(self, case_id: str) -> dict:
        with self.transaction() as db:
            state, policy, bundle, history, raw = self._load(db, case_id)
            nodes = bundle['payload']['graph']['nodes']
            values = lambda kind: next(node['data'] for node in nodes.values() if node['kind'] == kind)
            revisions = [{'number': row['number'], 'root': json.loads(row['bundle'])['payload']['graph']['root']}
                         for row in db.execute('SELECT number,bundle FROM revisions WHERE case_id=? ORDER BY number', (case_id,))]
            features = values('features')['values']
            options = self.response_options(state, policy, features)
            return {'case': state, 'decision': values('decision'), 'attribution': values('attribution'),
                    'features': features, 'recommended_scenario': values('counterfactual'),
                    'policy': policy, 'events': sorted([normalize(item) for item in raw], key=lambda event: datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))),
                    'original_records': [item.decode('utf8') for item in raw],
                    'provenance': [{'hash': key, **value} for key, value in nodes.items()],
                    'history': history, 'revisions': revisions, 'response_options': options,
                    'techniques': annotate(features), 'headline': headline(features), 'short_id': bundle['payload']['graph']['short_id'],
                    'verification': verify(bundle, self.public_key), 'key_fingerprint': fingerprint(self.public_key)}

    @staticmethod
    def _features(bundle: dict) -> dict[str, int]:
        return next(node['data']['values'] for node in bundle['payload']['graph']['nodes'].values() if node['kind'] == 'features')

    def summary(self) -> list[dict]:
        """One flat row per case for SIEM, ticketing or spreadsheet ingestion."""
        rows = []
        with self.transaction() as db:
            for row in db.execute('SELECT id FROM cases ORDER BY rowid').fetchall():
                state, _, bundle, history, _ = self._load(db, row['id'])
                graph = bundle['payload']['graph']
                features = self._features(bundle)
                rows.append({'schema': 'investigation-summary-v1', 'case_id': state['id'], 'title': headline(features),
                             'tenant': state['tenant'],
                             'principal': state['principal'], 'resource': state['resource'],
                             'risk_points': state['risk_points'], 'alert': state['alert'], 'status': state['status'],
                             'assessment': state['assessment'], 'disposition': state['disposition'],
                             'revision': state['revision'], 'evidence_root': state['root'], 'short_id': graph['short_id'],
                             'indicators': features, 'techniques': [item['id'] for item in annotate(features)],
                             'external_reference': (state['execution'] or {}).get('reference'),
                             'history_events': len(history), 'created_at': state['created_at'], 'updated_at': state['updated_at']})
        return rows

    @staticmethod
    def response_options(state: dict, policy: dict, features: dict) -> list[dict]:
        allowed = {(edge['principal'], edge['resource'], edge['action']) for edge in policy['edges']}
        results = []
        for size in range(1, len(ACTIONS) + 1):
            for candidate in itertools.combinations(ACTIONS, size):
                if any((state['principal'], state['resource'], action) not in allowed or features[feature] == 0
                       for action, feature, _ in candidate):
                    continue
                preview = dict(features)
                for _, feature, _ in candidate:
                    preview[feature] = 0
                results.append({'actions': [action for action, _, _ in candidate], 'features': preview,
                                'risk_points': score(preview), 'cost': sum(cost for _, _, cost in candidate),
                                'below_threshold': score(preview) < MODEL['threshold'], 'applied': False})
        return sorted(results, key=lambda item: item['cost'])

    def assess(self, case_id: str, expected: int, actor: str, assessment: str, rationale: str) -> dict:
        actor = required_text(actor, 'Analyst name', 100)
        rationale = required_text(rationale, 'Assessment rationale')
        if assessment not in {'expected', 'needs_evidence', 'threat'}:
            raise ValueError('Select a conclusion: expected activity, more evidence required or suspected threat.')
        with self.transaction() as db:
            state, _, _, _, _ = self._load(db, case_id)
            self._check_version(state, expected)
            if state['approval']:
                raise ConflictError('A response is already approved. Record its outcome or add new evidence before reassessing.')
            state.update(assessment=assessment, rationale=rationale,
                         status={'expected': 'reviewed_expected', 'needs_evidence': 'needs_evidence', 'threat': 'reviewed_threat'}[assessment])
            self._commit(db, state, actor, 'assessed', {'assessment': assessment, 'rationale': rationale})
        return self.detail(case_id)

    def note(self, case_id: str, expected: int, actor: str, text: str) -> dict:
        actor = required_text(actor, 'Analyst name', 100)
        text = required_text(text, 'Investigation note')
        with self.transaction() as db:
            state, _, _, _, _ = self._load(db, case_id)
            self._check_version(state, expected)
            self._commit(db, state, actor, 'note_added', {'note': text})
        return self.detail(case_id)

    def add_evidence(self, case_id: str, expected: int, actor: str, content: bytes | None,
                     format_name: str, policy: dict | None, reason: str,
                     adapter_settings: dict | None = None) -> dict:
        actor = required_text(actor, 'Analyst name', 100)
        reason = required_text(reason, 'Evidence update reason')
        incoming = read_records(content, format_name, adapter_settings) if content else []
        if not incoming and policy is None:
            raise ValueError('Attach additional events or an updated permission policy.')
        with self.transaction() as db:
            state, current_policy, _, _, raw = self._load(db, case_id)
            self._check_version(state, expected)
            selected_policy = policy_for(state['tenant'], policy) if policy is not None else current_policy
            existing = {normalize(item)['event_id']: item for item in raw}
            for item in incoming:
                event = normalize(item)
                if (event['tenant'], event['principal'], event['resource']) != (state['tenant'], state['principal'], state['resource']):
                    raise ValueError('Additional events must belong to the same tenant, principal and resource as this investigation.')
                if event['event_id'] in existing and existing[event['event_id']] != item:
                    raise ValueError('An existing event cannot be replaced. Use a new event ID for each new observation.')
                existing[event['event_id']] = item
            graph, decision, _, _ = build(list(existing.values()), selected_policy)
            if graph['root'] == state['root']:
                raise ConflictError('The update contains no new events or policy changes.')
            for event_id, item in existing.items():
                db.execute('INSERT OR IGNORE INTO observations VALUES(?,?,?)', (case_id, event_id, item))
            state.update(revision=state['revision'] + 1, root=graph['root'], risk_points=decision['risk_points'],
                         alert=decision['alert'], status='open', assessment=None, rationale='', approval=None,
                         execution=None, disposition=None, closing_note='')
            db.execute('INSERT INTO revisions VALUES(?,?,?)', (case_id, state['revision'], canonical(seal(graph, self.key, retention='local-sqlite-append-only-not-WORM')).decode()))
            db.execute('UPDATE cases SET policy=? WHERE id=?', (canonical(selected_policy).decode(), case_id))
            self._commit(db, state, actor, 'evidence_added', {'reason': reason, 'new_records': len(existing) - len(raw),
                                                           'assessment_reset': True, 'root': graph['root']})
        return self.detail(case_id)

    def preview(self, case_id: str, expected: int, actor: str, actions: list[str]) -> dict:
        actor = required_text(actor, 'Analyst name', 100)
        if not isinstance(actions, list) or not actions or any(not isinstance(action, str) for action in actions):
            raise ValueError('Select a permitted response action.')
        with self.transaction() as db:
            state, policy, bundle, _, _ = self._load(db, case_id)
            self._check_version(state, expected)
            if state['assessment'] != 'threat' or state['approval']:
                raise ConflictError('Record a suspected-threat assessment before previewing a response.')
            features = next(node['data']['values'] for node in bundle['payload']['graph']['nodes'].values() if node['kind'] == 'features')
            option = next((item for item in self.response_options(state, policy, features)
                           if sorted(item['actions']) == sorted(actions)), None)
            if option is None:
                raise ValueError('The selected action is not permitted by the current permission policy.')
            preview = {'id': str(uuid.uuid4()), 'case_id': case_id, 'revision': state['revision'],
                       'root': state['root'], 'created_at': now(), **option}
            document = sign_document(preview, self.key)
            db.execute('INSERT INTO previews VALUES(?,?,?)', (preview['id'], case_id, canonical(document).decode()))
            self._commit(db, state, actor, 'response_previewed', {'preview': preview})
        return {'incident': self.detail(case_id), 'preview': preview}

    def approve(self, case_id: str, expected: int, actor: str, preview_id: str, rationale: str) -> dict:
        actor = required_text(actor, 'Analyst name', 100)
        rationale = required_text(rationale, 'Approval rationale')
        with self.transaction() as db:
            state, policy, _, history, _ = self._load(db, case_id)
            self._check_version(state, expected)
            if state['assessment'] != 'threat' or state['approval']:
                raise ConflictError('A response can be approved only for a suspected threat without an existing approval.')
            if policy.get('separation_of_duties'):
                assessor = next((entry['payload']['actor'] for entry in reversed(history)
                                 if entry['payload']['kind'] == 'assessed'), None)
                if assessor is not None and assessor.casefold() == actor.casefold():
                    raise ConflictError('This policy requires separation of duties. The response must be approved '
                                        f'by an analyst other than the assessor ({assessor}).')
            row = db.execute('SELECT document FROM previews WHERE id=? AND case_id=?', (preview_id, case_id)).fetchone()
            if row is None:
                raise ValueError('The response preview was not found. Preview the response again.')
            preview = verify_document(json.loads(row['document']), self.public_key)
            if preview['root'] != state['root'] or preview['revision'] != state['revision']:
                raise ConflictError('The evidence has changed since this preview. Preview the response again before approving.')
            state['approval'] = {'preview': preview, 'actor': actor, 'rationale': rationale, 'approved_at': now()}
            state['status'] = 'response_approved'
            self._commit(db, state, actor, 'response_approved', state['approval'])
        return self.detail(case_id)

    def record_execution(self, case_id: str, expected: int, actor: str, outcome: str,
                         reference: str, explanation: str) -> dict:
        actor = required_text(actor, 'Analyst name', 100)
        reference = required_text(reference, 'External change or ticket reference', 500)
        explanation = required_text(explanation, 'Response outcome note')
        if outcome not in {'completed', 'failed', 'not_applied'}:
            raise ValueError('Select an outcome: completed, failed or not applied.')
        with self.transaction() as db:
            state, _, _, _, _ = self._load(db, case_id)
            self._check_version(state, expected)
            if not state['approval'] or state['execution']:
                raise ConflictError('An outcome can be recorded only for an approved response that has no outcome yet.')
            state['execution'] = {'outcome': outcome, 'reference': reference, 'note': explanation,
                                  'recorded_at': now(), 'actor': actor, 'execution_source': 'analyst-attested-external-action'}
            state['status'] = 'response_recorded'
            self._commit(db, state, actor, 'response_outcome_recorded', state['execution'])
        return self.detail(case_id)

    def close(self, case_id: str, expected: int, actor: str, disposition: str, explanation: str,
              reference: str = '') -> dict:
        actor = required_text(actor, 'Analyst name', 100)
        explanation = required_text(explanation, 'Closure rationale')
        with self.transaction() as db:
            state, _, _, _, _ = self._load(db, case_id)
            self._check_version(state, expected)
            if disposition == 'expected':
                if state['assessment'] != 'expected':
                    raise ConflictError('Record an expected-activity assessment before closing as expected.')
            elif disposition == 'resolved':
                if state['assessment'] != 'threat' or not state['execution'] or state['execution']['outcome'] != 'completed':
                    raise ConflictError('Closing as resolved requires an approved response with a completed outcome.')
            elif disposition == 'escalated':
                if state['assessment'] != 'threat':
                    raise ConflictError('Record a suspected-threat assessment before escalating.')
                reference = required_text(reference, 'Escalation reference', 500)
            else:
                raise ValueError('Select a disposition: expected activity, resolved or escalated.')
            state.update(status='closed', disposition=disposition, closing_note=explanation)
            self._commit(db, state, actor, 'closed', {'disposition': disposition, 'note': explanation, 'reference': reference})
        return self.detail(case_id)

    def export_material(self, case_id: str) -> dict:
        with self.transaction() as db:
            state, policy, bundle, history, raw = self._load(db, case_id)
            revisions = [json.loads(row['bundle']) for row in db.execute(
                'SELECT bundle FROM revisions WHERE case_id=? ORDER BY number', (case_id,))]
            return {'case': state, 'policy': policy, 'bundle': bundle, 'history': history,
                    'revisions': revisions, 'raw_records': raw}
