"""Loopback HTTP application for the complete investigation workflow."""
import base64
import csv
import io
import json
import logging
import re
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from cloud_threat import __version__
from cloud_threat.core.validation import parse_record
from cloud_threat.workflow.crypto import fingerprint
from cloud_threat.workflow.exports import export_archive
from cloud_threat.workflow.imports import FIELDS
from cloud_threat.workflow.store import ConflictError, InvestigationStore, NotFoundError

LOG = logging.getLogger(__name__)
MAX_BODY_BYTES = 24 * 1024 * 1024
PROVIDER_SAMPLES = ('cloudtrail', 'azure', 'gcp')


def make_application(workspace: str | Path, port: int = 8765, host: str = '127.0.0.1',
                     allowed_hosts: tuple[str, ...] = ()) -> ThreadingHTTPServer:
    """Create the workspace server.

    ``host`` is the bind address (loopback by default). ``allowed_hosts`` adds
    extra ``hostname:port`` values accepted in Host/Origin headers, e.g. when a
    container maps the service to a different published port.
    """
    store = InvestigationStore(workspace)
    token = secrets.token_urlsafe(32)
    assets = Path(__file__).parent
    routes = {
        '/': ('templates/workspace.html', 'text/html; charset=utf-8'),
        '/static/workspace.css': ('static/workspace.css', 'text/css; charset=utf-8'),
        '/static/workspace.js': ('static/workspace.js', 'text/javascript; charset=utf-8'),
        '/static/favicon.svg': ('static/favicon.svg', 'image/svg+xml'),
        '/favicon.ico': ('static/favicon.svg', 'image/svg+xml'),
    }

    class Handler(BaseHTTPRequestHandler):
        server_version = f'CloudInvestigation/{__version__}'
        protocol_version = 'HTTP/1.0'
        timeout = 20

        def allowed(self) -> set[str]:
            return {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}', *allowed_hosts}

        def host_ok(self) -> bool:
            return self.headers.get('Host') in self.allowed()

        def send_bytes(self, status: int, content: bytes, kind: str, filename: str | None = None) -> None:
            self.send_response(status)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            if filename:
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
            self.end_headers()
            self.wfile.write(content)

        def send_json(self, status: int, value: dict) -> None:
            self.send_bytes(status, json.dumps(value, ensure_ascii=False).encode('utf8'), 'application/json')

        def dispatch_error(self, error: Exception) -> None:
            if isinstance(error, NotFoundError):
                status, message = 404, str(error)
            elif isinstance(error, ConflictError):
                status, message = 409, str(error)
            elif isinstance(error, (ValueError, KeyError, TypeError)):
                status, message = 422, str(error)
            else:
                LOG.exception('Investigation request failed')
                status, message = 500, 'The operation failed. Check the local service log before retrying.'
            self.send_json(status, {'error': message})

        def do_GET(self) -> None:
            if not self.host_ok():
                self.send_json(421, {'error': 'Unrecognized local host'})
                return
            path = urlsplit(self.path).path
            try:
                if path in routes:
                    file, kind = routes[path]
                    content = (assets / file).read_bytes()
                    if path == '/':
                        content = content.replace(b'{{csrf_token}}', token.encode())
                    self.send_bytes(200, content, kind)
                elif path == '/health':
                    self.send_json(200, {'status': 'ok', 'workspace': 'available'})
                elif path == '/api/workspace':
                    self.send_json(200, {'cases': store.list_cases(), 'key_fingerprint': fingerprint(store.public_key),
                                         'identity_assurance': 'self-asserted-local-analyst', 'version': __version__})
                elif path == '/api/summary.jsonl':
                    lines = b''.join(json.dumps(row, ensure_ascii=False).encode('utf8') + b'\n' for row in store.summary())
                    self.send_bytes(200, lines, 'application/x-ndjson; charset=utf-8', 'investigation-summary.jsonl')
                elif path == '/api/public-key':
                    self.send_bytes(200, store.public_key, 'application/octet-stream', 'trusted-public-key.bin')
                elif path == '/api/template.csv':
                    buffer = io.StringIO(newline='')
                    writer = csv.writer(buffer)
                    writer.writerow(FIELDS)
                    writer.writerow(['tenant-example', 'evt-001', '2026-10-31T12:00:00Z', 'service-example', 'storage-example', 'read', 1, 1, 1])
                    self.send_bytes(200, buffer.getvalue().encode(), 'text/csv; charset=utf-8', 'security-events.csv')
                elif path == '/api/example-policy':
                    self.send_json(200, {'tenant': 'tenant-example', 'version': 'permission-policy-v1', 'edges': [
                        {'principal': 'service-example', 'resource': 'storage-example', 'action': 'disable_public_access'},
                        {'principal': 'service-example', 'resource': 'storage-example', 'action': 'limit_read_volume'}]})
                elif match := re.fullmatch(r'/api/cases/([0-9a-f-]{36})(/export)?', path):
                    case_id, export = match.groups()
                    if export:
                        self.send_bytes(200, export_archive(store, case_id), 'application/zip', f'investigation-{case_id}.zip')
                    else:
                        self.send_json(200, store.detail(case_id))
                else:
                    self.send_json(404, {'error': 'Route not found'})
            except Exception as error:
                self.dispatch_error(error)

        def do_POST(self) -> None:
            if not self.host_ok():
                self.send_json(421, {'error': 'Unrecognized local host'})
                return
            origin = self.headers.get('Origin')
            allowed_origins = {f'http://{value}' for value in self.allowed()}
            supplied_token = self.headers.get('X-Workspace-Token', '')
            if (origin and origin not in allowed_origins) or not supplied_token.isascii() or not secrets.compare_digest(supplied_token, token):
                self.send_json(403, {'error': 'Workspace request token rejected. Reload the application.'})
                return
            if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                self.send_json(415, {'error': 'Send a bounded JSON request'})
                return
            try:
                length = int(self.headers.get('Content-Length', '-1'))
                if not 0 < length <= MAX_BODY_BYTES:
                    self.send_json(413, {'error': 'Request exceeds the 24 MiB limit'})
                    return
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError('Incomplete request body')
                data = parse_record(body, max_bytes=MAX_BODY_BYTES)
                path = urlsplit(self.path).path
                actor = data.get('actor')
                def content() -> bytes | None:
                    encoded = data.get('content')
                    if encoded is None:
                        return None
                    if not isinstance(encoded, str):
                        raise ValueError('File content must be base64 text')
                    return base64.b64decode(encoded, validate=True)
                if path == '/api/import':
                    self.send_json(201, store.import_records(content() or b'', data.get('format', ''), actor,
                                                           data.get('filename', ''), data.get('policy'),
                                                           data.get('adapter_settings')))
                elif path == '/api/examples':
                    fixtures = Path(__file__).parents[1] / 'resources'
                    dataset = data.get('dataset', 'normalized')
                    if dataset in PROVIDER_SAMPLES:
                        samples = fixtures / 'samples'
                        self.send_json(201, store.import_records(
                            (samples / f'{dataset}_sample.json').read_bytes(), dataset, actor, f'sample-{dataset}.json',
                            json.loads((samples / f'{dataset}_policy.json').read_text(encoding='utf8')),
                            json.loads((samples / f'{dataset}_settings.json').read_text(encoding='utf8'))))
                    elif dataset == 'normalized':
                        policy = json.loads((fixtures / 'investigation_policy.json').read_text(encoding='utf8'))
                        self.send_json(201, store.import_records((fixtures / 'investigation_examples.jsonl').read_bytes(), 'jsonl', actor,
                                                               'included-security-records.jsonl', policy))
                    else:
                        raise ValueError('Unknown sample dataset.')
                elif match := re.fullmatch(r'/api/cases/([0-9a-f-]{36})/(assessment|note|evidence|preview|approve|execution|close)', path):
                    case_id, command = match.groups()
                    common = (case_id, data.get('version'), actor)
                    if command == 'assessment':
                        result = store.assess(*common, data.get('assessment'), data.get('rationale'))
                    elif command == 'note':
                        result = store.note(*common, data.get('note'))
                    elif command == 'evidence':
                        result = store.add_evidence(*common, content(), data.get('format', ''), data.get('policy'), data.get('reason'), data.get('adapter_settings'))
                    elif command == 'preview':
                        result = store.preview(*common, data.get('actions'))
                    elif command == 'approve':
                        result = store.approve(*common, data.get('preview_id'), data.get('rationale'))
                    elif command == 'execution':
                        result = store.record_execution(*common, data.get('outcome'), data.get('reference'), data.get('note'))
                    else:
                        result = store.close(*common, data.get('disposition'), data.get('note'), data.get('reference', ''))
                    self.send_json(200, result)
                else:
                    self.send_json(404, {'error': 'Route not found'})
            except Exception as error:
                self.dispatch_error(error)

        def log_message(self, format_string: str, *args) -> None:
            LOG.info('%s - %s', self.address_string(), format_string % args)

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    server.store = store
    return server
