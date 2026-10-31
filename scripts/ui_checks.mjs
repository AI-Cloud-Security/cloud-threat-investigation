/** Exercise the shipped UI controller against the real HTTP application.
 * This DOM substitute checks interaction logic; it is not a browser renderer.
 * Node.js 20+ and the project's Python runtime dependency are required.
 */
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const python = process.env.CTI_PYTHON || 'python';
const temporary = await mkdtemp(path.join(tmpdir(), 'cloud-investigation-ui-'));
const child = spawn(python, ['-u', path.join(root, 'run.py'), '--no-browser', '--port', '0', '--workspace', path.join(temporary, 'workspace')], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
let output = '';
let logs = '';
child.stdout.on('data', (chunk) => { output += chunk; });
child.stderr.on('data', (chunk) => { logs = (logs + chunk).slice(-12000); });
const deadline = Date.now() + 15000;
let base;
try {
  while (!(base = output.match(/Open (http:\/\/127\.0\.0\.1:\d+)/)?.[1])) {
    if (child.exitCode !== null) throw new Error(`Application startup failed: ${logs}`);
    if (Date.now() > deadline) throw new Error('Application startup timed out.');
    await new Promise((resolve) => setTimeout(resolve, 30));
  }
  const html = await (await fetch(base)).text();
  const token = html.match(/name="workspace-token" content="([^"]+)"/)[1];
  const elements = new Map();
  const listeners = new Map();
  class Element {
    constructor(id) { this.id = id; this.value = ''; this.hidden = false; this.open = false; this.files = []; this.dataset = {}; this.textContent = ''; this.disabled = false; this.events = new Map(); }
    set innerHTML(value) {
      this.markup = value;
      for (const match of value.matchAll(/\bid="([^"]+)"/g)) elements.set(match[1], new Element(match[1]));
    }
    get innerHTML() { return this.markup || ''; }
    addEventListener(name, callback) { this.events.set(name, callback); }
    querySelectorAll() { return [{ disabled: false }]; }
    showModal() { this.open = true; }
    close() { this.open = false; }
    focus() { this.focused = true; }
    scrollIntoView() { /* No layout engine in this harness. */ }
    closest() { return this; }
  }
  for (const match of html.matchAll(/\bid="([^"]+)"/g)) elements.set(match[1], new Element(match[1]));
  const document = {
    getElementById(id) { assert(elements.has(id), `UI referenced a missing element: ${id}`); return elements.get(id); },
    querySelector(selector) { assert.equal(selector, 'meta[name="workspace-token"]'); return { content: token }; },
    addEventListener(name, callback) { listeners.set(name, callback); }
  };
  elements.get('filter').value = 'all';
  const storage = new Map();
  class FileReader {
    readAsDataURL(file) {
      this.result = `data:application/octet-stream;base64,${file.bytes.toString('base64')}`;
      queueMicrotask(() => this.onload());
    }
  }
  const context = vm.createContext({ document, FileReader, console, localStorage: { getItem: (key) => storage.get(key), setItem: (key, value) => storage.set(key, value) }, fetch: (url, options) => fetch(new URL(url, base), options) });
  const source = await readFile(path.join(root, 'src/cloud_threat/web/static/workspace.js'), 'utf8');
  vm.runInContext(source, context);
  await vm.runInContext('refresh()', context);
  const state = () => vm.runInContext('state', context);
  const element = (id) => document.getElementById(id);
  const fill = (id, value) => { element(id).value = value; };
  const file = (id, name, bytes) => { bytes = Buffer.from(bytes); element(id).files = [{ name, size: bytes.length, bytes, text: async () => bytes.toString('utf8') }]; };
  async function click(action, data = {}) {
    const target = new Element('action'); target.dataset = { action, ...data };
    await listeners.get('click')({ target });
  }
  async function submit(id) {
    await listeners.get('submit')({ target: element(id), preventDefault() {} });
    assert.notEqual(element('message').className, 'error', element('message').textContent);
  }
  const check = (value, explanation) => assert(value, explanation);
  check(state().cases.length === 0, 'First start must be empty.');
  check(element('case-detail').innerHTML.includes('Start with the activity'), 'Empty state must explain the next step.');
  await click('import');
  await click('examples');
  check(element('import-feedback').textContent.includes('analyst name'), 'Missing actor must be explained inside the dialog.');
  fill('import-actor', 'UI Analyst');
  await click('examples');
  check(state().cases.length === 3 && !element('import-dialog').open, 'Explicit included-data import must create three cases and close the dialog.');
  check(state().current.case.risk_points === 95, 'Imported payment case must be selected.');
  fill('search', 'backup-service'); element('search').events.get('input')();
  check((element('case-list').innerHTML.match(/class="case-item /g) || []).length === 1, 'Search must filter the inbox.');
  fill('search', ''); element('search').events.get('input')();

  fill('investigation-note', '<img src=x onerror=alert(1)>'); await submit('note-form');
  await click('tab', { tab: 'history' });
  check(element('case-detail').innerHTML.includes('&lt;img'), 'Untrusted analyst text must be escaped.');
  check(!element('case-detail').innerHTML.includes('<img'), 'Untrusted analyst text must not create markup.');
  await click('tab', { tab: 'overview' });
  fill('assessment', 'needs_evidence'); fill('rationale', 'Need another source observation.'); await submit('assessment-form');
  check(state().current.case.status === 'needs_evidence', 'Assessment must enter the evidence-collection branch.');
  await click('tab', { tab: 'evidence' });
  const records = await readFile(path.join(root, 'src/cloud_threat/resources/investigation_examples.jsonl'), 'utf8');
  const extra = JSON.parse(records.split('\n')[0]); extra.event_id = 'ui-additional-003';
  file('additional-events', 'additional.jsonl', JSON.stringify(extra)); fill('evidence-reason', 'Collected another relevant source event.');
  await submit('evidence-form');
  check(state().current.case.revision === 2 && state().current.case.assessment === null, 'Evidence addition must reset assessment and preserve a new revision.');
  await click('tab', { tab: 'overview' }); fill('assessment', 'threat'); fill('rationale', 'Unexpected access outside the approved operating context.'); await submit('assessment-form');
  await click('tab', { tab: 'response' }); fill('response-option', '0'); await submit('preview-form');
  check(state().preview.risk_points === 60, 'Permitted response preview must use the saved model and policy.');
  fill('approval-note', 'Approved within the permission policy.'); await submit('approval-form');
  check(state().current.case.status === 'response_approved', 'Approval must advance the workflow.');
  fill('outcome', 'completed'); fill('execution-reference', 'CHG-1042'); fill('execution-note', 'Completion was recorded by the analyst after an external change.'); await submit('execution-form');
  fill('disposition', 'resolved'); fill('closure-reference', ''); fill('closure-note', 'Reviewed the recorded external response and closed the investigation.'); await submit('closure-form');
  check(state().current.case.status === 'closed', 'Completed response must allow resolved closure.');
  check(element('case-detail').innerHTML.includes('Export the completed investigation'), 'Closed case must show the final export.');
  const tabTarget = element('tab-response'); tabTarget.dataset.tab = 'response';
  listeners.get('keydown')({ target: tabTarget, key: 'ArrowRight', preventDefault() {} });
  check(state().tab === 'history' && element('tab-history').focused, 'Arrow keys must move and focus investigation tabs.');
  await click('tab', { tab: 'response' });
  const caseId = state().selected;
  const archive = Buffer.from(await (await fetch(`${base}/api/cases/${caseId}/export`)).arrayBuffer());
  const publicKey = Buffer.from(await (await fetch(`${base}/api/public-key`)).arrayBuffer());
  await writeFile(path.join(temporary, 'investigation.zip'), archive); await writeFile(path.join(temporary, 'trusted-public-key.bin'), publicKey);
  const verified = spawnSync(python, [path.join(root, 'run.py'), 'verify-export', path.join(temporary, 'investigation.zip'), '--trusted-key', path.join(temporary, 'trusted-public-key.bin')], { encoding: 'utf8' });
  assert.equal(verified.status, 0, verified.stderr); check(JSON.parse(verified.stdout).final, 'UI export must verify independently as final.');
  await click('verify'); check(element('message').textContent.includes('passed integrity verification'), 'Recheck control must report a verified investigation.');

  const backup = state().cases.find((item) => item.principal === 'backup-service');
  await click('select', { id: backup.id }); fill('assessment', 'expected'); fill('rationale', 'Approved scheduled backup.'); await submit('assessment-form');
  await click('tab', { tab: 'response' }); fill('disposition', 'expected'); fill('closure-note', 'Confirmed the scheduled operation.'); await submit('closure-form');
  check(state().current.case.disposition === 'expected', 'Expected-activity closure must be available.');
  const analytics = state().cases.find((item) => item.principal === 'analytics-job');
  await click('select', { id: analytics.id }); fill('assessment', 'threat'); fill('rationale', 'Requires specialist review.'); await submit('assessment-form');
  await click('tab', { tab: 'response' }); fill('disposition', 'escalated'); fill('closure-reference', 'INC-1043'); fill('closure-note', 'Handed off for specialist review.'); await submit('closure-form');
  check(state().current.case.disposition === 'escalated', 'Escalation must close with a reference.');
  fill('filter', 'closed'); element('filter').events.get('change')();
  check((element('case-list').innerHTML.match(/class="case-item /g) || []).length === 3, 'Closed filter must include all completed cases.');
  fill('filter', 'all'); element('filter').events.get('change')();

  await click('import');
  const csv = 'tenant,event_id,timestamp,principal,resource,action,public_access,unusual_region,large_read\ntenant-csv,event-csv,2026-10-31T12:00:00Z,csv-service,csv-storage,read,1,1,1\n';
  file('event-file', 'own-events.csv', csv); await submit('import-form');
  check(state().current.case.principal === 'csv-service' && state().current.response_options.length === 0, 'CSV upload without policy must create a default-deny case.');
  await click('import'); file('event-file', 'invalid.jsonl', '{}');
  await listeners.get('submit')({ target: element('import-form'), preventDefault() {} });
  check(element('import-dialog').open && !element('import-feedback').hidden, 'Invalid upload must leave the dialog open with a visible error.');
  check(state().cases.length === 4, 'Invalid upload must not create partial cases.');
  const ownEvent = { ...extra, tenant: 'tenant-json', event_id: 'event-json', principal: 'json-service', resource: 'json-storage' };
  file('event-file', 'own-events.json', JSON.stringify({ events: [ownEvent] })); await submit('import-form');
  check(state().current.case.principal === 'json-service', 'JSON-container upload must complete through the UI form.');
  check(storage.get('cti-analyst') === 'UI Analyst', 'Analyst name must be retained locally.');
  console.log('UI controller checks passed: empty state, actor errors, three-case inbox, search, escaped notes, evidence revision, response approval, external outcome, all closure branches, trusted-key export, filtering and CSV/JSON imports.');
} finally {
  if (child.exitCode === null) { child.kill(); await once(child, 'exit'); }
  await rm(temporary, { recursive: true, force: true });
}
