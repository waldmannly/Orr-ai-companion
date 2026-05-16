/**
 * Integration verification script for all new roadmap features.
 * Run: node tests/integration-check.mjs
 */
import { initDb, upsertSession, insertEvent, insertMemoryOp, upsertBaseline, getBaseline, getAllBaselines, getSessionTokens, getProjectTokens, getMemoryLineage, getMemoryHealth, getEventsFiltered, getSessionHealthMetrics, getGlobalMetrics } from '../dist/storage/db.js';
import { mergeConfig } from '../dist/config/index.js';
import { classifyRiskWithReasons } from '../dist/risk/classifier.js';
import { testWebhook } from '../dist/notifications/index.js';
import { createDashboardServer } from '../dist/dashboard/server.js';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TEST_DB = path.join(__dirname, '.integ-test.db');

// Clean slate
try { fs.unlinkSync(TEST_DB); } catch {}
try { fs.unlinkSync(TEST_DB + '-wal'); } catch {}
try { fs.unlinkSync(TEST_DB + '-shm'); } catch {}

let pass = 0, fail = 0;
function check(name, condition, detail) {
  if (condition) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}${detail ? ' — ' + detail : ''}`); }
}

initDb(TEST_DB);

// ════════════════════════════════════════════
console.log('\n══ 1. CONFIG — Notifications Merge ══');
// ════════════════════════════════════════════

const cfg1 = mergeConfig({});
check('defaults: slack.enabled = false', cfg1.notifications.slack.enabled === false);
check('defaults: slack.minSeverity = warn', cfg1.notifications.slack.minSeverity === 'warn');
check('defaults: slack.url = empty', cfg1.notifications.slack.url === '');
check('defaults: webhook.enabled = false', cfg1.notifications.webhook.enabled === false);
check('defaults: webhook.minSeverity = danger', cfg1.notifications.webhook.minSeverity === 'danger');
check('defaults: desktop.enabled = true', cfg1.notifications.desktop.enabled === true);
check('defaults: desktop.minSeverity = danger', cfg1.notifications.desktop.minSeverity === 'danger');

const cfg2 = mergeConfig({ notifications: { slack: { enabled: true, url: 'https://hooks.slack.com/test' } } });
check('partial merge: slack.enabled = true', cfg2.notifications.slack.enabled === true);
check('partial merge: slack.url preserved', cfg2.notifications.slack.url === 'https://hooks.slack.com/test');
check('partial merge: slack.minSeverity from defaults', cfg2.notifications.slack.minSeverity === 'warn');
check('partial merge: webhook untouched', cfg2.notifications.webhook.enabled === false);
check('partial merge: desktop untouched', cfg2.notifications.desktop.enabled === true);

const cfg3 = mergeConfig({ notifications: { desktop: { minSeverity: 'watch' } } });
check('partial merge desktop: minSeverity override', cfg3.notifications.desktop.minSeverity === 'watch');
check('partial merge desktop: enabled still defaults', cfg3.notifications.desktop.enabled === true);

// ════════════════════════════════════════════
console.log('\n══ 2. BASELINES ══');
// ════════════════════════════════════════════

upsertBaseline('integ-proj', 'events_per_session', 50, 5);
const b1 = getBaseline('integ-proj', 'events_per_session');
check('baseline created', !!b1);
check('baseline value = 50', b1.value === 50);
check('baseline sample_count = 5', b1.sample_count === 5);

upsertBaseline('integ-proj', 'danger_per_session', 3, 10);
const all = getAllBaselines('integ-proj');
check('getAllBaselines returns 2 entries', all.length === 2);
check('metrics are correct', all.map(x => x.metric).sort().join(',') === 'danger_per_session,events_per_session');

// Upsert again — should update average
upsertBaseline('integ-proj', 'events_per_session', 100, 1);
const b2 = getBaseline('integ-proj', 'events_per_session');
check('baseline updated (sample_count grew)', b2.sample_count >= 6);

// ════════════════════════════════════════════
console.log('\n══ 3. TOKEN TRACKING ══');
// ════════════════════════════════════════════

upsertSession({ id: 'tok-integ-1', workspace: '/w', project_name: 'integ-proj', started_at: new Date().toISOString(), ended_at: null, total_events: 5, danger_count: 0, warn_count: 0, source_tool: 'vscode-copilot' });
insertEvent({ session_id: 'tok-integ-1', timestamp: new Date().toISOString(), agent_id: 'main', parent_agent_id: null, event_type: 'user_message', tool_name: null, risk_level: 'info', summary: 'hello', file_paths: [], command: null, parameters: null, duration_ms: null, raw_log: '', source_tool: 'vscode-copilot', token_count: 100, anomaly_score: null });
insertEvent({ session_id: 'tok-integ-1', timestamp: new Date().toISOString(), agent_id: 'main', parent_agent_id: null, event_type: 'assistant_message', tool_name: null, risk_level: 'info', summary: 'reply', file_paths: [], command: null, parameters: null, duration_ms: null, raw_log: '', source_tool: 'vscode-copilot', token_count: 300, anomaly_score: 0.8 });
insertEvent({ session_id: 'tok-integ-1', timestamp: new Date().toISOString(), agent_id: 'main', parent_agent_id: null, event_type: 'file_write', tool_name: null, risk_level: 'watch', summary: 'edit', file_paths: ['/a.ts'], command: null, parameters: null, duration_ms: null, raw_log: '', source_tool: 'vscode-copilot', token_count: null, anomaly_score: null });

const sessTokens = getSessionTokens('tok-integ-1');
check('session tokens = 400', sessTokens === 400);
const projTokens = getProjectTokens('integ-proj');
check('project tokens >= 400', projTokens >= 400);
check('null token_count events dont count', sessTokens === 400); // 100+300, not 100+300+0

// ════════════════════════════════════════════
console.log('\n══ 4. MEMORY LINEAGE ══');
// ════════════════════════════════════════════

insertMemoryOp({ event_id: null, session_id: 'tok-integ-1', timestamp: '2025-06-01T10:00:00Z', operation: 'write', memory_scope: 'user', memory_path: '/memories/integ.md', content_summary: 'Created file', risk_level: 'info' });
insertMemoryOp({ event_id: null, session_id: 'tok-integ-1', timestamp: '2025-06-01T11:00:00Z', operation: 'read', memory_scope: 'user', memory_path: '/memories/integ.md', content_summary: 'Read file', risk_level: 'info' });
insertMemoryOp({ event_id: null, session_id: 'tok-integ-1', timestamp: '2025-06-01T12:00:00Z', operation: 'write', memory_scope: 'user', memory_path: '/memories/integ.md', content_summary: 'Updated with injection', risk_level: 'danger' });

const lineage = getMemoryLineage('/memories/integ.md');
check('lineage has 3 ops', lineage.length === 3);
check('lineage ordered by time', lineage[0].timestamp < lineage[2].timestamp);
check('lineage includes write-read-write', lineage.map(o => o.operation).join(',') === 'write,read,write');
check('lineage preserves risk_level', lineage[2].risk_level === 'danger');

const emptyLineage = getMemoryLineage('/nonexistent/path.md');
check('empty lineage for unknown path', emptyLineage.length === 0);

const health = getMemoryHealth();
check('memory health returns entries', health.length > 0);
const entry = health.find(h => h.memory_path === '/memories/integ.md');
check('health entry found for integ.md', !!entry);
if (entry) {
  check('health write_count = 2', entry.write_count === 2);
  check('health read_count = 1', entry.read_count === 1);
  check('health sessions = 1', entry.sessions === 1);
}

// ════════════════════════════════════════════
console.log('\n══ 5. ADVANCED FILTERING ══');
// ════════════════════════════════════════════

const f1 = getEventsFiltered({});
check('no filters returns events', f1.length > 0);

const f2 = getEventsFiltered({ sessionId: 'tok-integ-1' });
check('filter by session', f2.length === 3);
check('all from correct session', f2.every(e => e.session_id === 'tok-integ-1'));

const f3 = getEventsFiltered({ riskLevel: 'watch' });
check('filter by risk_level=watch', f3.length > 0 && f3.every(e => e.risk_level === 'watch'));

const f4 = getEventsFiltered({ eventType: 'user_message', sessionId: 'tok-integ-1' });
check('filter by event_type + session', f4.length === 1);

const f5 = getEventsFiltered({ search: 'reply' });
check('search finds matching event', f5.length >= 1);

const f6 = getEventsFiltered({ startDate: '2099-01-01' });
check('future start date returns empty', f6.length === 0);

const f7 = getEventsFiltered({ limit: 2 });
check('limit works', f7.length === 2);

const f8 = getEventsFiltered({ offset: 1000 });
check('large offset returns empty', f8.length === 0);

// ════════════════════════════════════════════
console.log('\n══ 6. SESSION HEALTH METRICS ══');
// ════════════════════════════════════════════

upsertSession({ id: 'grade-A', workspace: '/w', project_name: 'integ-proj', started_at: new Date(Date.now() - 3600000).toISOString(), ended_at: new Date().toISOString(), total_events: 50, danger_count: 0, warn_count: 1, source_tool: 'vscode-copilot' });
upsertSession({ id: 'grade-C', workspace: '/w', project_name: 'integ-proj', started_at: new Date(Date.now() - 7200000).toISOString(), ended_at: new Date().toISOString(), total_events: 200, danger_count: 2, warn_count: 15, source_tool: 'vscode-copilot' });
upsertSession({ id: 'grade-F', workspace: '/w', project_name: 'integ-proj', started_at: new Date(Date.now() - 1800000).toISOString(), ended_at: new Date().toISOString(), total_events: 100, danger_count: 10, warn_count: 20, source_tool: 'vscode-copilot' });

const hA = getSessionHealthMetrics('grade-A');
check('grade A session', hA.grade === 'A' || hA.grade === 'B', `got ${hA.grade}`);
check('grade A danger=0', hA.dangerCount === 0);
check('duration > 0', hA.durationMinutes > 0);
check('eventsPerMinute > 0', hA.eventsPerMinute > 0);

const hC = getSessionHealthMetrics('grade-C');
check('grade C session (danger=2, warn=15)', hC.grade === 'C', `got ${hC.grade}`);

const hF = getSessionHealthMetrics('grade-F');
check('grade F session (danger=10)', hF.grade === 'F', `got ${hF.grade}`);
check('risk velocity > 0 for dangerous session', hF.riskVelocity > 0);

const hNone = getSessionHealthMetrics('nonexistent');
check('nonexistent session returns grade A', hNone.grade === 'A');
check('nonexistent session returns 0 events', hNone.totalEvents === 0);

// ════════════════════════════════════════════
console.log('\n══ 7. GLOBAL METRICS ══');
// ════════════════════════════════════════════

const gm = getGlobalMetrics();
check('totalSessions > 0', gm.totalSessions > 0);
check('totalEvents > 0', gm.totalEvents > 0);
check('projectsCovered > 0', gm.projectsCovered > 0);
check('alertFatigueIndex is number', typeof gm.alertFatigueIndex === 'number');
check('acknowledgedAlerts is number', typeof gm.acknowledgedAlerts === 'number');
check('avgTimeToFirstDanger is number', typeof gm.avgTimeToFirstDanger === 'number');

// ════════════════════════════════════════════
console.log('\n══ 8. NEW DETECTION RULES ══');
// ════════════════════════════════════════════

const cfg = mergeConfig({});
const ruleTests = [
  { name: 'dependency_mutation (npm install)', ev: { event_type: 'terminal_command', command: 'npm install express', summary: '', file_paths: [] }, expected: 'dependency_mutation' },
  { name: 'dependency_mutation (npm remove)', ev: { event_type: 'terminal_command', command: 'npm remove lodash', summary: '', file_paths: [] }, expected: 'dependency_mutation' },
  { name: 'dependency_mutation (yarn add)', ev: { event_type: 'terminal_command', command: 'yarn add react', summary: '', file_paths: [] }, expected: 'dependency_mutation' },
  { name: 'dependency_mutation (pip install)', ev: { event_type: 'terminal_command', command: 'pip install requests', summary: '', file_paths: [] }, expected: 'dependency_mutation' },
  { name: 'dependency_mutation (cargo add)', ev: { event_type: 'terminal_command', command: 'cargo add serde', summary: '', file_paths: [] }, expected: 'dependency_mutation' },
  { name: 'env_var_access ($SECRET_KEY)', ev: { event_type: 'terminal_command', command: 'echo $SECRET_KEY', summary: '', file_paths: [] }, expected: 'env_var_access' },
  { name: 'env_var_access (printenv)', ev: { event_type: 'terminal_command', command: 'printenv', summary: '', file_paths: [] }, expected: 'env_var_access' },
  { name: 'env_var_access ($API_TOKEN)', ev: { event_type: 'terminal_command', command: 'curl -H "Auth: $API_TOKEN"', summary: '', file_paths: [] }, expected: 'env_var_access' },
  { name: 'protected_branch (main)', ev: { event_type: 'git_push', command: 'git push origin main', summary: '', file_paths: [] }, expected: 'protected_branch' },
  { name: 'protected_branch (production)', ev: { event_type: 'git_push', command: 'git push origin production', summary: '', file_paths: [] }, expected: 'protected_branch' },
  { name: 'protected_branch (master)', ev: { event_type: 'git_commit', command: 'git commit -m "fix" && git push master', summary: '', file_paths: [] }, expected: 'protected_branch' },
  { name: 'file_permissions (chmod)', ev: { event_type: 'terminal_command', command: 'chmod 777 /tmp/script.sh', summary: '', file_paths: [] }, expected: 'file_permissions' },
  { name: 'file_permissions (chown)', ev: { event_type: 'terminal_command', command: 'chown root:root /etc/passwd', summary: '', file_paths: [] }, expected: 'file_permissions' },
  { name: 'file_permissions (icacls)', ev: { event_type: 'terminal_command', command: 'icacls C:\\secret /grant Everyone:F', summary: '', file_paths: [] }, expected: 'file_permissions' },
  { name: 'retry_pattern (--retry)', ev: { event_type: 'terminal_command', command: 'curl --retry 5 http://api.com', summary: '', file_paths: [] }, expected: 'retry_pattern' },
  { name: 'retry_pattern (while true)', ev: { event_type: 'terminal_command', command: 'while true; do curl http://x; done', summary: '', file_paths: [] }, expected: 'retry_pattern' },
  { name: 'process_management (kill)', ev: { event_type: 'terminal_command', command: 'kill -9 1234', summary: '', file_paths: [] }, expected: 'process_management' },
  { name: 'process_management (systemctl)', ev: { event_type: 'terminal_command', command: 'systemctl restart nginx', summary: '', file_paths: [] }, expected: 'process_management' },
  { name: 'process_management (taskkill)', ev: { event_type: 'terminal_command', command: 'taskkill /F /PID 1234', summary: '', file_paths: [] }, expected: 'process_management' },
];

for (const t of ruleTests) {
  const result = classifyRiskWithReasons(t.ev, cfg);
  const rules = result.signals.map(s => s.rule);
  check(t.name, rules.includes(t.expected), `rules: [${rules.join(', ')}]`);
}

// Negative tests — make sure rules don't fire incorrectly
const negTests = [
  { name: 'no dep_mutation on npm run', ev: { event_type: 'terminal_command', command: 'npm run build', summary: '', file_paths: [] }, notExpected: 'dependency_mutation' },
  { name: 'no env_var on normal echo', ev: { event_type: 'terminal_command', command: 'echo hello', summary: '', file_paths: [] }, notExpected: 'env_var_access' },
  { name: 'no protected_branch on feature', ev: { event_type: 'git_push', command: 'git push origin feature/xyz', summary: '', file_paths: [] }, notExpected: 'protected_branch' },
  { name: 'no process_mgmt on ls', ev: { event_type: 'terminal_command', command: 'ls -la', summary: '', file_paths: [] }, notExpected: 'process_management' },
];
for (const t of negTests) {
  const result = classifyRiskWithReasons(t.ev, cfg);
  const rules = result.signals.map(s => s.rule);
  check(t.name, !rules.includes(t.notExpected), `unexpected: ${t.notExpected} in [${rules.join(', ')}]`);
}

// ════════════════════════════════════════════
console.log('\n══ 9. WEBHOOK TEST (no config) ══');
// ════════════════════════════════════════════

const wr1 = await testWebhook('slack');
check('testWebhook(slack) returns ok=false', wr1.ok === false);
check('testWebhook(slack) error message', wr1.error === 'No URL configured');

const wr2 = await testWebhook('webhook');
check('testWebhook(webhook) returns ok=false', wr2.ok === false);
check('testWebhook(webhook) error message', wr2.error === 'No URL configured');

// ════════════════════════════════════════════
console.log('\n══ 10. API ROUTES — Live Server ══');
// ════════════════════════════════════════════

const app = createDashboardServer(mergeConfig({}));
const server = http.createServer(app);
await new Promise(r => server.listen(0, '127.0.0.1', r));
const port = server.address().port;
const BASE = `http://127.0.0.1:${port}`;

async function apiCheck(method, path, body, assertions) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(`${BASE}${path}`, opts);
  const data = await res.json();
  for (const [name, fn] of assertions) {
    check(name, fn(res, data), `status=${res.status}`);
  }
}

await apiCheck('GET', '/api/metrics/global', null, [
  ['GET /api/metrics/global 200', (r) => r.status === 200],
  ['global metrics has totalSessions', (_, d) => typeof d.totalSessions === 'number'],
  ['global metrics has alertFatigueIndex', (_, d) => typeof d.alertFatigueIndex === 'number'],
  ['global metrics has projectsCovered', (_, d) => typeof d.projectsCovered === 'number'],
]);

await apiCheck('GET', '/api/baselines/integ-proj', null, [
  ['GET /api/baselines/:project 200', (r) => r.status === 200],
  ['baselines is array', (_, d) => Array.isArray(d)],
  ['baselines has entries', (_, d) => d.length >= 2],
]);

await apiCheck('GET', '/api/sessions/tok-integ-1/tokens', null, [
  ['GET /api/sessions/:id/tokens 200', (r) => r.status === 200],
  ['tokens = 400', (_, d) => d.tokens === 400],
]);

await apiCheck('GET', '/api/projects/integ-proj/tokens', null, [
  ['GET /api/projects/:name/tokens 200', (r) => r.status === 200],
  ['project tokens >= 400', (_, d) => d.tokens >= 400],
]);

await apiCheck('GET', '/api/memory/lineage?path=/memories/integ.md', null, [
  ['GET /api/memory/lineage 200', (r) => r.status === 200],
  ['lineage is array with 3 ops', (_, d) => Array.isArray(d) && d.length === 3],
]);

await apiCheck('GET', '/api/memory/lineage', null, [
  ['GET /api/memory/lineage without path = 400', (r) => r.status === 400],
]);

await apiCheck('GET', '/api/memory/health', null, [
  ['GET /api/memory/health 200', (r) => r.status === 200],
  ['health is array', (_, d) => Array.isArray(d)],
]);

await apiCheck('GET', '/api/events/filtered?sessionId=tok-integ-1', null, [
  ['GET /api/events/filtered 200', (r) => r.status === 200],
  ['filtered returns array', (_, d) => Array.isArray(d)],
  ['filtered by session has 3 events', (_, d) => d.length === 3],
]);

await apiCheck('GET', '/api/events/filtered?riskLevel=watch&limit=1', null, [
  ['filtered with risk+limit', (r) => r.status === 200],
  ['limit=1 works', (_, d) => d.length === 1],
]);

await apiCheck('GET', '/api/sessions/grade-F/health', null, [
  ['GET /api/sessions/:id/health 200', (r) => r.status === 200],
  ['grade = F', (_, d) => d.grade === 'F'],
  ['dangerCount = 10', (_, d) => d.dangerCount === 10],
]);

await apiCheck('GET', '/api/sessions/grade-A/replay', null, [
  ['GET /api/sessions/:id/replay 200', (r) => r.status === 200],
  ['replay has events array', (_, d) => Array.isArray(d.events)],
]);

await apiCheck('POST', '/api/notifications/test', { type: 'slack' }, [
  ['POST /api/notifications/test slack 200', (r) => r.status === 200],
  ['result ok=false (no url)', (_, d) => d.ok === false],
]);

await apiCheck('POST', '/api/notifications/test', { type: 'webhook' }, [
  ['POST /api/notifications/test webhook 200', (r) => r.status === 200],
  ['result ok=false (no url)', (_, d) => d.ok === false],
]);

await apiCheck('POST', '/api/notifications/test', { type: 'email' }, [
  ['POST /api/notifications/test invalid = 400', (r) => r.status === 400],
]);

server.close();

// Cleanup test DB
try { fs.unlinkSync(TEST_DB); } catch {}
try { fs.unlinkSync(TEST_DB + '-wal'); } catch {}
try { fs.unlinkSync(TEST_DB + '-shm'); } catch {}

// ════════════════════════════════════════════
console.log('\n══════════════════════════════════════════════════');
console.log(`  INTEGRATION CHECK: ${pass} passed, ${fail} failed`);
console.log('══════════════════════════════════════════════════');
if (fail > 0) process.exit(1);
