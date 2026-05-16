/**
 * Tests for the Intervention Queue system — approve/deny blocked agent actions.
 */
import { createIntervention, resolveIntervention, getPendingInterventions, getResolvedInterventions,
  getAllInterventions, getIntervention, denyAllPending, getInterventionStats,
  waitForResolution, setAutoDenyTimeout, getAutoDenyTimeout, _resetForTesting,
} from '../dist/guardrails/intervention.js';
import { initDb, upsertSession, insertEvent } from '../dist/storage/db.js';
import { mergeConfig } from '../dist/config/index.js';
import { createDashboardServer } from '../dist/dashboard/server.js';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TEST_DB = path.join(__dirname, '.intervention-test.db');
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
console.log('\n══ 1. CREATE & RESOLVE ══');
// ════════════════════════════════════════════

_resetForTesting();

const int1 = createIntervention({
  sessionId: 's1', rule: 'scope_blocked', severity: 'danger',
  message: 'File ".env" matches blocked pattern', actionType: 'file',
  actionTarget: '/home/user/.env.local', provider: 'vscode-copilot',
});

check('intervention created', !!int1.id);
check('status is pending', int1.status === 'pending');
check('has timestamp', !!int1.timestamp);
check('has sessionId', int1.sessionId === 's1');
check('has rule', int1.rule === 'scope_blocked');
check('has provider', int1.provider === 'vscode-copilot');

const pending = getPendingInterventions();
check('1 pending', pending.length === 1);
check('pending is int1', pending[0].id === int1.id);

// Resolve as denied
const resolved = resolveIntervention(int1.id, 'denied', 'user');
check('resolve returns intervention', !!resolved);
check('status now denied', resolved.status === 'denied');
check('resolvedBy is user', resolved.resolvedBy === 'user');
check('resolvedAt set', !!resolved.resolvedAt);

check('0 pending after resolve', getPendingInterventions().length === 0);
check('1 resolved', getResolvedInterventions().length === 1);

// Resolve again should fail
const again = resolveIntervention(int1.id, 'approved');
check('double resolve returns null', again === null);

// ════════════════════════════════════════════
console.log('\n══ 2. APPROVE FLOW ══');
// ════════════════════════════════════════════

_resetForTesting();

const int2 = createIntervention({
  sessionId: 's2', rule: 'command_blocked', severity: 'danger',
  message: 'Command matches blocked pattern: rm -rf', actionType: 'command',
  actionTarget: 'rm -rf /tmp/important', provider: 'claude-code',
});

const approved = resolveIntervention(int2.id, 'approved', 'user');
check('approved intervention', approved.status === 'approved');
check('approved resolvedBy user', approved.resolvedBy === 'user');

// ════════════════════════════════════════════
console.log('\n══ 3. DENY ALL ══');
// ════════════════════════════════════════════

_resetForTesting();

createIntervention({ sessionId: 's1', rule: 'scope_blocked', severity: 'danger', message: 'msg1', actionType: 'file', actionTarget: '/a', provider: 'p1' });
createIntervention({ sessionId: 's1', rule: 'command_blocked', severity: 'danger', message: 'msg2', actionType: 'command', actionTarget: 'rm -rf /', provider: 'p1' });
createIntervention({ sessionId: 's2', rule: 'network_blocked', severity: 'danger', message: 'msg3', actionType: 'network', actionTarget: 'evil.com', provider: 'p2' });

check('3 pending before deny-all', getPendingInterventions().length === 3);
const denied = denyAllPending();
check('deny-all returns 3', denied.length === 3);
check('all denied', denied.every(d => d.status === 'denied'));
check('all by user-kill-all', denied.every(d => d.resolvedBy === 'user-kill-all'));
check('0 pending after deny-all', getPendingInterventions().length === 0);
check('3 resolved', getResolvedInterventions().length === 3);

// ════════════════════════════════════════════
console.log('\n══ 4. STATS ══');
// ════════════════════════════════════════════

const stats = getInterventionStats();
check('stats pending = 0', stats.pending === 0);
check('stats totalResolved = 3', stats.totalResolved === 3);
check('stats denied = 0 (user-kill-all not counted as user-denied)', stats.denied === 0);
check('stats expired = 0', stats.expired === 0);

// ════════════════════════════════════════════
console.log('\n══ 5. GET BY ID ══');
// ════════════════════════════════════════════

_resetForTesting();

const int5 = createIntervention({
  sessionId: 's5', rule: 'scope_blocked', severity: 'danger',
  message: 'blocked', actionType: 'file', actionTarget: '/x', provider: 'p',
});

check('get pending by id', getIntervention(int5.id)?.status === 'pending');
resolveIntervention(int5.id, 'denied');
check('get resolved by id', getIntervention(int5.id)?.status === 'denied');
check('get unknown returns null', getIntervention('nonexistent') === null);

// ════════════════════════════════════════════
console.log('\n══ 6. AUTO-DENY TIMEOUT ══');
// ════════════════════════════════════════════

_resetForTesting();
setAutoDenyTimeout(500); // 500ms for testing

const int6 = createIntervention({
  sessionId: 's6', rule: 'command_blocked', severity: 'danger',
  message: 'dangerous', actionType: 'command', actionTarget: 'rm -rf', provider: 'p',
});

check('pending before timeout', getPendingInterventions().length === 1);

// Wait for auto-deny
await new Promise(r => setTimeout(r, 800));

check('auto-denied after timeout', getPendingInterventions().length === 0);
const autoDenied = getIntervention(int6.id);
check('status is denied', autoDenied?.status === 'denied');
check('resolvedBy auto-timeout', autoDenied?.resolvedBy === 'auto-timeout');

setAutoDenyTimeout(30000); // reset

// ════════════════════════════════════════════
console.log('\n══ 7. waitForResolution ══');
// ════════════════════════════════════════════

_resetForTesting();

const int7 = createIntervention({
  sessionId: 's7', rule: 'scope_blocked', severity: 'danger',
  message: 'wait test', actionType: 'file', actionTarget: '/z', provider: 'p',
});

// Resolve after a delay
setTimeout(() => resolveIntervention(int7.id, 'approved', 'user'), 100);
const waited = await waitForResolution(int7.id, 5000);
check('waitForResolution resolves', waited.status === 'approved');
check('waited resolvedBy user', waited.resolvedBy === 'user');

// ════════════════════════════════════════════
console.log('\n══ 8. MULTIPLE INTERVENTIONS ══');
// ════════════════════════════════════════════

_resetForTesting();

const a = createIntervention({ sessionId: 's8', rule: 'scope_blocked', severity: 'danger', message: 'a', actionType: 'file', actionTarget: '/a', provider: 'p' });
const b = createIntervention({ sessionId: 's8', rule: 'command_blocked', severity: 'danger', message: 'b', actionType: 'command', actionTarget: 'rm', provider: 'p' });
const c = createIntervention({ sessionId: 's9', rule: 'network_blocked', severity: 'danger', message: 'c', actionType: 'network', actionTarget: 'evil.com', provider: 'q' });

check('3 pending', getPendingInterventions().length === 3);
resolveIntervention(a.id, 'approved');
check('2 pending after 1 resolved', getPendingInterventions().length === 2);
resolveIntervention(b.id, 'denied');
check('1 pending', getPendingInterventions().length === 1);
check('all includes both pending and resolved', getAllInterventions().length === 3);

// ════════════════════════════════════════════
console.log('\n══ 9. API ROUTES ══');
// ════════════════════════════════════════════

_resetForTesting();

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
    check(name, fn(res, data), `status=${res.status} body=${JSON.stringify(data).substring(0,100)}`);
  }
  return data;
}

// Create interventions directly for API testing
const api1 = createIntervention({ sessionId: 'api-s1', rule: 'command_blocked', severity: 'danger', message: 'rm -rf /', actionType: 'command', actionTarget: 'rm -rf /', provider: 'copilot' });
const api2 = createIntervention({ sessionId: 'api-s1', rule: 'scope_blocked', severity: 'danger', message: '.env access', actionType: 'file', actionTarget: '.env', provider: 'copilot' });

await apiCheck('GET', '/api/interventions?status=pending', null, [
  ['GET pending 200', (r) => r.status === 200],
  ['2 pending interventions', (_, d) => d.length === 2],
]);

await apiCheck('GET', '/api/interventions/stats', null, [
  ['GET stats 200', (r) => r.status === 200],
  ['stats pending=2', (_, d) => d.pending === 2],
]);

await apiCheck('GET', `/api/interventions/${api1.id}`, null, [
  ['GET single 200', (r) => r.status === 200],
  ['single is pending', (_, d) => d.status === 'pending'],
]);

await apiCheck('POST', `/api/interventions/${api1.id}/deny`, null, [
  ['POST deny 200', (r) => r.status === 200],
  ['denied status', (_, d) => d.status === 'denied'],
  ['denied by user', (_, d) => d.resolvedBy === 'user'],
]);

await apiCheck('POST', `/api/interventions/${api2.id}/approve`, null, [
  ['POST approve 200', (r) => r.status === 200],
  ['approved status', (_, d) => d.status === 'approved'],
]);

await apiCheck('GET', '/api/interventions?status=resolved', null, [
  ['GET resolved 200', (r) => r.status === 200],
  ['2 resolved', (_, d) => d.length === 2],
]);

// Deny-all with new pending
const api3 = createIntervention({ sessionId: 'api-s2', rule: 'network_blocked', severity: 'danger', message: 'evil.com', actionType: 'network', actionTarget: 'evil.com', provider: 'claude' });

await apiCheck('POST', '/api/interventions/deny-all', null, [
  ['POST deny-all 200', (r) => r.status === 200],
  ['denied 1', (_, d) => d.denied === 1],
]);

// 404 for resolved intervention
await apiCheck('POST', `/api/interventions/${api1.id}/approve`, null, [
  ['already resolved = 404', (r) => r.status === 404],
]);

// Settings
await apiCheck('GET', '/api/interventions/settings', null, [
  ['GET settings 200', (r) => r.status === 200],
  ['has autoDenyTimeoutMs', (_, d) => typeof d.autoDenyTimeoutMs === 'number'],
]);

await apiCheck('PUT', '/api/interventions/settings', { autoDenyTimeoutMs: 60000 }, [
  ['PUT settings 200', (r) => r.status === 200],
  ['timeout updated', (_, d) => d.autoDenyTimeoutMs === 60000],
]);

await apiCheck('PUT', '/api/interventions/settings', { autoDenyTimeoutMs: 100 }, [
  ['too-short rejected', (r) => r.status === 400],
]);

server.close();

// Cleanup
try { fs.unlinkSync(TEST_DB); } catch {}
try { fs.unlinkSync(TEST_DB + '-wal'); } catch {}
try { fs.unlinkSync(TEST_DB + '-shm'); } catch {}

// ════════════════════════════════════════════
console.log('\n══════════════════════════════════════════════════');
console.log(`  INTERVENTIONS: ${pass} passed, ${fail} failed`);
console.log('══════════════════════════════════════════════════');
if (fail > 0) process.exit(1);
