/**
 * Command Queue — tests for the persistent blocking, editing, and re-release system.
 */

import { initDb, getDb } from '../dist/storage/db.js';
import { mergeConfig } from '../dist/config/index.js';
import { createDashboardServer } from '../dist/dashboard/server.js';
import {
  queueBlockedCommand, getBlockedCommands, getResolvedCommands,
  getRecentCommands, getSessionCommands, getCommandById,
  approveCommand, denyCommand, modifyAndRelease,
  denyAllBlocked, getCommandQueueStats, getOrphanedBlocked,
  expireStaleCommands,
} from '../dist/commands/index.js';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TEST_DB = path.join(__dirname, '.commands-test.db');
try { fs.unlinkSync(TEST_DB); } catch {}
try { fs.unlinkSync(TEST_DB + '-wal'); } catch {}

let passed = 0, failed = 0;
function assert(cond, msg) {
  if (cond) { passed++; process.stdout.write(`  \x1b[32m✓\x1b[0m ${msg}\n`); }
  else { failed++; process.stdout.write(`  \x1b[31m✗\x1b[0m ${msg}\n`); }
}

// ── Init DB ──
initDb(TEST_DB);

// ── SECTION 1: Core CRUD ──
console.log('\n══ 1. QUEUE & RETRIEVE ══');

const q1 = queueBlockedCommand({
  session_id: 'sess-1', event_id: 100, provider: 'copilot',
  project_name: 'my-app', action_type: 'command',
  original_command: 'rm -rf /', rule: 'command_blocked',
  severity: 'danger', message: 'Matches blocked pattern: rm -rf /',
});
assert(q1.id > 0, 'command queued with id');
assert(q1.status === 'blocked', 'status is blocked');
assert(q1.original_command === 'rm -rf /', 'original_command stored');
assert(q1.session_id === 'sess-1', 'session_id stored');
assert(q1.provider === 'copilot', 'provider stored');
assert(q1.rule === 'command_blocked', 'rule stored');
assert(q1.blocked_at != null, 'blocked_at set');
assert(q1.resolved_at === null, 'resolved_at null');
assert(q1.modified_command === null, 'modified_command null');

const fetched = getCommandById(q1.id);
assert(fetched !== null, 'getCommandById returns it');
assert(fetched.original_command === 'rm -rf /', 'fetched command matches');

const blocked = getBlockedCommands();
assert(blocked.length === 1, '1 blocked command');
assert(blocked[0].id === q1.id, 'correct id');

// ── SECTION 2: Approve ──
console.log('\n══ 2. APPROVE ══');

const approved = approveCommand(q1.id, 'user', 'Looks safe actually');
assert(approved !== null, 'approveCommand returns entry');
assert(approved.status === 'approved', 'status is approved');
assert(approved.resolved_by === 'user', 'resolved_by = user');
assert(approved.resolved_at !== null, 'resolved_at set');
assert(approved.notes === 'Looks safe actually', 'notes stored');

const blocked2 = getBlockedCommands();
assert(blocked2.length === 0, '0 blocked after approve');

// Double approve should fail
assert(approveCommand(q1.id) === null, 'double approve returns null');

// ── SECTION 3: Deny ──
console.log('\n══ 3. DENY ══');

const q2 = queueBlockedCommand({
  session_id: 'sess-1', event_id: 101, provider: 'claude',
  project_name: 'my-app', action_type: 'file',
  original_command: '/etc/passwd', rule: 'scope_blocked',
  severity: 'danger', message: 'Blocked file path',
});

const denied = denyCommand(q2.id, 'user', 'Nope');
assert(denied !== null, 'denyCommand returns entry');
assert(denied.status === 'denied', 'status is denied');
assert(denied.resolved_by === 'user', 'resolved_by = user');
assert(denied.notes === 'Nope', 'denial notes stored');

// ── SECTION 4: Modify & Release ──
console.log('\n══ 4. MODIFY & RELEASE ══');

const q3 = queueBlockedCommand({
  session_id: 'sess-2', event_id: 102, provider: 'copilot',
  project_name: 'my-app', action_type: 'command',
  original_command: 'rm -rf /tmp/build', rule: 'command_blocked',
  severity: 'danger', message: 'Matches blocked pattern',
});

const modified = modifyAndRelease(q3.id, 'rm -rf ./build', 'user', 'Scoped to project dir');
assert(modified !== null, 'modifyAndRelease returns entry');
assert(modified.status === 'modified', 'status is modified');
assert(modified.original_command === 'rm -rf /tmp/build', 'original preserved');
assert(modified.modified_command === 'rm -rf ./build', 'modified_command stored');
assert(modified.notes === 'Scoped to project dir', 'modification notes stored');
assert(modified.resolved_at !== null, 'resolved_at set');

// Can't modify already resolved
assert(modifyAndRelease(q3.id, 'echo hello') === null, 'double modify returns null');

// ── SECTION 5: Deny All ──
console.log('\n══ 5. DENY ALL ══');

const q4 = queueBlockedCommand({ session_id: 'sess-3', event_id: 200, provider: 'gemini', project_name: 'p', action_type: 'command', original_command: 'cmd1', rule: 'r', severity: 'danger', message: 'm' });
const q5 = queueBlockedCommand({ session_id: 'sess-3', event_id: 201, provider: 'gemini', project_name: 'p', action_type: 'command', original_command: 'cmd2', rule: 'r', severity: 'danger', message: 'm' });
const q6 = queueBlockedCommand({ session_id: 'sess-3', event_id: 202, provider: 'gemini', project_name: 'p', action_type: 'command', original_command: 'cmd3', rule: 'r', severity: 'danger', message: 'm' });

assert(getBlockedCommands().length === 3, '3 blocked before deny-all');
const denyCount = denyAllBlocked();
assert(denyCount === 3, 'denyAllBlocked returns 3');
assert(getBlockedCommands().length === 0, '0 blocked after deny-all');

// ── SECTION 6: Stats ──
console.log('\n══ 6. STATS ══');

const stats = getCommandQueueStats();
assert(stats.total === 6, 'total = 6');
assert(stats.approved === 1, 'approved = 1');
assert(stats.denied >= 4, 'denied >= 4');
assert(stats.modified === 1, 'modified = 1');
assert(stats.blocked === 0, 'blocked = 0');
assert(typeof stats.avgResolutionMs === 'number', 'avgResolutionMs is number');

// ── SECTION 7: Session & Recent Queries ──
console.log('\n══ 7. QUERIES ══');

const sess1Cmds = getSessionCommands('sess-1');
assert(sess1Cmds.length === 2, 'sess-1 has 2 commands');

const sess2Cmds = getSessionCommands('sess-2');
assert(sess2Cmds.length === 1, 'sess-2 has 1 command');

const recent = getRecentCommands(100);
assert(recent.length === 6, 'all 6 in recent');

const resolved = getResolvedCommands(50);
assert(resolved.length === 6, '6 resolved');

// ── SECTION 8: Expiry ──
console.log('\n══ 8. EXPIRY ══');

// Create a command and backdate it
const q7 = queueBlockedCommand({ session_id: 'sess-old', event_id: 300, provider: 'copilot', project_name: 'p', action_type: 'command', original_command: 'old cmd', rule: 'r', severity: 'warn', message: 'm' });
// Backdate manually
getDb().prepare('UPDATE command_queue SET blocked_at = ? WHERE id = ?')
  .run(new Date(Date.now() - 7200_000).toISOString(), q7.id);

assert(getBlockedCommands().length === 1, '1 blocked (stale)');
const expired = expireStaleCommands(3600_000); // 1 hour
assert(expired === 1, '1 expired');
assert(getBlockedCommands().length === 0, '0 blocked after expiry');

const expiredCmd = getCommandById(q7.id);
assert(expiredCmd.status === 'expired', 'status is expired');
assert(expiredCmd.resolved_by === 'auto-expire', 'resolved_by is auto-expire');

// ── SECTION 9: Orphaned ──
console.log('\n══ 9. ORPHANED ══');

const q8 = queueBlockedCommand({ session_id: 'sess-crash', event_id: 400, provider: 'copilot', project_name: 'p', action_type: 'command', original_command: 'orphan cmd', rule: 'r', severity: 'danger', message: 'm' });

const orphaned = getOrphanedBlocked();
assert(orphaned.length === 1, '1 orphaned');
assert(orphaned[0].original_command === 'orphan cmd', 'orphan command correct');

// Clean up
denyAllBlocked();

// ── SECTION 10: API Routes ──
console.log('\n══ 10. API ROUTES ══');

// Seed data for API tests
const q9 = queueBlockedCommand({ session_id: 'api-sess', event_id: 500, provider: 'copilot', project_name: 'api-test', action_type: 'command', original_command: 'dangerous cmd', rule: 'command_blocked', severity: 'danger', message: 'test' });
const q10 = queueBlockedCommand({ session_id: 'api-sess', event_id: 501, provider: 'copilot', project_name: 'api-test', action_type: 'file', original_command: '.env', rule: 'scope_blocked', severity: 'danger', message: 'test2' });

const app = createDashboardServer(mergeConfig({}));
const server = await new Promise(resolve => {
  const s = http.createServer(app).listen(0, '127.0.0.1', () => resolve(s));
});
const port = server.address().port;
const base = `http://127.0.0.1:${port}`;

async function apiGet(path) {
  const r = await fetch(base + path);
  return { status: r.status, data: await r.json() };
}
async function apiPost(path, body) {
  const r = await fetch(base + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
  return { status: r.status, data: await r.json() };
}

try {
  // GET /api/commands/blocked
  const { status: s1, data: d1 } = await apiGet('/api/commands/blocked');
  assert(s1 === 200, 'GET /api/commands/blocked 200');
  assert(Array.isArray(d1), 'blocked is array');
  assert(d1.length === 2, '2 blocked');

  // GET /api/commands/stats
  const { data: stats2 } = await apiGet('/api/commands/stats');
  assert(stats2.blocked === 2, 'stats blocked = 2');
  assert(typeof stats2.total === 'number', 'stats has total');

  // GET /api/commands
  const { data: all } = await apiGet('/api/commands?limit=5');
  assert(Array.isArray(all), 'all commands is array');

  // GET /api/commands/:id
  const { status: s3, data: single } = await apiGet(`/api/commands/${q9.id}`);
  assert(s3 === 200, 'GET single command 200');
  assert(single.original_command === 'dangerous cmd', 'single command correct');

  // GET /api/commands/999999
  const { status: s4 } = await apiGet('/api/commands/999999');
  assert(s4 === 404, 'unknown command 404');

  // POST /api/commands/:id/approve
  const { status: s5, data: d5 } = await apiPost(`/api/commands/${q9.id}/approve`, { notes: 'ok' });
  assert(s5 === 200, 'POST approve 200');
  assert(d5.status === 'approved', 'approved status');
  assert(d5.notes === 'ok', 'approve notes');

  // POST /api/commands/:id/deny
  const { status: s6, data: d6 } = await apiPost(`/api/commands/${q10.id}/deny`);
  assert(s6 === 200, 'POST deny 200');
  assert(d6.status === 'denied', 'denied status');

  // Already resolved = 404
  const { status: s7 } = await apiPost(`/api/commands/${q9.id}/approve`);
  assert(s7 === 404, 'already resolved = 404');

  // POST modify
  const q11 = queueBlockedCommand({ session_id: 'api-sess', event_id: 502, provider: 'copilot', project_name: 'api-test', action_type: 'command', original_command: 'rm -rf stuff', rule: 'command_blocked', severity: 'danger', message: 'test3' });
  const { status: s8, data: d8 } = await apiPost(`/api/commands/${q11.id}/modify`, { command: 'rm -rf ./build', notes: 'fixed' });
  assert(s8 === 200, 'POST modify 200');
  assert(d8.status === 'modified', 'modified status');
  assert(d8.modified_command === 'rm -rf ./build', 'modified_command set');
  assert(d8.notes === 'fixed', 'modify notes');

  // POST modify without command = 400
  const q12 = queueBlockedCommand({ session_id: 'api-sess', event_id: 503, provider: 'copilot', project_name: 'api-test', action_type: 'command', original_command: 'test', rule: 'r', severity: 'danger', message: 'm' });
  const { status: s9 } = await apiPost(`/api/commands/${q12.id}/modify`, {});
  assert(s9 === 400, 'POST modify without command = 400');

  // POST deny-all
  const q13 = queueBlockedCommand({ session_id: 'api-sess', event_id: 504, provider: 'copilot', project_name: 'api-test', action_type: 'command', original_command: 'c1', rule: 'r', severity: 'danger', message: 'm' });
  const q14 = queueBlockedCommand({ session_id: 'api-sess', event_id: 505, provider: 'copilot', project_name: 'api-test', action_type: 'command', original_command: 'c2', rule: 'r', severity: 'danger', message: 'm' });
  const { status: s10, data: d10 } = await apiPost('/api/commands/deny-all');
  assert(s10 === 200, 'POST deny-all 200');
  assert(d10.denied >= 2, 'deny-all count >= 2');

  // GET session commands
  const { data: sessCmds } = await apiGet('/api/sessions/api-sess/commands');
  assert(Array.isArray(sessCmds), 'session commands is array');
  assert(sessCmds.length >= 4, 'session has >= 4 commands');

  // GET resolved
  const { data: resolvedList } = await apiGet('/api/commands/resolved');
  assert(Array.isArray(resolvedList), 'resolved is array');

  // GET orphaned
  const { data: orphanedList } = await apiGet('/api/commands/orphaned');
  assert(Array.isArray(orphanedList), 'orphaned is array');

} finally {
  server.close();
}

// Cleanup test DB
try { fs.unlinkSync(TEST_DB); } catch {}
try { fs.unlinkSync(TEST_DB + '-wal'); } catch {}
try { fs.unlinkSync(TEST_DB + '-shm'); } catch {}

// ══ Results ══
console.log(`\n${'═'.repeat(50)}`);
console.log(`  COMMAND QUEUE: ${passed} passed, ${failed} failed`);
console.log('═'.repeat(50));
process.exit(failed > 0 ? 1 : 0);
