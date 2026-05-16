/**
 * Verification tests for the VISION.md features:
 * - Guardrails (scope locks, token caps, blocked commands, network allowlist)
 * - Trust scoring (per-provider, grades, decay/recovery)
 * - Compliance (hash chain, evidence reports, signed exports)
 * - Community rule packs (supply-chain, credentials, ci-cd)
 * - Branch/PR linking
 * - IDE API endpoints
 */
import { initDb, upsertSession, insertEvent, insertGuardrailViolation, getGuardrailViolations, setSessionBranch, getSessionsByBranch, getBranchSummary, getActiveSessionStatus, getFileActivity } from '../dist/storage/db.js';
import { mergeConfig } from '../dist/config/index.js';
import { evaluateGuardrails, trackTokenUsage, getSessionTokenUsage, GUARDRAILS_DEFAULTS } from '../dist/guardrails/index.js';
import { updateTrustScore, getTrustScore, getAllTrustScores, getProviderComparison } from '../dist/trust/index.js';
import { appendToChain, verifyChain, initHashChain, generateEvidenceReport, exportSignedSession } from '../dist/compliance/index.js';
import { evaluatePackRules, getAvailablePacks, loadPackFromFile } from '../dist/rules/packs.js';
import { createDashboardServer } from '../dist/dashboard/server.js';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TEST_DB = path.join(__dirname, '.vision-test.db');
try { fs.unlinkSync(TEST_DB); } catch {}
try { fs.unlinkSync(TEST_DB + '-wal'); } catch {}
try { fs.unlinkSync(TEST_DB + '-shm'); } catch {}

let pass = 0, fail = 0;
function check(name, condition, detail) {
  if (condition) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}${detail ? ' — ' + detail : ''}`); }
}

initDb(TEST_DB);
initHashChain();

// ════════════════════════════════════════════
console.log('\n══ 1. GUARDRAILS — Scope Locks ══');
// ════════════════════════════════════════════

const grConfig = { ...GUARDRAILS_DEFAULTS, enabled: true, mode: 'block' };

const v1 = evaluateGuardrails({ event_type: 'file_write', file_paths: ['/home/user/.env.local'], command: null, summary: '', session_id: 's1', timestamp: '', agent_id: 'main', parent_agent_id: null, tool_name: null, risk_level: 'info', parameters: null, duration_ms: null, raw_log: '', source_tool: 'x' }, grConfig, 's1');
check('blocks .env file access', v1.length > 0);
check('scope_blocked rule', v1.some(v => v.rule === 'scope_blocked'));
check('blocked flag set', v1.some(v => v.blocked === true));
check('danger severity', v1.some(v => v.severity === 'danger'));

const v2 = evaluateGuardrails({ event_type: 'file_write', file_paths: ['/src/app.ts'], command: null, summary: '', session_id: 's1', timestamp: '', agent_id: 'main', parent_agent_id: null, tool_name: null, risk_level: 'info', parameters: null, duration_ms: null, raw_log: '', source_tool: 'x' }, grConfig, 's1');
check('allows normal file write', v2.length === 0);

// With scope allow patterns
const grAllowOnly = { ...grConfig, scopeAllowPatterns: ['src/**'] };
const v3 = evaluateGuardrails({ event_type: 'file_write', file_paths: ['config/db.ts'], command: null, summary: '', session_id: 's1', timestamp: '', agent_id: 'main', parent_agent_id: null, tool_name: null, risk_level: 'info', parameters: null, duration_ms: null, raw_log: '', source_tool: 'x' }, grAllowOnly, 's1');
check('blocks files outside allow scope', v3.length > 0);
check('scope_outside rule', v3.some(v => v.rule === 'scope_outside'));

// ════════════════════════════════════════════
console.log('\n══ 2. GUARDRAILS — Blocked Commands ══');
// ════════════════════════════════════════════

const v4 = evaluateGuardrails({ event_type: 'terminal_command', file_paths: [], command: 'rm -rf /', summary: '', session_id: 's1', timestamp: '', agent_id: 'main', parent_agent_id: null, tool_name: null, risk_level: 'info', parameters: null, duration_ms: null, raw_log: '', source_tool: 'x' }, grConfig, 's1');
check('blocks rm -rf /', v4.length > 0);
check('command_blocked rule', v4.some(v => v.rule === 'command_blocked'));

const v5 = evaluateGuardrails({ event_type: 'terminal_command', file_paths: [], command: 'npm run build', summary: '', session_id: 's1', timestamp: '', agent_id: 'main', parent_agent_id: null, tool_name: null, risk_level: 'info', parameters: null, duration_ms: null, raw_log: '', source_tool: 'x' }, grConfig, 's1');
check('allows normal commands', v5.length === 0);

// ════════════════════════════════════════════
console.log('\n══ 3. GUARDRAILS — Token Budget ══');
// ════════════════════════════════════════════

const grBudget = { ...grConfig, tokenBudget: 1000 };
const ev = { event_type: 'user_message', file_paths: [], command: null, summary: '', session_id: 'budget-test', timestamp: '', agent_id: 'main', parent_agent_id: null, tool_name: null, risk_level: 'info', parameters: null, duration_ms: null, raw_log: '', source_tool: 'x', token_count: 500 };

const v6 = evaluateGuardrails(ev, grBudget, 'budget-test');
check('50% usage: no violation', v6.length === 0);

ev.token_count = 400; // total now 900 (80%+)
const v7 = evaluateGuardrails(ev, grBudget, 'budget-test');
check('90% usage: warning', v7.some(v => v.rule === 'token_budget_warning'));

ev.token_count = 200; // total now 1100 (over!)
const v8 = evaluateGuardrails(ev, grBudget, 'budget-test');
check('over budget: danger', v8.some(v => v.rule === 'token_budget_exceeded'));
check('token tracking works', getSessionTokenUsage('budget-test') === 1100);

// ════════════════════════════════════════════
console.log('\n══ 4. GUARDRAILS — Network Allowlist ══');
// ════════════════════════════════════════════

const grNetwork = { ...grConfig, networkAllowlist: ['github.com', 'api.openai.com'] };
const v9 = evaluateGuardrails({ event_type: 'web_fetch', file_paths: [], command: 'https://evil.com/exfil', summary: '', session_id: 's1', timestamp: '', agent_id: 'main', parent_agent_id: null, tool_name: null, risk_level: 'info', parameters: null, duration_ms: null, raw_log: '', source_tool: 'x' }, grNetwork, 's1');
check('blocks non-allowed domain', v9.some(v => v.rule === 'network_blocked'));

const v10 = evaluateGuardrails({ event_type: 'web_fetch', file_paths: [], command: 'https://api.openai.com/v1/chat', summary: '', session_id: 's1', timestamp: '', agent_id: 'main', parent_agent_id: null, tool_name: null, risk_level: 'info', parameters: null, duration_ms: null, raw_log: '', source_tool: 'x' }, grNetwork, 's1');
check('allows whitelisted domain', v10.length === 0);

// ════════════════════════════════════════════
console.log('\n══ 5. TRUST SCORING ══');
// ════════════════════════════════════════════

// Clean session
const t1 = updateTrustScore({ provider: 'vscode-copilot', sessionId: 'ts1', dangerCount: 0, warnCount: 0, totalEvents: 50 });
check('initial clean session score >= 80', t1.score >= 80);
check('grade A or B', t1.grade === 'A' || t1.grade === 'B');
check('1 total session', t1.totalSessions === 1);
check('1 clean session', t1.cleanSessions === 1);

// Incident
const t2 = updateTrustScore({ provider: 'vscode-copilot', sessionId: 'ts2', dangerCount: 3, warnCount: 5, totalEvents: 100 });
check('score drops after incident', t2.score < t1.score);
check('incidents = 1', t2.incidents === 1);

// Major incident
const t3 = updateTrustScore({ provider: 'vscode-copilot', sessionId: 'ts3', dangerCount: 8, warnCount: 10, totalEvents: 200 });
check('score drops significantly for major incident', t3.score < t2.score);

// Different provider stays clean
const t4 = updateTrustScore({ provider: 'claude-code', sessionId: 'ts4', dangerCount: 0, warnCount: 1, totalEvents: 30 });
check('different provider independent', t4.score >= 80);

// Get all scores
const all = getAllTrustScores();
check('2 providers tracked', all.length === 2);

// Comparison
const comp = getProviderComparison();
check('comparison returns entries', comp.length === 2);
check('comparison has cleanRate', comp[0].cleanRate !== undefined);

// ════════════════════════════════════════════
console.log('\n══ 6. COMPLIANCE — Hash Chain ══');
// ════════════════════════════════════════════

upsertSession({ id: 'comp-s1', workspace: '/w', project_name: 'proj', started_at: '2025-06-01T00:00:00Z', ended_at: null, total_events: 3, danger_count: 0, warn_count: 0, source_tool: 'x' });

const e1 = { id: 1, session_id: 'comp-s1', timestamp: '2025-06-01T00:01:00Z', event_type: 'file_write', risk_level: 'info', summary: 'edit app.ts', agent_id: 'main', parent_agent_id: null, tool_name: null, file_paths: ['/app.ts'], command: null, parameters: null, duration_ms: null, raw_log: '', source_tool: 'x' };
insertEvent(e1);
const h1 = appendToChain(e1);
check('hash chain entry 1 created', typeof h1 === 'string' && h1.length === 64);

const e2 = { id: 2, session_id: 'comp-s1', timestamp: '2025-06-01T00:02:00Z', event_type: 'terminal_command', risk_level: 'watch', summary: 'npm test', agent_id: 'main', parent_agent_id: null, tool_name: null, file_paths: [], command: 'npm test', parameters: null, duration_ms: null, raw_log: '', source_tool: 'x' };
insertEvent(e2);
const h2 = appendToChain(e2);
check('hash chain entry 2 different', h2 !== h1);

const e3 = { id: 3, session_id: 'comp-s1', timestamp: '2025-06-01T00:03:00Z', event_type: 'git_push', risk_level: 'danger', summary: 'push to main', agent_id: 'main', parent_agent_id: null, tool_name: null, file_paths: [], command: 'git push origin main', parameters: null, duration_ms: null, raw_log: '', source_tool: 'x' };
insertEvent(e3);
appendToChain(e3);

const verification = verifyChain();
check('chain is valid', verification.valid === true);
check('chain has 3 entries', verification.totalEntries === 3);

// ════════════════════════════════════════════
console.log('\n══ 7. COMPLIANCE — Evidence Report ══');
// ════════════════════════════════════════════

const report = generateEvidenceReport('2025-06-01T00:00:00Z', '2025-06-02T00:00:00Z');
check('report has generatedAt', !!report.generatedAt);
check('report period correct', report.period.start === '2025-06-01T00:00:00Z');
check('report sessions = 1', report.summary.totalSessions === 1);
check('report events = 3', report.summary.totalEvents === 3);
check('report danger events = 1', report.summary.dangerEvents === 1);
check('report chain integrity valid', report.chainIntegrity.valid === true);
check('report high risk events = 1', report.highRiskEvents.length === 1);

// Signed session export
const signed = exportSignedSession('comp-s1');
check('signed export has session', !!signed.session);
check('signed export has events', signed.events.length === 3);
check('signed export has signature', signed.signatureHash.length === 64);

// ════════════════════════════════════════════
console.log('\n══ 8. COMMUNITY RULE PACKS ══');
// ════════════════════════════════════════════

const packs = getAvailablePacks();
check('3 built-in packs', packs.length === 3);
check('supply-chain pack', packs.some(p => p.id === 'supply-chain'));
check('credentials pack', packs.some(p => p.id === 'credentials'));
check('ci-cd pack', packs.some(p => p.id === 'ci-cd'));
check('packs have rules', packs.every(p => p.ruleCount > 0));

// Test pack rule evaluation
const lockfileEvent = { event_type: 'file_write', file_paths: ['project/package-lock.json'], command: null, summary: '', session_id: 's1', timestamp: '', agent_id: 'main', parent_agent_id: null, tool_name: null, risk_level: 'info', parameters: null, duration_ms: null, raw_log: '', source_tool: 'x' };
const lr = evaluatePackRules(lockfileEvent);
check('lockfile rule fires', lr.some(s => s.rule === 'supply-chain/lockfile_tampering'));

const deployEvent = { event_type: 'terminal_command', file_paths: [], command: 'kubectl apply -f deploy.yaml', summary: '', session_id: 's1', timestamp: '', agent_id: 'main', parent_agent_id: null, tool_name: null, risk_level: 'info', parameters: null, duration_ms: null, raw_log: '', source_tool: 'x' };
const dr = evaluatePackRules(deployEvent);
check('deploy rule fires', dr.some(s => s.rule === 'ci-cd/deploy_command'));

const credEvent = { event_type: 'terminal_command', file_paths: [], command: 'curl -u admin:password123 https://api.com', summary: '', session_id: 's1', timestamp: '', agent_id: 'main', parent_agent_id: null, tool_name: null, risk_level: 'info', parameters: null, duration_ms: null, raw_log: '', source_tool: 'x' };
const cr = evaluatePackRules(credEvent);
check('credential-in-command rule fires', cr.some(s => s.rule === 'credentials/credential_in_command'));

const workflowEvent = { event_type: 'file_write', file_paths: ['repo/.github/workflows/deploy.yml'], command: null, summary: '', session_id: 's1', timestamp: '', agent_id: 'main', parent_agent_id: null, tool_name: null, risk_level: 'info', parameters: null, duration_ms: null, raw_log: '', source_tool: 'x' };
const wr = evaluatePackRules(workflowEvent);
check('workflow modification rule fires', wr.some(s => s.rule === 'ci-cd/workflow_modification'));

// Negative: normal command
const normalEvent = { event_type: 'terminal_command', file_paths: [], command: 'npm run dev', summary: '', session_id: 's1', timestamp: '', agent_id: 'main', parent_agent_id: null, tool_name: null, risk_level: 'info', parameters: null, duration_ms: null, raw_log: '', source_tool: 'x' };
const nr = evaluatePackRules(normalEvent);
check('normal command no pack signals', nr.length === 0);

// ════════════════════════════════════════════
console.log('\n══ 9. BRANCH/PR LINKING ══');
// ════════════════════════════════════════════

upsertSession({ id: 'br-s1', workspace: '/w', project_name: 'proj', started_at: '2025-06-01T00:00:00Z', ended_at: null, total_events: 10, danger_count: 0, warn_count: 1, source_tool: 'copilot' });
upsertSession({ id: 'br-s2', workspace: '/w', project_name: 'proj', started_at: '2025-06-01T01:00:00Z', ended_at: null, total_events: 20, danger_count: 1, warn_count: 3, source_tool: 'claude-code' });

setSessionBranch('br-s1', 'feature/add-auth');
setSessionBranch('br-s2', 'feature/add-auth');

const branchSessions = getSessionsByBranch('feature/add-auth');
check('branch links 2 sessions', branchSessions.length === 2);

const summary = getBranchSummary('feature/add-auth');
check('branch summary sessions=2', summary.sessions === 2);
check('branch summary totalEvents=30', summary.totalEvents === 30);
check('branch summary dangerCount=1', summary.dangerCount === 1);
check('branch summary 2 providers', summary.providers.length === 2);

const emptyBranch = getSessionsByBranch('nonexistent');
check('unknown branch returns empty', emptyBranch.length === 0);

// ════════════════════════════════════════════
console.log('\n══ 10. IDE API ══');
// ════════════════════════════════════════════

// Insert a recent event for file activity
insertEvent({ session_id: 'br-s1', timestamp: new Date().toISOString(), event_type: 'file_write', risk_level: 'info', summary: 'edit auth.ts', agent_id: 'main', parent_agent_id: null, tool_name: null, file_paths: ['/src/auth.ts'], command: null, parameters: null, duration_ms: null, raw_log: '', source_tool: 'copilot' });

const activity = getFileActivity('/src/auth.ts');
check('file activity returns events', activity.length > 0);
check('file activity has provider', activity[0].provider !== undefined);

const status = getActiveSessionStatus();
check('status returns grade', typeof status.grade === 'string');
check('status returns provider', typeof status.provider === 'string');

// ════════════════════════════════════════════
console.log('\n══ 11. API ROUTES — New Endpoints ══');
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

await apiCheck('GET', '/api/trust', null, [
  ['GET /api/trust 200', (r) => r.status === 200],
  ['trust is array', (_, d) => Array.isArray(d)],
  ['trust has entries', (_, d) => d.length >= 2],
]);

await apiCheck('GET', '/api/trust/vscode-copilot', null, [
  ['GET /api/trust/:provider 200', (r) => r.status === 200],
  ['has score field', (_, d) => typeof d.score === 'number'],
  ['has grade field', (_, d) => typeof d.grade === 'string'],
]);

await apiCheck('GET', '/api/compliance/chain/verify', null, [
  ['GET /api/compliance/chain/verify 200', (r) => r.status === 200],
  ['valid field', (_, d) => typeof d.valid === 'boolean'],
  ['totalEntries field', (_, d) => typeof d.totalEntries === 'number'],
]);

await apiCheck('GET', '/api/compliance/report?start=2025-06-01T00:00:00&end=2025-06-02T00:00:00', null, [
  ['GET /api/compliance/report 200', (r) => r.status === 200],
  ['report has summary', (_, d) => d.summary !== undefined],
  ['report has chainIntegrity', (_, d) => d.chainIntegrity !== undefined],
]);

await apiCheck('GET', '/api/compliance/session/comp-s1/signed', null, [
  ['GET signed session 200', (r) => r.status === 200],
  ['has signatureHash', (_, d) => d.signatureHash && d.signatureHash.length === 64],
]);

await apiCheck('GET', '/api/guardrails/violations', null, [
  ['GET /api/guardrails/violations 200', (r) => r.status === 200],
  ['violations is array', (_, d) => Array.isArray(d)],
]);

await apiCheck('GET', '/api/guardrails/config', null, [
  ['GET /api/guardrails/config 200', (r) => r.status === 200],
  ['config has enabled', (_, d) => typeof d.enabled === 'boolean'],
]);

await apiCheck('GET', '/api/rules/packs', null, [
  ['GET /api/rules/packs 200', (r) => r.status === 200],
  ['3 packs available', (_, d) => d.length === 3],
]);

await apiCheck('GET', '/api/branches/feature%2Fadd-auth/summary', null, [
  ['GET branch summary 200', (r) => r.status === 200],
  ['branch has sessions', (_, d) => d.sessions === 2],
]);

await apiCheck('GET', '/api/ide/status', null, [
  ['GET /api/ide/status 200', (r) => r.status === 200],
  ['status has grade', (_, d) => typeof d.grade === 'string'],
]);

await apiCheck('GET', '/api/ide/file-activity?path=/src/auth.ts', null, [
  ['GET /api/ide/file-activity 200', (r) => r.status === 200],
  ['file activity is array', (_, d) => Array.isArray(d)],
]);

await apiCheck('GET', '/api/ide/session-summary', null, [
  ['GET /api/ide/session-summary 200', (r) => r.status === 200],
]);

await apiCheck('GET', '/api/trust/compare/all', null, [
  ['GET trust compare 200', (r) => r.status === 200],
  ['comparison is array', (_, d) => Array.isArray(d)],
]);

server.close();

// Cleanup
try { fs.unlinkSync(TEST_DB); } catch {}
try { fs.unlinkSync(TEST_DB + '-wal'); } catch {}
try { fs.unlinkSync(TEST_DB + '-shm'); } catch {}

// ════════════════════════════════════════════
console.log('\n══════════════════════════════════════════════════');
console.log(`  VISION FEATURES: ${pass} passed, ${fail} failed`);
console.log('══════════════════════════════════════════════════');
if (fail > 0) process.exit(1);
