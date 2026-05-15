// AL Companion Tracker — Automated UI Test Suite
// Run with: node tests/ui-test.mjs
// Requires the server to be running at http://127.0.0.1:3847

const BASE = 'http://127.0.0.1:3847';
let pass = 0, fail = 0, errors = [];

async function api(path) {
  const res = await fetch(BASE + path);
  return { status: res.status, data: await res.json().catch(() => null), ok: res.ok };
}

async function html(path) {
  const res = await fetch(BASE + (path || '/'));
  return { status: res.status, text: await res.text(), ok: res.ok };
}

function assert(name, condition, detail) {
  if (condition) {
    pass++;
    console.log(`  ✅ ${name}`);
  } else {
    fail++;
    const msg = `  ❌ ${name}${detail ? ' — ' + detail : ''}`;
    errors.push(msg);
    console.log(msg);
  }
}

// ══════════════════════════════════════════════════════
// 1. FRONTEND SERVING
// ══════════════════════════════════════════════════════
console.log('\n═══ 1. FRONTEND SERVING ═══');

const page = await html('/');
assert('Index HTML serves (200)', page.status === 200);
assert('HTML has correct title', page.text.includes('<title>AL Companion Tracker</title>'));
assert('HTML has phone-frame layout', page.text.includes('class="phone-frame"'));
assert('HTML has bottom nav', page.text.includes('class="bottom-nav"'));
assert('HTML has 6 nav buttons', (page.text.match(/<button[^>]*data-page="/g) || []).length === 6);
assert('HTML has Home page', page.text.includes('id="page-home"'));
assert('HTML has Sessions page', page.text.includes('id="page-sessions"'));
assert('HTML has Timeline page', page.text.includes('id="page-timeline"'));
assert('HTML has Security page', page.text.includes('id="page-security"'));
assert('HTML has Memory page', page.text.includes('id="page-memory"'));
assert('HTML has Projects page', page.text.includes('id="page-projects"'));
assert('HTML has status bar with clock', page.text.includes('id="clockDisplay"'));
assert('HTML has live pulse indicator', page.text.includes('live-pulse'));
assert('HTML has showPage function', page.text.includes('function showPage('));
assert('HTML has loadHome function', page.text.includes('function loadHome('));
assert('HTML has loadSessions function', page.text.includes('function loadSessions('));
assert('HTML has loadTimeline function', page.text.includes('function loadTimeline('));
assert('HTML has loadSecurity function', page.text.includes('function loadSecurity('));
assert('HTML has loadMemory function', page.text.includes('function loadMemory('));
assert('HTML has loadProjects function', page.text.includes('function loadProjects('));
assert('HTML has ackAlert function', page.text.includes('function ackAlert('));
assert('HTML has toggleRiskFilter function', page.text.includes('function toggleRiskFilter('));
assert('HTML has session search input', page.text.includes('id="sessionSearch"'));
assert('HTML has timeline search input', page.text.includes('id="timelineSearch"'));
assert('HTML has risk filter button', page.text.includes('id="riskFilterBtn"'));
assert('HTML has security badge', page.text.includes('id="securityBadge"'));
assert('SPA fallback works', (await html('/any/route')).text.includes('AL Companion Tracker'));

// Dark theme CSS
assert('CSS has dark theme variables', page.text.includes('--bg:') && page.text.includes('#0e1117'));
assert('CSS has 720px panel width', page.text.includes('width: 720px'));
assert('CSS has donut chart styles', page.text.includes('.donut'));
assert('CSS has timeline styles', page.text.includes('.tl-item'));
assert('CSS has skeleton loading', page.text.includes('.skeleton'));
assert('CSS has fadeIn animation', page.text.includes('@keyframes fadeIn'));

// ══════════════════════════════════════════════════════
// 2. HOME / STATS API
// ══════════════════════════════════════════════════════
console.log('\n═══ 2. HOME / STATS API ═══');

const stats = await api('/api/stats');
assert('Stats endpoint returns 200', stats.status === 200);
assert('Stats has today object', stats.data?.today != null);
assert('Stats today.totalEvents is number', typeof stats.data?.today?.totalEvents === 'number');
assert('Stats today.filesChanged is number', typeof stats.data?.today?.filesChanged === 'number');
assert('Stats today.commandsRun is number', typeof stats.data?.today?.commandsRun === 'number');
assert('Stats today.alertCount is number', typeof stats.data?.today?.alertCount === 'number');
assert('Stats today.unreviewedAlerts is number', typeof stats.data?.today?.unreviewedAlerts === 'number');
assert('Stats has riskDistribution array', Array.isArray(stats.data?.riskDistribution));
assert('Risk distribution has entries', stats.data?.riskDistribution?.length > 0, `got ${stats.data?.riskDistribution?.length}`);
assert('Risk entries have risk_level', stats.data?.riskDistribution?.[0]?.risk_level != null);
assert('Risk entries have count', typeof stats.data?.riskDistribution?.[0]?.count === 'number');
assert('Stats has dailyCounts array', Array.isArray(stats.data?.dailyCounts));
assert('Daily counts has 7 entries', stats.data?.dailyCounts?.length === 7, `got ${stats.data?.dailyCounts?.length}`);
assert('Daily count entry has date', stats.data?.dailyCounts?.[0]?.date != null);
assert('Daily count entry has count', typeof stats.data?.dailyCounts?.[0]?.count === 'number');

// Verify home page renders real data (non-zero)
assert('Events ingested (totalEvents > 0)', stats.data?.today?.totalEvents > 0, `got ${stats.data?.today?.totalEvents}`);

// ══════════════════════════════════════════════════════
// 3. SESSIONS API + LIST
// ══════════════════════════════════════════════════════
console.log('\n═══ 3. SESSIONS ═══');

const sessions = await api('/api/sessions');
assert('Sessions endpoint returns 200', sessions.status === 200);
assert('Sessions returns array', Array.isArray(sessions.data));
assert('Has sessions data', sessions.data?.length > 0, `got ${sessions.data?.length}`);

const s0 = sessions.data?.[0];
assert('Session has id', typeof s0?.id === 'string' && s0.id.length > 0);
assert('Session has project_name', typeof s0?.project_name === 'string');
assert('Session has started_at', typeof s0?.started_at === 'string');
assert('Session has total_events (number)', typeof s0?.total_events === 'number');
assert('Session has danger_count', typeof s0?.danger_count === 'number');
assert('Session has warn_count', typeof s0?.warn_count === 'number');

// Limit param
const limited = await api('/api/sessions?limit=3');
assert('Sessions limit param works', limited.data?.length <= 3);

// Session detail
const detail = await api(`/api/sessions/${s0.id}`);
assert('Session detail returns 200', detail.status === 200);
assert('Session detail has matching id', detail.data?.id === s0.id);
assert('Session detail has project_name', detail.data?.project_name === s0.project_name);

// 404 for missing session
const missing = await api('/api/sessions/nonexistent-id-12345');
assert('Missing session returns 404', missing.status === 404);

// Session search (frontend filter) — verify data supports it
const projectNames = sessions.data.map(s => s.project_name).filter(Boolean);
assert('Sessions have project names for search', projectNames.length > 0);
const uniqueProjects = [...new Set(projectNames)];
assert('Multiple projects for meaningful search', uniqueProjects.length > 1, `got ${uniqueProjects.length}: ${uniqueProjects.join(', ')}`);

// ══════════════════════════════════════════════════════
// 4. TIMELINE / EVENTS API
// ══════════════════════════════════════════════════════
console.log('\n═══ 4. TIMELINE / EVENTS ═══');

// Session events
const events = await api(`/api/sessions/${s0.id}/events?limit=20`);
assert('Session events returns 200', events.status === 200);
assert('Session events returns array', Array.isArray(events.data));
assert('Has events', events.data?.length > 0, `got ${events.data?.length}`);

const e0 = events.data?.[0];
assert('Event has session_id', e0?.session_id === s0.id);
assert('Event has timestamp', typeof e0?.timestamp === 'string');
assert('Event has event_type', typeof e0?.event_type === 'string');
assert('Event has risk_level', ['info', 'watch', 'warn', 'danger'].includes(e0?.risk_level));
assert('Event has summary', typeof e0?.summary === 'string' && e0.summary.length > 0);
assert('Event has file_paths array', Array.isArray(e0?.file_paths));

// Recent events (cross-session)
const recent = await api('/api/events/recent?limit=10');
assert('Recent events returns 200', recent.status === 200);
assert('Recent events returns array', Array.isArray(recent.data));
assert('Has recent events', recent.data?.length > 0);

// Live events
const liveTs = new Date(Date.now() - 300000).toISOString();
const live = await api(`/api/events/live?since=${liveTs}`);
assert('Live events returns 200', live.status === 200);
assert('Live events returns array', Array.isArray(live.data));

// Risk filter — verify we have multiple risk levels for filtering
const riskLevels = [...new Set(events.data?.map(e => e.risk_level) || [])];
assert('Events have risk levels for filter', riskLevels.length > 0, `levels: ${riskLevels.join(', ')}`);

// Verify event types cover the design features
const allEvents = await api(`/api/sessions/${s0.id}/events?limit=500`);
const eventTypes = [...new Set(allEvents.data?.map(e => e.event_type) || [])];
console.log(`    Event types found: ${eventTypes.join(', ')}`);

// Check for file operations (design: "file write, reads")
const hasFileOps = eventTypes.some(t => ['file_read', 'file_write', 'file_create'].includes(t));
assert('Tracks file operations (reads/writes)', hasFileOps, `types: ${eventTypes.join(', ')}`);

// Check for terminal commands (design: "commands")
const hasTerminal = eventTypes.some(t => ['terminal_command', 'terminal_send'].includes(t));
assert('Tracks terminal commands', hasTerminal);

// Check for search operations
const hasSearch = eventTypes.some(t => t === 'search');
assert('Tracks search operations', hasSearch);

// Timeline expand (click to toggle) — verify detail data exists
const withTool = events.data?.find(e => e.tool_name);
assert('Events have tool_name for detail view', withTool != null);

// ══════════════════════════════════════════════════════
// 5. SECURITY / ALERTS
// ══════════════════════════════════════════════════════
console.log('\n═══ 5. SECURITY / ALERTS ═══');

const alerts = await api('/api/alerts?limit=50');
assert('Alerts endpoint returns 200', alerts.status === 200);
assert('Alerts returns array', Array.isArray(alerts.data));
assert('Has alerts', alerts.data?.length > 0, `got ${alerts.data?.length}`);

const a0 = alerts.data?.[0];
assert('Alert has id', typeof a0?.id === 'number');
assert('Alert has session_id', typeof a0?.session_id === 'string');
assert('Alert has timestamp', typeof a0?.timestamp === 'string');
assert('Alert has severity', ['info', 'watch', 'warn', 'danger'].includes(a0?.severity));
assert('Alert has message', typeof a0?.message === 'string' && a0.message.length > 0);
assert('Alert has alert_type', typeof a0?.alert_type === 'string');
assert('Alert has acknowledged field', typeof a0?.acknowledged === 'boolean');

// Alert types — verify features from design
const alertTypes = [...new Set(alerts.data.map(a => a.alert_type))];
console.log(`    Alert types found: ${alertTypes.join(', ')}`);
assert('Detects sensitive file access', alertTypes.includes('sensitive_file'), `types: ${alertTypes.join(', ')}`);

// Severity filter
const warnAlerts = await api('/api/alerts?limit=50&severity=warn');
assert('Alert severity filter works', warnAlerts.data?.every(a => a.severity === 'warn') ?? true);

// Acknowledge flow
const unacked = alerts.data.find(a => !a.acknowledged);
if (unacked) {
  const ack = await fetch(BASE + `/api/alerts/${unacked.id}/acknowledge`, { method: 'POST' });
  assert('Acknowledge returns 200', ack.status === 200);
  const ackData = await ack.json();
  assert('Acknowledge returns ok', ackData.ok === true);

  // Verify it persisted
  const check = await api('/api/alerts?limit=200');
  const found = check.data?.find(a => a.id === unacked.id);
  assert('Acknowledge persisted', found?.acknowledged === true);
} else {
  assert('Has unacknowledged alert to test', false, 'all alerts already acknowledged');
}

// ══════════════════════════════════════════════════════
// 6. MEMORY OPERATIONS
// ══════════════════════════════════════════════════════
console.log('\n═══ 6. MEMORY ═══');

const memory = await api('/api/memory?limit=50');
assert('Memory endpoint returns 200', memory.status === 200);
assert('Memory returns array', Array.isArray(memory.data));
assert('Has memory operations', memory.data?.length > 0, `got ${memory.data?.length}`);

const m0 = memory.data?.[0];
assert('MemOp has session_id', typeof m0?.session_id === 'string');
assert('MemOp has timestamp', typeof m0?.timestamp === 'string');
assert('MemOp has operation', ['read', 'write', 'delete'].includes(m0?.operation));
assert('MemOp has memory_scope', ['user', 'session', 'repo', 'unknown'].includes(m0?.memory_scope));
assert('MemOp has memory_path', typeof m0?.memory_path === 'string');
assert('MemOp has content_summary', typeof m0?.content_summary === 'string');
assert('MemOp has risk_level', ['info', 'watch', 'warn', 'danger'].includes(m0?.risk_level));

// Check scopes (design: "accessing memory like agent memory")
const scopes = [...new Set(memory.data.map(m => m.memory_scope))];
console.log(`    Memory scopes: ${scopes.join(', ')}`);
assert('Tracks multiple memory scopes', scopes.length > 1, `scopes: ${scopes.join(', ')}`);

// Check operations
const ops = [...new Set(memory.data.map(m => m.operation))];
console.log(`    Memory operations: ${ops.join(', ')}`);
assert('Tracks write operations', ops.includes('write'));

// Session filter
const filteredMem = await api(`/api/memory?limit=10&session_id=${s0.id}`);
assert('Memory session filter works', filteredMem.status === 200);

// ══════════════════════════════════════════════════════
// 7. PROJECTS
// ══════════════════════════════════════════════════════
console.log('\n═══ 7. PROJECTS ═══');

const projects = await api('/api/projects');
assert('Projects endpoint returns 200', projects.status === 200);
assert('Projects returns array', Array.isArray(projects.data));
assert('Has projects', projects.data?.length > 0, `got ${projects.data?.length}`);

const p0 = projects.data?.[0];
assert('Project has project_name', typeof p0?.project_name === 'string' && p0.project_name.length > 0);
assert('Project has session_count', typeof p0?.session_count === 'number');
assert('Project has total_events', typeof p0?.total_events === 'number');
assert('Project has danger_count', typeof p0?.danger_count === 'number');
assert('Project has warn_count', typeof p0?.warn_count === 'number');
assert('Project has last_active', p0?.last_active != null);

// Multiple projects (design: "drill down into what projects are being worked on")
assert('Multiple projects tracked', projects.data.length > 3, `got ${projects.data.length}`);

// ══════════════════════════════════════════════════════
// 8. NAVIGATION & INTERACTIVE ELEMENTS
// ══════════════════════════════════════════════════════
console.log('\n═══ 8. NAVIGATION & INTERACTIVITY ═══');

// Verify nav buttons have correct data-page attributes
const navPages = ['home', 'sessions', 'timeline', 'security', 'memory', 'projects'];
for (const p of navPages) {
  assert(`Nav button exists for "${p}"`, page.text.includes(`data-page="${p}"`));
}

// Verify click handlers are wired
assert('Nav buttons have click listeners', page.text.includes("btn.addEventListener('click'"));
assert('Session items have onclick openSession', page.text.includes('openSession('));
assert('Timeline items have onclick toggle expand', page.text.includes("this.classList.toggle('expanded')"));

// Verify session search handler
assert('Session search has input listener', page.text.includes("sessionSearch")
  && page.text.includes("addEventListener('input'"));

// Verify timeline search handler  
assert('Timeline search has input listener', page.text.includes("timelineSearch")
  && page.text.includes('renderTimeline()'));

// Verify risk filter toggle
assert('Risk filter toggles riskOnly state', page.text.includes('riskOnly = !riskOnly'));
assert('Risk filter re-renders timeline', page.text.includes('renderTimeline'));

// Verify acknowledge button
assert('Acknowledge button calls ackAlert', page.text.includes('ackAlert('));
assert('ackAlert sends POST', page.text.includes('/acknowledge'));
assert('ackAlert updates button class', page.text.includes("classList.add('done')"));

// Security badge updates
assert('Security badge updates on unreviewed alerts', page.text.includes("securityBadge") 
  && page.text.includes("unreviewedAlerts"));

// Scrolls to top on page change
assert('Content scrolls to top on navigate', page.text.includes('scrollTop = 0'));

// Auto-refresh
assert('Home auto-refreshes on interval', page.text.includes('setInterval'));

// ══════════════════════════════════════════════════════
// 9. DESIGN FEATURES VERIFICATION
// ══════════════════════════════════════════════════════
console.log('\n═══ 9. DESIGN FEATURES ═══');

// From design.txt requirements:
// "tracks write actions, commands, git commits, file write, reads"
assert('Feature: File reads tracked', eventTypes.includes('file_read'));
assert('Feature: File writes tracked', eventTypes.includes('file_write') || eventTypes.includes('file_create'));
assert('Feature: Terminal commands tracked', eventTypes.includes('terminal_command'));
assert('Feature: Search operations tracked', eventTypes.includes('search'));

// "highlight security issues and destructive commands"
const hasDangerAlerts = alerts.data?.some(a => a.severity === 'danger');
assert('Feature: Danger alerts detected', hasDangerAlerts || alerts.data?.some(a => a.alert_type === 'destructive_command'));

const hasSensitiveAlerts = alerts.data?.some(a => a.alert_type === 'sensitive_file');
assert('Feature: Sensitive file alerts', hasSensitiveAlerts);

// "highlight accessing memory"  
assert('Feature: Memory operations tracked', memory.data?.length > 0);
assert('Feature: Memory scopes identified', scopes.length > 0);

// "nice web dashboards and charts"
assert('Feature: Risk donut chart', page.text.includes('conic-gradient'));
assert('Feature: Activity bar chart', page.text.includes('bar-chart'));
assert('Feature: Stat cards grid', page.text.includes('stat-grid'));

// "drill down into what projects"
assert('Feature: Projects page with stats', projects.data?.length > 0);

// "light weight tool" — verify it's a single HTML file SPA
assert('Feature: Single-file SPA (no external JS)', !page.text.includes('<script src='));

// "see if there was poisoned memory"
assert('Feature: Memory risk flagging', page.text.includes('flagged'));
assert('Feature: Injection detection exists', page.text.includes('mem-flag'));

// ══════════════════════════════════════════════════════
// 10. EDGE CASES
// ══════════════════════════════════════════════════════
console.log('\n═══ 10. EDGE CASES ═══');

// XSS protection (esc function)
assert('Has XSS escape function', page.text.includes('function esc('));
assert('Escape uses textContent', page.text.includes('d.textContent = s'));

// Empty state handling
assert('Home has empty state', page.text.includes('No data yet'));
assert('Sessions has empty state', page.text.includes('No sessions found'));
assert('Timeline has empty state', page.text.includes('No events to show'));
assert('Security has empty state', page.text.includes('No alerts'));
assert('Memory has empty state', page.text.includes('No memory operations'));
assert('Projects has empty state', page.text.includes('No projects tracked'));

// API error handling
assert('API has try/catch error handling', page.text.includes('catch (e)'));

// ══════════════════════════════════════════════════════
// SUMMARY
// ══════════════════════════════════════════════════════
console.log('\n' + '═'.repeat(50));
console.log(`\n  RESULTS: ${pass} passed, ${fail} failed\n`);
if (errors.length > 0) {
  console.log('  FAILURES:');
  errors.forEach(e => console.log(e));
}
console.log('');
process.exit(fail > 0 ? 1 : 0);
