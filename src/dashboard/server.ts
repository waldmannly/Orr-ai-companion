import express from 'express';
import * as path from 'path';
import * as fs from 'fs';
import { execFile } from 'child_process';
import { Config, saveConfig, mergeConfig, getConfigPath } from '../config';
import {
  getAllSessions, getSession, getSessionEvents, getRecentEvents,
  getAlerts, acknowledgeAlert, acknowledgeAllAlerts, getMemoryOps,
  getStats, getStatsForRange, getProjectStats, getLiveEvents, getAgentStats,
  getEventById, getEventsByFile, getSessionsByProject, searchEvents, getDb,
  getAllBaselines, getSessionTokens, getProjectTokens,
  getMemoryLineage, getMemoryHealth,
  getEventsFiltered, getSessionHealthMetrics, getGlobalMetrics,
  getGuardrailViolations, getSessionsByBranch, getBranchSummary,
  getActiveSessionStatus, getFileActivity, setSessionBranch,
  setSessionTaskGroup, getLinkedSessions, getTaskGroups, getBranchActivitySummary,
  vacuumDb,
} from '../storage/db';
import { testWebhook } from '../notifications';
import { getAllTrustScores, getTrustScore, getProviderComparison } from '../trust';
import { verifyChain, generateEvidenceReport, exportSignedSession, initHashChain } from '../compliance';
import { getAvailablePacks, loadPackFromFile, loadPacksFromDirectory } from '../rules/packs';
import {
  getPendingInterventions, getResolvedInterventions, getAllInterventions,
  getIntervention, resolveIntervention, denyAllPending, getInterventionStats,
  getAutoDenyTimeout, setAutoDenyTimeout,
} from '../guardrails/intervention';
import {
  getSessionPrompts, getRecentPrompts, getProjectPrompts, searchPrompts,
  getPromptStats, generateCrashRecovery,
} from '../prompts';
import {
  getBlockedCommands, getResolvedCommands, getRecentCommands, getSessionCommands,
  getCommandById, approveCommand, denyCommand, modifyAndRelease,
  denyAllBlocked, getCommandQueueStats, getOrphanedBlocked, expireStaleCommands,
} from '../commands';
import {
  exportEventsCSV, exportEventsJSON, exportAlertsCSV,
  generateIncidentReport, generateWeeklySummary,
} from '../export';
import {
  getSessionAgentNodes, buildDelegationTree, getSessionDelegations,
  getAuthorityViolations, setAgentScopes, checkAgentAuthority,
} from '../agents';
import {
  getMultiAgentProjects, getInterleavedTimeline, getCrossSessionStats,
} from '../correlation';
import {
  scoreInjection, getMemoryDiffs, generateMemoryAnalysis,
} from '../analysis';
import {
  getLoadedPlugins, getPlugin, loadPlugin, unloadPlugin,
  getAllPluginRules, executeWidgetQuery, loadPluginsFromDirectory,
} from '../plugins';
import {
  createUser, listUsers, deactivateUser, getSharedRules,
  createSharedRule, toggleSharedRule, deleteSharedRule, getTeamStats,
} from '../team';
import {
  getAutoResponseConfig, updateAutoResponseConfig,
  getAutoActions, getAutoResponseStats, pauseSession, resumeSession, reverseAction,
} from '../response';
import { getActiveWatcher } from '../watcher';
import { getKilledSessions } from '../storage/db';
import {
  getPolicy, getTier, loadPolicy, applyPolicy, checkPolicy,
  mergeGuardrails, isFieldLocked, hasPermission, requirePermission,
  getPolicyViolations, getPolicyMetrics, getPolicySummary, getPolicyHistory,
  recordPolicyViolation, recordPolicyMetric,
} from '../policy';
import { collectPRData, generatePRComment, PRCommentRequest } from '../pr-bot';
import { postOrUpdateComment, getPRBranch } from '../pr-bot/github';
import {
  getCostSummary, getCostRecommendations, getSessionCost,
  getTodayCost, getAvailablePricing, estimateCost,
} from '../cost';

// SSE — broadcast events to connected dashboard clients
const sseClients = new Set<express.Response>();

export function broadcastSSE(eventType: string, data: unknown) {
  const payload = `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try { client.write(payload); } catch { sseClients.delete(client); }
  }
}

/**
 * SECURITY: Check if a file path is within allowed directories.
 * Allows reads only within: tracker data dir, watched workspaces, config dir.
 */
function isPathAllowed(resolved: string, config: Config): boolean {
  const allowed = [
    path.resolve(process.cwd(), 'data'),
    path.resolve(process.cwd()),
    ...config.watchPaths.map(p => path.resolve(p)),
  ];
  const normalized = path.normalize(resolved);
  return allowed.some(base => {
    const normalizedBase = path.normalize(base);
    return normalized === normalizedBase || normalized.startsWith(normalizedBase + path.sep);
  });
}

export function createDashboardServer(config: Config): express.Express {
  const app = express();
  app.use(express.json({ limit: '100kb' }));

  // ── Security headers ──
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'");
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
  });

  // ── Rate limiting ──
  const rateBuckets = new Map<string, { count: number; resetAt: number }>();
  function rateLimit(key: string, maxPerMinute: number): boolean {
    const now = Date.now();
    let bucket = rateBuckets.get(key);
    if (!bucket || now > bucket.resetAt) {
      bucket = { count: 0, resetAt: now + 60_000 };
      rateBuckets.set(key, bucket);
    }
    bucket.count++;
    return bucket.count > maxPerMinute;
  }
  // General API rate limiter
  app.use('/api', (req, res, next) => {
    if (rateLimit('global', 300)) {
      return res.status(429).json({ error: 'Too many requests' });
    }
    next();
  });

  // Serve static frontend files
  app.use(express.static(path.join(__dirname, '..', '..', 'src', 'dashboard', 'public')));

  // ── API Routes ──

  // SSE — real-time event streaming
  app.get('/api/events/stream', (req, res) => {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    });
    res.write('event: connected\ndata: {}\n\n');
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
  });

  // Stats / Home
  app.get('/api/stats', (req, res) => {
    const range = (req.query.range as string) || 'today';
    const now = new Date();
    let startDate: string;
    let endDate = new Date(now.getTime() + 86400000).toISOString().split('T')[0] + 'T00:00:00';

    if (range === 'week') {
      const d = new Date(now);
      d.setDate(d.getDate() - 7);
      startDate = d.toISOString().split('T')[0] + 'T00:00:00';
    } else if (range === 'month') {
      const d = new Date(now);
      d.setDate(d.getDate() - 30);
      startDate = d.toISOString().split('T')[0] + 'T00:00:00';
    } else {
      startDate = now.toISOString().split('T')[0] + 'T00:00:00';
    }

    const stats = getStatsForRange(startDate, endDate);

    // Daily event counts for chart
    const days = range === 'month' ? 30 : range === 'week' ? 7 : 7;
    const dailyCounts: Array<{ date: string; count: number }> = [];
    const d2 = getDb();
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const dateStr = d.toISOString().split('T')[0];
      const count = (d2.prepare('SELECT COUNT(*) as c FROM events WHERE timestamp >= ? AND timestamp < ?')
        .get(dateStr + 'T00:00:00', dateStr + 'T23:59:59') as { c: number }).c;
      dailyCounts.push({ date: dateStr, count });
    }

    res.json({ ...stats, dailyCounts });
  });

  // Sessions
  app.get('/api/sessions', (req, res) => {
    const limit = parseInt(req.query.limit as string) || 50;
    res.json(getAllSessions(limit));
  });

  app.get('/api/sessions/:id', (req, res) => {
    const session = getSession(req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    res.json(session);
  });

  // Events
  app.get('/api/sessions/:id/events', (req, res) => {
    const limit = parseInt(req.query.limit as string) || 500;
    const offset = parseInt(req.query.offset as string) || 0;
    const risk = req.query.risk as string | undefined;
    const type = req.query.type as string | undefined;
    const events = getSessionEvents(req.params.id, limit, offset,
      risk as 'info' | 'watch' | 'warn' | 'danger' | undefined, type);
    res.json(events);
  });

  app.get('/api/events/recent', (req, res) => {
    const limit = parseInt(req.query.limit as string) || 50;
    res.json(getRecentEvents(limit));
  });

  // Live events (polling endpoint — returns events since a timestamp)
  app.get('/api/events/live', (req, res) => {
    const since = (req.query.since as string) || new Date(Date.now() - 60000).toISOString();
    res.json(getLiveEvents(since));
  });

  // Events touching a specific file (must be before :id route)
  app.get('/api/events/by-file', (req, res) => {
    const filePath = req.query.path as string;
    if (!filePath) return res.status(400).json({ error: 'Missing path' });
    const limit = parseInt(req.query.limit as string) || 100;
    res.json(getEventsByFile(filePath, limit));
  });

  // Advanced event filtering (must be before :id route)
  app.get('/api/events/filtered', (req, res) => {
    res.json(getEventsFiltered({
      sessionId: req.query.sessionId as string,
      startDate: req.query.startDate as string,
      endDate: req.query.endDate as string,
      riskLevel: req.query.riskLevel as string,
      eventType: req.query.eventType as string,
      search: req.query.search as string,
      limit: req.query.limit ? Number(req.query.limit) : undefined,
      offset: req.query.offset ? Number(req.query.offset) : undefined,
    }));
  });

  // Single event by ID
  app.get('/api/events/:id', (req, res) => {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid event ID' });
    const event = getEventById(id);
    if (!event) return res.status(404).json({ error: 'Event not found' });
    res.json(event);
  });

  // Sessions for a project
  app.get('/api/projects/:name/sessions', (req, res) => {
    const limit = parseInt(req.query.limit as string) || 50;
    res.json(getSessionsByProject(req.params.name, limit));
  });

  // Full-text search across events
  app.get('/api/search', (req, res) => {
    const q = req.query.q as string;
    if (!q || q.length < 2) return res.status(400).json({ error: 'Query must be at least 2 characters' });
    const limit = parseInt(req.query.limit as string) || 100;
    res.json(searchEvents(q, limit));
  });

  // Alerts
  app.get('/api/alerts', (req, res) => {
    const limit = parseInt(req.query.limit as string) || 100;
    const severity = req.query.severity as string | undefined;
    const sessionId = req.query.session_id as string | undefined;
    res.json(getAlerts(limit, severity as 'warn' | 'danger' | 'critical' | undefined, sessionId));
  });

  // Dedicated threats endpoint — critical alerts only
  app.get('/api/threats', (req, res) => {
    const limit = parseInt(req.query.limit as string) || 200;
    res.json(getAlerts(limit, 'critical'));
  });

  app.post('/api/alerts/:id/acknowledge', (req, res) => {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid alert ID' });
    acknowledgeAlert(id);
    res.json({ ok: true });
  });

  app.post('/api/alerts/acknowledge-all', (_req, res) => {
    acknowledgeAllAlerts();
    res.json({ ok: true });
  });

  // Agent stats
  app.get('/api/sessions/:id/agents', (req, res) => {
    res.json(getAgentStats(req.params.id));
  });

  // Export session data
  app.get('/api/sessions/:id/export', (req, res) => {
    const session = getSession(req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    const events = getSessionEvents(req.params.id, 10000);
    const alerts = getAlerts(1000, undefined, req.params.id);
    const memory = getMemoryOps(1000, req.params.id);
    const format = (req.query.format as string) || 'json';

    if (format === 'csv') {
      const header = 'timestamp,event_type,risk_level,agent_id,tool_name,summary,command,file_paths\n';
      const rows = events.map(e =>
        [e.timestamp, e.event_type, e.risk_level, e.agent_id, e.tool_name || '',
         `"${(e.summary || '').replace(/"/g, '""')}"`,
         `"${(e.command || '').replace(/"/g, '""')}"`,
         `"${(e.file_paths || []).join(';')}"`].join(',')
      ).join('\n');
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="session-${req.params.id.substring(0,8)}.csv"`);
      return res.send(header + rows);
    }

    res.setHeader('Content-Disposition', `attachment; filename="session-${req.params.id.substring(0,8)}.json"`);
    res.json({ session, events, alerts, memory });
  });

  // Memory
  app.get('/api/memory', (req, res) => {
    const limit = parseInt(req.query.limit as string) || 100;
    const sessionId = req.query.session_id as string | undefined;
    res.json(getMemoryOps(limit, sessionId));
  });

  // Projects
  app.get('/api/projects', (_req, res) => {
    res.json(getProjectStats());
  });

  // ── File Deep-Linking ──

  // Resolve Copilot virtual memory paths to real filesystem paths
  function resolveMemoryPath(virtualPath: string): string | null {
    if (!virtualPath.startsWith('/memories/')) return null;

    // /memories/repo/X.md → .github/copilot-memory/X.md (in each workspace)
    if (virtualPath.startsWith('/memories/repo/')) {
      const relative = virtualPath.replace('/memories/repo/', '');
      // Check known workspaces from sessions
      const sessions = getAllSessions(100);
      for (const s of sessions) {
        if (!s.workspace) continue;
        const candidate = path.join(s.workspace, '.github', 'copilot-memory', relative);
        if (fs.existsSync(candidate)) return candidate;
      }
      // Also check cwd
      const cwdCandidate = path.join(process.cwd(), '.github', 'copilot-memory', relative);
      if (fs.existsSync(cwdCandidate)) return cwdCandidate;
      return null;
    }

    // /memories/session/X.md → not persisted on disk after session ends
    if (virtualPath.startsWith('/memories/session/')) return null;

    // /memories/X.md (user scope) → %APPDATA%/Code/User/... area
    const userHome = process.env.USERPROFILE || process.env.HOME || '';
    const appData = process.env.APPDATA || path.join(userHome, 'AppData', 'Roaming');
    const relative = virtualPath.replace('/memories/', '');

    // VS Code stores user memories in globalStorage
    const candidates = [
      path.join(appData, 'Code', 'User', 'memories', relative),
      path.join(appData, 'Code', 'User', 'globalStorage', 'github.copilot-chat', 'memories', relative),
    ];
    for (const c of candidates) {
      if (fs.existsSync(c)) return c;
    }
    return null;
  }

  // Resolve a memory path to a real path
  app.get('/api/memory/resolve', (req, res) => {
    const memPath = req.query.path as string;
    if (!memPath) return res.status(400).json({ error: 'Missing path' });
    const resolved = resolveMemoryPath(memPath);
    if (!resolved) return res.status(404).json({ error: 'Memory file not found on disk', virtual_path: memPath, hint: memPath.startsWith('/memories/session/') ? 'Session memory is ephemeral and not persisted to disk' : 'Could not locate the physical file — it may have been deleted or the workspace is not accessible' });
    res.json({ virtual_path: memPath, real_path: resolved });
  });

  // Read file content (text files only, capped at 200KB)
  // SECURITY: Only allows reads within watched workspaces, the tracker's data dir,
  // or explicitly resolved memory paths. Blocks arbitrary file system access.
  app.get('/api/file/read', (req, res) => {
    if (rateLimit('file-read', 60)) return res.status(429).json({ error: 'Too many requests' });
    let filePath = req.query.path as string;
    if (!filePath || typeof filePath !== 'string') return res.status(400).json({ error: 'Missing path' });
    // Auto-resolve memory virtual paths
    if (filePath.startsWith('/memories/')) {
      const resolved = resolveMemoryPath(filePath);
      if (!resolved) return res.status(404).json({ error: 'Memory file not found on disk', hint: filePath.startsWith('/memories/session/') ? 'Session memory is ephemeral' : 'Could not locate the physical file' });
      filePath = resolved;
    }
    const resolved = path.resolve(filePath);
    // Enforce path allowlist: data dir + watched workspaces only
    if (!isPathAllowed(resolved, config)) {
      return res.status(403).json({ error: 'Path outside allowed directories' });
    }
    try {
      const stat = fs.statSync(resolved);
      if (!stat.isFile()) return res.status(400).json({ error: 'Not a file' });
      if (stat.size > 200 * 1024) return res.json({ path: resolved, truncated: true, size: stat.size, content: fs.readFileSync(resolved, 'utf-8').substring(0, 200 * 1024) });
      res.json({ path: resolved, truncated: false, size: stat.size, content: fs.readFileSync(resolved, 'utf-8') });
    } catch {
      res.status(404).json({ error: 'File not found' });
    }
  });

  // Open file in default editor (VS Code preferred)
  // SECURITY: Uses execFile() (no shell) to prevent command injection
  app.post('/api/file/open', (req, res) => {
    if (rateLimit('file-open', 10)) return res.status(429).json({ error: 'Too many requests' });
    let filePath = req.body?.path as string;
    if (!filePath || typeof filePath !== 'string') return res.status(400).json({ error: 'Missing path' });
    if (filePath.startsWith('/memories/')) {
      const mem = resolveMemoryPath(filePath);
      if (!mem) return res.status(404).json({ error: 'Memory file not found on disk' });
      filePath = mem;
    }
    const resolved = path.resolve(filePath);
    if (!isPathAllowed(resolved, config)) return res.status(403).json({ error: 'Path outside allowed directories' });
    if (!fs.existsSync(resolved)) return res.status(404).json({ error: 'File not found' });
    // Try VS Code first, fall back to OS default — no shell to prevent injection
    execFile('code', ['--goto', resolved], (err) => {
      if (err) {
        if (process.platform === 'win32') execFile('cmd', ['/c', 'start', '""', resolved], () => {});
        else if (process.platform === 'darwin') execFile('open', [resolved], () => {});
        else execFile('xdg-open', [resolved], () => {});
      }
    });
    res.json({ ok: true });
  });

  // Reveal file/folder in system file explorer
  // SECURITY: Uses execFile() (no shell) to prevent command injection
  app.post('/api/file/reveal', (req, res) => {
    if (rateLimit('file-reveal', 10)) return res.status(429).json({ error: 'Too many requests' });
    let filePath = req.body?.path as string;
    if (!filePath || typeof filePath !== 'string') return res.status(400).json({ error: 'Missing path' });
    if (filePath.startsWith('/memories/')) {
      const mem = resolveMemoryPath(filePath);
      if (!mem) return res.status(404).json({ error: 'Memory file not found on disk' });
      filePath = mem;
    }
    const resolved = path.resolve(filePath);
    const dir = fs.existsSync(resolved) && fs.statSync(resolved).isDirectory() ? resolved : path.dirname(resolved);
    if (!fs.existsSync(dir)) return res.status(404).json({ error: 'Path not found' });
    if (!isPathAllowed(dir, config)) return res.status(403).json({ error: 'Path outside allowed directories' });
    if (process.platform === 'win32') execFile('explorer', [dir], () => {});
    else if (process.platform === 'darwin') execFile('open', [dir], () => {});
    else execFile('xdg-open', [dir], () => {});
    res.json({ ok: true });
  });

  // ── Settings ──
  // SECURITY: GET strips secrets, PUT uses field allowlist

  app.get('/api/settings', (_req, res) => {
    const safe = JSON.parse(JSON.stringify(config));
    // Strip secrets from response
    if (safe.prBot?.token) safe.prBot.token = safe.prBot.token ? '***' : '';
    if (safe.notifications?.slack?.url) safe.notifications.slack.url = safe.notifications.slack.url ? '(configured)' : '';
    if (safe.notifications?.webhook?.url) safe.notifications.webhook.url = safe.notifications.webhook.url ? '(configured)' : '';
    if (safe.notifications?.teams?.url) safe.notifications.teams.url = safe.notifications.teams.url ? '(configured)' : '';
    res.json(safe);
  });

  // Fields that can be changed via API — security-critical fields require manual config edit
  const SETTINGS_MUTABLE_FIELDS = new Set([
    'retention', 'alerts', 'dashboard', 'tokenBudget', 'costEstimation',
    'alertRules', 'sensitiveFiles', 'dangerousCommands',
  ]);

  app.put('/api/settings', (req, res) => {
    const updates = req.body;
    if (!updates || typeof updates !== 'object' || Array.isArray(updates)) return res.status(400).json({ error: 'Invalid settings' });
    // Block prototype pollution keys
    const forbidden = Object.keys(updates).filter(k => !SETTINGS_MUTABLE_FIELDS.has(k) || k === '__proto__' || k === 'constructor' || k === 'prototype');
    if (forbidden.length > 0) {
      return res.status(403).json({ error: `Cannot modify via API: ${forbidden.join(', ')}. Edit config.json directly for security-sensitive fields.` });
    }
    const merged = mergeConfig({ ...config, ...updates });
    // Apply to running config
    Object.assign(config, merged);
    try {
      saveConfig(merged);
      broadcastSSE('settings-updated', {});
      res.json({ ok: true });
    } catch (err: unknown) {
      console.error('[dashboard] Config save failed:', err);
      res.status(500).json({ error: 'Failed to save configuration' });
    }
  });

  // ── Baselines API ──
  app.get('/api/baselines/:project', (req, res) => {
    res.json(getAllBaselines(req.params.project));
  });

  // ── Token tracking API ──
  app.get('/api/sessions/:id/tokens', (req, res) => {
    res.json({ tokens: getSessionTokens(req.params.id) });
  });

  app.get('/api/projects/:name/tokens', (req, res) => {
    res.json({ tokens: getProjectTokens(req.params.name) });
  });

  // ── Cost Estimation API ──

  app.get('/api/costs/today', (_req, res) => {
    res.json(getTodayCost(config));
  });

  app.get('/api/costs/summary', (req, res) => {
    const days = Math.min(Number(req.query.days) || 30, 365);
    res.json(getCostSummary(config, days));
  });

  app.get('/api/costs/session/:id', (req, res) => {
    const cost = getSessionCost(req.params.id, config);
    if (!cost) return res.status(404).json({ error: 'Session not found' });
    res.json(cost);
  });

  app.get('/api/costs/recommendations', (_req, res) => {
    res.json(getCostRecommendations(config));
  });

  app.get('/api/costs/pricing', (_req, res) => {
    res.json(getAvailablePricing(config));
  });

  app.get('/api/costs/estimate', (req, res) => {
    const tokens = Number(req.query.tokens) || 0;
    const provider = (req.query.provider as string) || 'vscode-copilot';
    res.json(estimateCost(tokens, provider, config));
  });

  // ── Memory lineage API ──
  app.get('/api/memory/lineage', (req, res) => {
    const memPath = req.query.path as string;
    if (!memPath) return res.status(400).json({ error: 'path required' });
    res.json(getMemoryLineage(memPath));
  });

  app.get('/api/memory/health', (_req, res) => {
    res.json(getMemoryHealth());
  });

  // ── Computed metrics ──
  app.get('/api/sessions/:id/health', (req, res) => {
    res.json(getSessionHealthMetrics(req.params.id));
  });

  app.get('/api/metrics/global', (_req, res) => {
    res.json(getGlobalMetrics());
  });

  // ── Session replay ──
  app.get('/api/sessions/:id/replay', (req, res) => {
    const events = getSessionEvents(req.params.id, 10000, 0);
    const session = getSession(req.params.id);
    res.json({ session, events });
  });

  // ── Webhook test ──
  app.post('/api/notifications/test', async (req, res) => {
    const { type } = req.body;
    if (type !== 'slack' && type !== 'webhook' && type !== 'teams') return res.status(400).json({ error: 'type must be slack, webhook, or teams' });
    const result = await testWebhook(type);
    res.json(result);
  });

  // ── Trust Scores ──
  app.get('/api/trust', (_req, res) => {
    res.json(getAllTrustScores());
  });

  app.get('/api/trust/:provider', (req, res) => {
    const score = getTrustScore(req.params.provider);
    if (!score) return res.status(404).json({ error: 'No data for provider' });
    res.json(score);
  });

  app.get('/api/trust/compare/all', (_req, res) => {
    res.json(getProviderComparison());
  });

  // ── Compliance ──
  app.get('/api/compliance/chain/verify', (_req, res) => {
    res.json(verifyChain());
  });

  app.get('/api/compliance/report', (req, res) => {
    const startDate = req.query.start as string;
    const endDate = req.query.end as string;
    if (!startDate || !endDate) return res.status(400).json({ error: 'start and end query params required' });
    res.json(generateEvidenceReport(startDate, endDate));
  });

  app.get('/api/compliance/session/:id/signed', (req, res) => {
    const result = exportSignedSession(req.params.id);
    if (!result.session) return res.status(404).json({ error: 'Session not found' });
    res.setHeader('Content-Disposition', `attachment; filename="signed-session-${req.params.id.substring(0, 8)}.json"`);
    res.json(result);
  });

  // ── Guardrails ──
  app.get('/api/guardrails/violations', (req, res) => {
    const sessionId = req.query.session_id as string | undefined;
    const limit = parseInt(req.query.limit as string) || 100;
    res.json(getGuardrailViolations(sessionId, limit));
  });

  app.get('/api/guardrails/config', (_req, res) => {
    res.json(config.guardrails || {});
  });

  // ── Interventions (real-time approve/deny for blocked actions) ──

  app.get('/api/interventions', (req, res) => {
    const status = req.query.status as string;
    if (status === 'pending') return res.json(getPendingInterventions());
    if (status === 'resolved') {
      const limit = parseInt(req.query.limit as string) || 50;
      return res.json(getResolvedInterventions(limit));
    }
    const limit = parseInt(req.query.limit as string) || 100;
    res.json(getAllInterventions(limit));
  });

  app.get('/api/interventions/stats', (_req, res) => {
    res.json(getInterventionStats());
  });

  app.get('/api/interventions/settings', (_req, res) => {
    res.json({ autoDenyTimeoutMs: getAutoDenyTimeout() });
  });

  app.put('/api/interventions/settings', (req, res) => {
    const { autoDenyTimeoutMs } = req.body;
    if (typeof autoDenyTimeoutMs === 'number' && autoDenyTimeoutMs >= 5000) {
      setAutoDenyTimeout(autoDenyTimeoutMs);
      res.json({ ok: true, autoDenyTimeoutMs });
    } else {
      res.status(400).json({ error: 'autoDenyTimeoutMs must be >= 5000' });
    }
  });

  app.get('/api/interventions/:id', (req, res) => {
    const intervention = getIntervention(req.params.id);
    if (!intervention) return res.status(404).json({ error: 'Intervention not found' });
    res.json(intervention);
  });

  app.post('/api/interventions/:id/approve', (req, res) => {
    const result = resolveIntervention(req.params.id, 'approved', 'user');
    if (!result) return res.status(404).json({ error: 'Intervention not found or already resolved' });
    broadcastSSE('intervention-resolved', result);
    res.json(result);
  });

  app.post('/api/interventions/:id/deny', (req, res) => {
    const result = resolveIntervention(req.params.id, 'denied', 'user');
    if (!result) return res.status(404).json({ error: 'Intervention not found or already resolved' });
    broadcastSSE('intervention-resolved', result);
    res.json(result);
  });

  app.post('/api/interventions/deny-all', (_req, res) => {
    const denied = denyAllPending();
    for (const d of denied) broadcastSSE('intervention-resolved', d);
    res.json({ denied: denied.length });
  });

  // ── Command Queue ──

  /** Get all blocked (pending) commands */
  app.get('/api/commands/blocked', (_req, res) => {
    res.json(getBlockedCommands());
  });

  /** Get resolved commands (approved/denied/modified/expired) */
  app.get('/api/commands/resolved', (req, res) => {
    const limit = Math.min(Number(req.query.limit) || 50, 500);
    res.json(getResolvedCommands(limit));
  });

  /** Get all recent commands (any status) */
  app.get('/api/commands', (req, res) => {
    const limit = Math.min(Number(req.query.limit) || 100, 500);
    res.json(getRecentCommands(limit));
  });

  /** Get command queue stats */
  app.get('/api/commands/stats', (_req, res) => {
    res.json(getCommandQueueStats());
  });

  /** Get orphaned blocked commands (from before last crash/restart) */
  app.get('/api/commands/orphaned', (_req, res) => {
    res.json(getOrphanedBlocked());
  });

  /** Get commands for a specific session */
  app.get('/api/sessions/:id/commands', (req, res) => {
    res.json(getSessionCommands(req.params.id));
  });

  /** Get a single command by ID */
  app.get('/api/commands/:id', (req, res) => {
    const cmd = getCommandById(Number(req.params.id));
    if (!cmd) return res.status(404).json({ error: 'Command not found' });
    res.json(cmd);
  });

  /** Approve a blocked command as-is */
  app.post('/api/commands/:id/approve', (req, res) => {
    const { notes } = req.body || {};
    const cmd = approveCommand(Number(req.params.id), 'user', notes);
    if (!cmd) return res.status(404).json({ error: 'Command not found or not blocked' });
    broadcastSSE('command-released', cmd);
    res.json(cmd);
  });

  /** Deny a blocked command */
  app.post('/api/commands/:id/deny', (req, res) => {
    const { notes } = req.body || {};
    const cmd = denyCommand(Number(req.params.id), 'user', notes);
    if (!cmd) return res.status(404).json({ error: 'Command not found or not blocked' });
    broadcastSSE('command-resolved', cmd);
    res.json(cmd);
  });

  /** Edit and release a modified version of the blocked command */
  app.post('/api/commands/:id/modify', (req, res) => {
    const { command, notes } = req.body || {};
    if (!command || typeof command !== 'string' || !command.trim()) {
      return res.status(400).json({ error: 'command is required' });
    }
    const cmd = modifyAndRelease(Number(req.params.id), command.trim(), 'user', notes);
    if (!cmd) return res.status(404).json({ error: 'Command not found or not blocked' });
    broadcastSSE('command-released', cmd);
    res.json(cmd);
  });

  /** Deny all blocked commands (emergency kill-all) */
  app.post('/api/commands/deny-all', (_req, res) => {
    const count = denyAllBlocked();
    broadcastSSE('commands-denied-all', { count });
    res.json({ denied: count });
  });

  /** Expire stale blocked commands */
  app.post('/api/commands/expire', (req, res) => {
    const maxAgeMs = Number(req.body?.maxAgeMs) || 3600_000;
    const count = expireStaleCommands(maxAgeMs);
    res.json({ expired: count });
  });

  // ── Rule Packs ──
  app.get('/api/rules/packs', (_req, res) => {
    res.json(getAvailablePacks());
  });

  app.post('/api/rules/packs/load', (req, res) => {
    const { path: packPath } = req.body;
    if (!packPath) return res.status(400).json({ error: 'path required' });
    try {
      const pack = loadPackFromFile(packPath);
      res.json({ ok: true, pack: { id: pack.id, name: pack.name, rules: pack.rules.length } });
    } catch (err) {
      console.error('[dashboard] Failed to load rule pack:', err);
      res.status(400).json({ error: 'Failed to load rule pack' });
    }
  });

  // ── Branch/PR Linking ──
  app.get('/api/branches/:branch/sessions', (req, res) => {
    res.json(getSessionsByBranch(req.params.branch));
  });

  app.get('/api/branches/:branch/summary', (req, res) => {
    res.json(getBranchSummary(req.params.branch));
  });

  app.post('/api/sessions/:id/branch', (req, res) => {
    const { branch } = req.body;
    if (!branch) return res.status(400).json({ error: 'branch required' });
    setSessionBranch(req.params.id, branch);
    res.json({ ok: true });
  });

  // ── IDE API (for VS Code extension status bar / inline annotations) ──
  app.get('/api/ide/status', (_req, res) => {
    res.json(getActiveSessionStatus());
  });

  app.get('/api/ide/file-activity', (req, res) => {
    const filePath = req.query.path as string;
    if (!filePath) return res.status(400).json({ error: 'path required' });
    const limit = parseInt(req.query.limit as string) || 50;
    res.json(getFileActivity(filePath, limit));
  });

  app.get('/api/ide/session-summary', (_req, res) => {
    const status = getActiveSessionStatus();
    if (!status.sessionId) return res.json({ active: false });
    const health = getSessionHealthMetrics(status.sessionId);
    const violations = getGuardrailViolations(status.sessionId, 10);
    res.json({ active: true, ...status, health, recentViolations: violations });
  });

  // ── Prompt History ──

  app.get('/api/prompts', (req, res) => {
    const limit = parseInt(req.query.limit as string) || 50;
    res.json(getRecentPrompts(limit));
  });

  app.get('/api/prompts/stats', (_req, res) => {
    res.json(getPromptStats());
  });

  app.get('/api/prompts/search', (req, res) => {
    const q = req.query.q as string;
    if (!q || q.length < 2) return res.status(400).json({ error: 'Query must be at least 2 chars' });
    const limit = parseInt(req.query.limit as string) || 50;
    res.json(searchPrompts(q, limit));
  });

  app.get('/api/sessions/:id/prompts', (req, res) => {
    res.json(getSessionPrompts(req.params.id));
  });

  app.get('/api/projects/:name/prompts', (req, res) => {
    const limit = parseInt(req.query.limit as string) || 100;
    res.json(getProjectPrompts(req.params.name, limit));
  });

  // ── Crash Recovery ──

  app.get('/api/sessions/:id/recovery', (req, res) => {
    const recentCount = parseInt(req.query.recent as string) || 5;
    const ctx = generateCrashRecovery(req.params.id, recentCount);
    if (!ctx) return res.status(404).json({ error: 'Session not found or no prompts recorded' });
    res.json(ctx);
  });

  // ── Export & Reporting ──

  app.get('/api/export/events', (req, res) => {
    const start = (req.query.start as string) || new Date(Date.now() - 7 * 86400_000).toISOString();
    const end = (req.query.end as string) || new Date().toISOString();
    const format = (req.query.format as string) || 'json';
    const sessionId = req.query.session_id as string | undefined;
    try {
      if (format === 'csv') {
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="events-export.csv"');
        res.send(exportEventsCSV(start, end, sessionId));
      } else {
        res.setHeader('Content-Disposition', 'attachment; filename="events-export.json"');
        res.json(exportEventsJSON(start, end, sessionId));
      }
    } catch (err: any) {
      res.status(500).json({ error: 'Export too large. Try narrowing the date range or filtering by session.' });
    }
  });

  app.get('/api/export/alerts', (req, res) => {
    const start = (req.query.start as string) || new Date(Date.now() - 7 * 86400_000).toISOString();
    const end = (req.query.end as string) || new Date().toISOString();
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="alerts-export.csv"');
    res.send(exportAlertsCSV(start, end));
  });

  app.get('/api/export/incident-report', (req, res) => {
    const start = (req.query.start as string) || new Date(Date.now() - 7 * 86400_000).toISOString();
    const end = (req.query.end as string) || new Date().toISOString();
    res.json(generateIncidentReport(start, end));
  });

  app.get('/api/export/weekly-summary', (req, res) => {
    const weekStart = req.query.start as string | undefined;
    res.json(generateWeeklySummary(weekStart));
  });

  // ── Sub-Agent Authority ──

  app.get('/api/sessions/:id/agents/tree', (req, res) => {
    res.json(buildDelegationTree(req.params.id));
  });

  app.get('/api/sessions/:id/agents/nodes', (req, res) => {
    res.json(getSessionAgentNodes(req.params.id));
  });

  app.get('/api/sessions/:id/delegations', (req, res) => {
    res.json(getSessionDelegations(req.params.id));
  });

  app.get('/api/authority/violations', (req, res) => {
    const sessionId = req.query.session_id as string | undefined;
    const limit = Math.min(Number(req.query.limit) || 50, 500);
    res.json(getAuthorityViolations(sessionId, limit));
  });

  app.put('/api/agents/:agentId/scopes', (req, res) => {
    const { session_id, allowed, denied } = req.body || {};
    if (!session_id) return res.status(400).json({ error: 'session_id required' });
    setAgentScopes(req.params.agentId, session_id, allowed || [], denied || []);
    res.json({ ok: true });
  });

  // ── Multi-Agent Correlation ──

  app.get('/api/correlation/projects', (_req, res) => {
    res.json(getMultiAgentProjects());
  });

  app.get('/api/correlation/stats', (_req, res) => {
    res.json(getCrossSessionStats());
  });

  app.get('/api/correlation/timeline', (req, res) => {
    const project_name = req.query.project as string | undefined;
    const session_ids = req.query.sessions ? (req.query.sessions as string).split(',') : undefined;
    const limit = Math.min(Number(req.query.limit) || 200, 1000);
    const offset = Number(req.query.offset) || 0;
    res.json(getInterleavedTimeline({ project_name, session_ids, limit, offset }));
  });

  // ── Memory Content Analysis ──

  app.get('/api/analysis/memory', (_req, res) => {
    res.json(generateMemoryAnalysis());
  });

  app.get('/api/analysis/memory/diffs', (req, res) => {
    const memoryPath = req.query.path as string | undefined;
    res.json(getMemoryDiffs(memoryPath));
  });

  app.post('/api/analysis/injection-score', (req, res) => {
    const { content } = req.body || {};
    if (!content || typeof content !== 'string') return res.status(400).json({ error: 'content required' });
    res.json(scoreInjection(content));
  });

  // ── Plugin System ──

  app.get('/api/plugins', (_req, res) => {
    res.json(getLoadedPlugins().map(p => ({
      id: p.manifest.id,
      name: p.manifest.name,
      version: p.manifest.version,
      description: p.manifest.description,
      author: p.manifest.author,
      ruleCount: p.compiledRules.length,
      widgetCount: p.manifest.widgets?.length || 0,
      loadedAt: p.loadedAt,
    })));
  });

  app.get('/api/plugins/rules', (_req, res) => {
    res.json(getAllPluginRules());
  });

  app.get('/api/plugins/:id', (req, res) => {
    const plugin = getPlugin(req.params.id);
    if (!plugin) return res.status(404).json({ error: 'Plugin not found' });
    res.json(plugin.manifest);
  });

  app.post('/api/plugins/load', (req, res) => {
    const { path: filePath } = req.body || {};
    if (!filePath) return res.status(400).json({ error: 'path required' });
    try {
      const loaded = loadPlugin(filePath);
      res.json({ ok: true, id: loaded.manifest.id, rules: loaded.compiledRules.length });
    } catch (err) {
      console.error('[dashboard] Failed to load plugin:', err);
      res.status(400).json({ error: 'Failed to load plugin' });
    }
  });

  app.delete('/api/plugins/:id', (req, res) => {
    const removed = unloadPlugin(req.params.id);
    res.json({ ok: removed });
  });

  app.get('/api/plugins/:pluginId/widgets/:widgetId', (req, res) => {
    try {
      const data = executeWidgetQuery(req.params.pluginId, req.params.widgetId, getDb());
      res.json(data);
    } catch (err) {
      console.error('[dashboard] Widget query failed:', err);
      res.status(400).json({ error: 'Widget query failed' });
    }
  });

  // ── Team Dashboard ──

  app.get('/api/team/users', (_req, res) => {
    const users = listUsers().map(u => ({ ...u, api_key_hash: undefined }));
    res.json(users);
  });

  app.post('/api/team/users', (req, res) => {
    const { name, role } = req.body || {};
    if (!name) return res.status(400).json({ error: 'name required' });
    const { user, apiKey } = createUser(name, role || 'viewer');
    res.json({ user: { ...user, api_key_hash: undefined }, apiKey });
  });

  app.delete('/api/team/users/:id', (req, res) => {
    const ok = deactivateUser(req.params.id);
    res.json({ ok });
  });

  app.get('/api/team/rules', (_req, res) => {
    res.json(getSharedRules());
  });

  app.post('/api/team/rules', (req, res) => {
    const { name, description, pattern, is_regex, severity, created_by } = req.body || {};
    if (!name || !pattern) return res.status(400).json({ error: 'name and pattern required' });
    const rule = createSharedRule({ name, description, pattern, is_regex, severity, created_by: created_by || 'anonymous' });
    res.json(rule);
  });

  app.put('/api/team/rules/:id/toggle', (req, res) => {
    const { enabled } = req.body || {};
    const ok = toggleSharedRule(Number(req.params.id), enabled !== false);
    res.json({ ok });
  });

  app.delete('/api/team/rules/:id', (req, res) => {
    const ok = deleteSharedRule(Number(req.params.id));
    res.json({ ok });
  });

  app.get('/api/team/stats', (_req, res) => {
    res.json(getTeamStats());
  });

  // ── Session Linking ──

  app.get('/api/tasks', (req, res) => {
    const limit = Math.min(Number(req.query.limit) || 50, 200);
    res.json(getTaskGroups(limit));
  });

  app.get('/api/tasks/:taskGroup/sessions', (req, res) => {
    res.json(getLinkedSessions(decodeURIComponent(req.params.taskGroup)));
  });

  app.put('/api/sessions/:id/task-group', (req, res) => {
    const { task_group } = req.body || {};
    if (!task_group) return res.status(400).json({ error: 'task_group required' });
    setSessionTaskGroup(req.params.id, task_group);
    res.json({ ok: true });
  });

  // ── PR / Branch Activity Summary ──

  app.get('/api/pr-summary', (req, res) => {
    const project = req.query.project as string;
    const branch = req.query.branch as string;
    if (!project || !branch) return res.status(400).json({ error: 'project and branch query params required' });
    res.json(getBranchActivitySummary(project, branch));
  });

  app.get('/api/pr-summary/text', (req, res) => {
    const project = req.query.project as string;
    const branch = req.query.branch as string;
    if (!project || !branch) return res.status(400).json({ error: 'project and branch query params required' });
    const data = getBranchActivitySummary(project, branch);

    // Generate human-readable PR comment text
    let text = `## 🛡️ AI Agent Activity Summary\n\n`;
    text += `**Branch:** ${branch} | **Project:** ${project}\n\n`;
    text += `| Metric | Value |\n|---|---|\n`;
    text += `| Sessions | ${data.sessions.length} |\n`;
    text += `| Total Events | ${data.totalEvents} |\n`;
    text += `| Danger Events | ${data.dangerEvents} |\n`;
    text += `| Providers | ${data.providers.join(', ')} |\n`;
    if (data.timespan.first) {
      text += `| Time Span | ${new Date(data.timespan.first).toLocaleDateString()} — ${new Date(data.timespan.last).toLocaleDateString()} |\n`;
    }
    if (data.topRisks.length) {
      text += `\n### ⚠️ Top Risks\n\n`;
      for (const r of data.topRisks.slice(0, 10)) {
        const icon = r.risk_level === 'danger' ? '🔴' : '🟡';
        text += `- ${icon} **${r.event_type}** — ${r.summary}\n`;
      }
    }
    if (!data.dangerEvents) {
      text += `\n✅ No danger-level events detected.\n`;
    }
    res.type('text/markdown').send(text);
  });

  // ── Automated Response ──

  app.get('/api/response/config', (_req, res) => {
    res.json(getAutoResponseConfig());
  });

  app.put('/api/response/config', (req, res) => {
    const updated = updateAutoResponseConfig(req.body || {});
    res.json(updated);
  });

  app.get('/api/response/actions', (req, res) => {
    const sessionId = req.query.session_id as string | undefined;
    const limit = Math.min(Number(req.query.limit) || 50, 500);
    res.json(getAutoActions(sessionId, limit));
  });

  app.get('/api/response/stats', (_req, res) => {
    res.json(getAutoResponseStats());
  });

  app.post('/api/response/pause/:sessionId', (req, res) => {
    const { reason } = req.body || {};
    const action = pauseSession(req.params.sessionId, reason || 'Manual pause');
    broadcastSSE('session-paused', action);
    res.json(action);
  });

  app.post('/api/response/resume/:sessionId', (req, res) => {
    const action = resumeSession(req.params.sessionId, 'user');
    if (!action) return res.status(404).json({ error: 'Session not paused' });
    broadcastSSE('session-resumed', action);
    res.json(action);
  });

  app.post('/api/response/actions/:id/reverse', (req, res) => {
    const action = reverseAction(Number(req.params.id), 'user');
    if (!action) return res.status(404).json({ error: 'Action not found or already reversed' });
    res.json(action);
  });

  // ── Session Kill (enforcement) ──

  app.get('/api/sessions/killed', (_req, res) => {
    res.json(getKilledSessions());
  });

  app.post('/api/sessions/:id/kill', (req, res) => {
    const watcher = getActiveWatcher();
    if (!watcher) return res.status(503).json({ error: 'Watcher not running' });
    const sessionId = req.params.id;
    const reason = req.body?.reason || 'Manual kill from dashboard';
    if (watcher.isSessionKilled(sessionId)) {
      return res.status(409).json({ error: 'Session already killed' });
    }
    watcher.killSession(sessionId, reason);
    res.json({ ok: true, session_id: sessionId, reason });
  });

  // ── Database Maintenance ──

  app.post('/api/db/compact', (_req, res) => {
    try {
      const result = vacuumDb();
      const savedMB = ((result.before - result.after) / 1048576).toFixed(1);
      res.json({
        ok: true,
        before: result.before,
        after: result.after,
        saved: result.before - result.after,
        message: `Compacted: ${(result.before / 1048576).toFixed(1)} MB → ${(result.after / 1048576).toFixed(1)} MB (saved ${savedMB} MB)`,
      });
    } catch (e: unknown) {
      console.error('[dashboard] Vacuum/compact failed:', e);
      res.status(500).json({ error: 'Database compaction failed' });
    }
  });

  // ── Policy Engine ──

  app.get('/api/policy', (_req, res) => {
    res.json(getPolicy());
  });

  app.get('/api/policy/summary', (_req, res) => {
    res.json(getPolicySummary());
  });

  app.get('/api/policy/tier', (_req, res) => {
    res.json({ tier: getTier() });
  });

  app.get('/api/policy/violations', (req, res) => {
    const limit = Math.min(Number(req.query.limit) || 100, 500);
    const category = req.query.category as string | undefined;
    res.json(getPolicyViolations({ limit, category }));
  });

  app.get('/api/policy/metrics', (req, res) => {
    const name = req.query.name as string | undefined;
    const since = req.query.since as string | undefined;
    res.json(getPolicyMetrics({ name, since }));
  });

  app.get('/api/policy/history', (_req, res) => {
    res.json(getPolicyHistory());
  });

  app.post('/api/policy/check', (req, res) => {
    const result = checkPolicy(req.body);
    res.json(result);
  });

  app.put('/api/policy', (req, res) => {
    try {
      const updated = applyPolicy(req.body, (req as any).teamUser?.name || 'api');
      res.json(updated);
    } catch (err: unknown) {
      console.error('[dashboard] Policy update failed:', err);
      res.status(400).json({ error: 'Failed to update policy' });
    }
  });

  app.get('/api/policy/field-locked/:field', (req, res) => {
    res.json({ locked: isFieldLocked(req.params.field) });
  });

  app.get('/api/policy/effective-guardrails', (_req, res) => {
    res.json(mergeGuardrails(config.guardrails));
  });

  // ── PR Comment Bot ──

  // Generate a preview of the PR comment (does not post to GitHub)
  app.get('/api/pr-comment/preview', (req, res) => {
    try {
      const branch = req.query.branch as string;
      if (!branch) return res.status(400).json({ error: 'branch query param is required' });
      const projectName = req.query.project as string | undefined;
      const request: PRCommentRequest = { branch, projectName };
      const data = collectPRData(request, config);
      const comment = generatePRComment(data, config);
      res.json({ branch, sessions: data.sessions.length, comment, data });
    } catch (e: unknown) {
      console.error('[dashboard] PR comment preview failed:', e);
      res.status(500).json({ error: 'Failed to generate PR comment preview' });
    }
  });

  // Post or update a PR comment on GitHub/GitLab/Bitbucket
  app.post('/api/pr-comment', async (req, res) => {
    try {
      const { branch, repo, prNumber, platform, projectName } = req.body || {};
      if (!prNumber) return res.status(400).json({ error: 'prNumber is required' });
      const targetRepo = repo || config.prBot.repo;
      if (!targetRepo) return res.status(400).json({ error: 'repo is required (set prBot.repo in config or pass in body)' });
      const targetPlatform = platform || config.prBot.platform;

      // If no branch provided, fetch it from the PR itself
      let targetBranch = branch as string;
      if (!targetBranch) {
        if (targetPlatform === 'github') {
          targetBranch = await getPRBranch(targetRepo, prNumber, config);
        } else {
          return res.status(400).json({ error: 'branch is required for non-GitHub platforms (or provide prNumber on GitHub to auto-detect)' });
        }
      }

      const request: PRCommentRequest = { branch: targetBranch, repo: targetRepo, prNumber, platform: targetPlatform, projectName };
      const data = collectPRData(request, config);
      const comment = generatePRComment(data, config);

      if (targetPlatform === 'github') {
        const result = await postOrUpdateComment(targetRepo, prNumber, comment, config);
        res.json({ ok: true, ...result, branch: targetBranch, sessions: data.sessions.length });
      } else {
        res.status(501).json({ error: 'Platform adapter not yet implemented. Use preview endpoint or GitHub.' });
      }
    } catch (e: unknown) {
      console.error('[dashboard] PR comment post failed:', e);
      res.status(500).json({ error: 'Failed to post PR comment' });
    }
  });

  // Fallback — serve index.html for SPA routes
  app.get('*', (_req, res) => {
    res.sendFile(path.join(__dirname, '..', '..', 'src', 'dashboard', 'public', 'index.html'));
  });

  return app;
}

export function startDashboard(config: Config) {
  const app = createDashboardServer(config);
  const { host, port } = config.dashboard;

  app.listen(port, host, () => {
    console.log(`[dashboard] Running at http://${host}:${port}`);
  });

  return app;
}
