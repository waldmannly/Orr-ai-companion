import express from 'express';
import * as path from 'path';
import * as fs from 'fs';
import { exec } from 'child_process';
import { Config } from '../config';
import {
  getAllSessions, getSession, getSessionEvents, getRecentEvents,
  getAlerts, acknowledgeAlert, acknowledgeAllAlerts, getMemoryOps,
  getStats, getStatsForRange, getProjectStats, getLiveEvents, getAgentStats,
  getEventById, getEventsByFile, getSessionsByProject, searchEvents, getDb,
} from '../storage/db';

// SSE — broadcast events to connected dashboard clients
const sseClients = new Set<express.Response>();

export function broadcastSSE(eventType: string, data: unknown) {
  const payload = `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try { client.write(payload); } catch { sseClients.delete(client); }
  }
}

export function createDashboardServer(config: Config): express.Express {
  const app = express();
  app.use(express.json());

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
    res.json(getAlerts(limit, severity as 'warn' | 'danger' | undefined, sessionId));
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

  // Read file content (text files only, capped at 200KB)
  app.get('/api/file/read', (req, res) => {
    const filePath = req.query.path as string;
    if (!filePath || typeof filePath !== 'string') return res.status(400).json({ error: 'Missing path' });
    const resolved = path.resolve(filePath);
    if (resolved.includes('..')) return res.status(403).json({ error: 'Invalid path' });
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
  app.post('/api/file/open', (req, res) => {
    const filePath = req.body?.path as string;
    if (!filePath || typeof filePath !== 'string') return res.status(400).json({ error: 'Missing path' });
    const resolved = path.resolve(filePath);
    if (!fs.existsSync(resolved)) return res.status(404).json({ error: 'File not found' });
    // Try VS Code first, fall back to OS default
    exec(`code "${resolved}"`, (err) => {
      if (err) {
        const cmd = process.platform === 'win32' ? `start "" "${resolved}"` : process.platform === 'darwin' ? `open "${resolved}"` : `xdg-open "${resolved}"`;
        exec(cmd);
      }
    });
    res.json({ ok: true });
  });

  // Reveal file/folder in system file explorer
  app.post('/api/file/reveal', (req, res) => {
    const filePath = req.body?.path as string;
    if (!filePath || typeof filePath !== 'string') return res.status(400).json({ error: 'Missing path' });
    const resolved = path.resolve(filePath);
    const dir = fs.existsSync(resolved) && fs.statSync(resolved).isDirectory() ? resolved : path.dirname(resolved);
    if (!fs.existsSync(dir)) return res.status(404).json({ error: 'Path not found' });
    const cmd = process.platform === 'win32' ? `explorer "${dir}"` : process.platform === 'darwin' ? `open "${dir}"` : `xdg-open "${dir}"`;
    exec(cmd);
    res.json({ ok: true });
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
