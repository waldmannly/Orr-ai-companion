import express from 'express';
import * as path from 'path';
import * as fs from 'fs';
import { exec } from 'child_process';
import { Config } from '../config';
import {
  getAllSessions, getSession, getSessionEvents, getRecentEvents,
  getAlerts, acknowledgeAlert, getMemoryOps, getStats, getProjectStats, getLiveEvents, getAgentStats,
  getEventById, getEventsByFile, getSessionsByProject,
} from '../storage/db';

export function createDashboardServer(config: Config): express.Express {
  const app = express();
  app.use(express.json());

  // Serve static frontend files
  app.use(express.static(path.join(__dirname, '..', '..', 'src', 'dashboard', 'public')));

  // ── API Routes ──

  // Stats / Home
  app.get('/api/stats', (_req, res) => {
    res.json(getStats());
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

  // Agent stats
  app.get('/api/sessions/:id/agents', (req, res) => {
    res.json(getAgentStats(req.params.id));
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
