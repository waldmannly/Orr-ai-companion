import express from 'express';
import * as path from 'path';
import { Config } from '../config';
import {
  getAllSessions, getSession, getSessionEvents, getRecentEvents,
  getAlerts, acknowledgeAlert, getMemoryOps, getStats, getProjectStats, getLiveEvents, getAgentStats,
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
