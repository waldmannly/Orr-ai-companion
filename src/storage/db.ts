import Database from 'better-sqlite3';
import * as path from 'path';
import * as fs from 'fs';
import { TrackerEvent, SessionInfo, Alert, MemoryOperation, RiskLevel } from '../parser/event-types';

let db: Database.Database;

export function getDb(): Database.Database {
  if (!db) throw new Error('Database not initialized. Call initDb() first.');
  return db;
}

export function initDb(dbPath?: string): Database.Database {
  const p = dbPath || path.join(process.cwd(), 'data', 'tracker.db');
  fs.mkdirSync(path.dirname(p), { recursive: true });
  db = new Database(p);
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  migrate();
  return db;
}

function migrate() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      workspace TEXT NOT NULL DEFAULT '',
      project_name TEXT NOT NULL DEFAULT '',
      started_at TEXT NOT NULL,
      ended_at TEXT,
      total_events INTEGER NOT NULL DEFAULT 0,
      danger_count INTEGER NOT NULL DEFAULT 0,
      warn_count INTEGER NOT NULL DEFAULT 0,
      source_tool TEXT NOT NULL DEFAULT 'vscode-copilot'
    );

    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      agent_id TEXT NOT NULL DEFAULT 'main',
      parent_agent_id TEXT,
      event_type TEXT NOT NULL,
      tool_name TEXT,
      risk_level TEXT NOT NULL DEFAULT 'info',
      summary TEXT NOT NULL DEFAULT '',
      file_paths TEXT NOT NULL DEFAULT '[]',
      command TEXT,
      parameters TEXT,
      duration_ms INTEGER,
      raw_log TEXT NOT NULL DEFAULT '',
      source_tool TEXT NOT NULL DEFAULT 'vscode-copilot'
    );

    CREATE TABLE IF NOT EXISTS memory_operations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id INTEGER,
      session_id TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      operation TEXT NOT NULL,
      memory_scope TEXT NOT NULL DEFAULT 'unknown',
      memory_path TEXT NOT NULL DEFAULT '',
      content_summary TEXT NOT NULL DEFAULT '',
      risk_level TEXT NOT NULL DEFAULT 'info'
    );

    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id INTEGER,
      session_id TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      alert_type TEXT NOT NULL,
      severity TEXT NOT NULL,
      message TEXT NOT NULL,
      acknowledged INTEGER NOT NULL DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_events_risk ON events(risk_level);
    CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
    CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_tool);
    CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id);
    CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
    CREATE INDEX IF NOT EXISTS idx_memory_session ON memory_operations(session_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_source ON sessions(source_tool);
  `);

  // Additive migration: add source_tool to existing DBs that lack it
  try {
    db.prepare("SELECT source_tool FROM events LIMIT 0").run();
  } catch {
    db.exec(`ALTER TABLE events ADD COLUMN source_tool TEXT NOT NULL DEFAULT 'vscode-copilot'`);
  }
  try {
    db.prepare("SELECT source_tool FROM sessions LIMIT 0").run();
  } catch {
    db.exec(`ALTER TABLE sessions ADD COLUMN source_tool TEXT NOT NULL DEFAULT 'vscode-copilot'`);
  }
}

// ── Retention cleanup ──

export function enforceRetention(maxAgeDays: number) {
  if (maxAgeDays <= 0) return;
  const cutoff = new Date(Date.now() - maxAgeDays * 86400000).toISOString();
  db.exec(`DELETE FROM events WHERE timestamp < '${cutoff}'`);
  db.exec(`DELETE FROM alerts WHERE timestamp < '${cutoff}'`);
  db.exec(`DELETE FROM memory_operations WHERE timestamp < '${cutoff}'`);
  // Clean up sessions with no remaining events
  db.exec(`DELETE FROM sessions WHERE id NOT IN (SELECT DISTINCT session_id FROM events) AND started_at < '${cutoff}'`);
}

// ── Session CRUD ──

export function upsertSession(info: SessionInfo) {
  const stmt = db.prepare(`
    INSERT INTO sessions (id, workspace, project_name, started_at, ended_at, total_events, danger_count, warn_count, source_tool)
    VALUES (@id, @workspace, @project_name, @started_at, @ended_at, @total_events, @danger_count, @warn_count, @source_tool)
    ON CONFLICT(id) DO UPDATE SET
      ended_at = COALESCE(@ended_at, ended_at),
      total_events = @total_events,
      danger_count = @danger_count,
      warn_count = @warn_count
  `);
  stmt.run(info);
}

export function getSession(id: string): SessionInfo | undefined {
  return db.prepare('SELECT * FROM sessions WHERE id = ?').get(id) as SessionInfo | undefined;
}

export function getAllSessions(limit = 50): SessionInfo[] {
  return db.prepare('SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?').all(limit) as SessionInfo[];
}

// ── Event CRUD ──

export function insertEvent(event: TrackerEvent): number {
  const stmt = db.prepare(`
    INSERT INTO events (session_id, timestamp, agent_id, parent_agent_id, event_type, tool_name, risk_level, summary, file_paths, command, parameters, duration_ms, raw_log, source_tool)
    VALUES (@session_id, @timestamp, @agent_id, @parent_agent_id, @event_type, @tool_name, @risk_level, @summary, @file_paths, @command, @parameters, @duration_ms, @raw_log, @source_tool)
  `);
  const result = stmt.run({
    ...event,
    file_paths: JSON.stringify(event.file_paths),
    parameters: event.parameters ? JSON.stringify(event.parameters) : null,
  });
  return Number(result.lastInsertRowid);
}

export function getSessionEvents(sessionId: string, limit = 500, offset = 0, riskFilter?: RiskLevel, typeFilter?: string): TrackerEvent[] {
  let sql = 'SELECT * FROM events WHERE session_id = ?';
  const params: unknown[] = [sessionId];
  if (riskFilter) { sql += ' AND risk_level = ?'; params.push(riskFilter); }
  if (typeFilter) { sql += ' AND event_type = ?'; params.push(typeFilter); }
  sql += ' ORDER BY timestamp ASC LIMIT ? OFFSET ?';
  params.push(limit, offset);
  const rows = db.prepare(sql).all(...params) as Array<Record<string, unknown>>;
  return rows.map(hydrateEvent);
}

export function getRecentEvents(limit = 50): TrackerEvent[] {
  const rows = db.prepare('SELECT * FROM events ORDER BY timestamp DESC LIMIT ?').all(limit) as Array<Record<string, unknown>>;
  return rows.map(hydrateEvent);
}

function hydrateEvent(row: Record<string, unknown>): TrackerEvent {
  return {
    ...row,
    file_paths: JSON.parse((row.file_paths as string) || '[]'),
    parameters: row.parameters ? JSON.parse(row.parameters as string) : null,
  } as unknown as TrackerEvent;
}

// ── Alert CRUD ──

export function insertAlert(alert: Alert): number {
  const stmt = db.prepare(`
    INSERT INTO alerts (event_id, session_id, timestamp, alert_type, severity, message, acknowledged)
    VALUES (@event_id, @session_id, @timestamp, @alert_type, @severity, @message, @acknowledged)
  `);
  const result = stmt.run({ ...alert, acknowledged: alert.acknowledged ? 1 : 0 });
  return Number(result.lastInsertRowid);
}

export function getAlerts(limit = 100, severity?: RiskLevel, sessionId?: string): Alert[] {
  let sql = 'SELECT * FROM alerts WHERE 1=1';
  const params: unknown[] = [];
  if (severity) { sql += ' AND severity = ?'; params.push(severity); }
  if (sessionId) { sql += ' AND session_id = ?'; params.push(sessionId); }
  sql += ' ORDER BY timestamp DESC LIMIT ?';
  params.push(limit);
  const rows = db.prepare(sql).all(...params) as Array<Record<string, unknown>>;
  return rows.map(r => ({ ...r, acknowledged: !!(r.acknowledged) } as unknown as Alert));
}

export function acknowledgeAlert(id: number) {
  db.prepare('UPDATE alerts SET acknowledged = 1 WHERE id = ?').run(id);
}

// ── Memory Operations ──

export function insertMemoryOp(op: MemoryOperation): number {
  const stmt = db.prepare(`
    INSERT INTO memory_operations (event_id, session_id, timestamp, operation, memory_scope, memory_path, content_summary, risk_level)
    VALUES (@event_id, @session_id, @timestamp, @operation, @memory_scope, @memory_path, @content_summary, @risk_level)
  `);
  const result = stmt.run(op);
  return Number(result.lastInsertRowid);
}

export function getMemoryOps(limit = 100, sessionId?: string): MemoryOperation[] {
  let sql = 'SELECT * FROM memory_operations WHERE 1=1';
  const params: unknown[] = [];
  if (sessionId) { sql += ' AND session_id = ?'; params.push(sessionId); }
  sql += ' ORDER BY timestamp DESC LIMIT ?';
  params.push(limit);
  return db.prepare(sql).all(...params) as MemoryOperation[];
}

// ── Stats / Queries ──

export function getStats() {
  const d = db;
  const today = new Date().toISOString().split('T')[0];

  const totalEvents = (d.prepare(`SELECT COUNT(*) as c FROM events WHERE timestamp >= ?`).get(today + 'T00:00:00') as { c: number }).c;
  const filesChanged = (d.prepare(`SELECT COUNT(DISTINCT e.id) as c FROM events e WHERE event_type IN ('file_write','file_create','file_delete') AND timestamp >= ?`).get(today + 'T00:00:00') as { c: number }).c;
  const commandsRun = (d.prepare(`SELECT COUNT(*) as c FROM events WHERE event_type IN ('terminal_command','git_commit','git_push','git_reset','git_checkout','git_operation') AND timestamp >= ?`).get(today + 'T00:00:00') as { c: number }).c;
  const alertCount = (d.prepare(`SELECT COUNT(*) as c FROM alerts WHERE timestamp >= ?`).get(today + 'T00:00:00') as { c: number }).c;
  const unreviewedAlerts = (d.prepare(`SELECT COUNT(*) as c FROM alerts WHERE acknowledged = 0`).get() as { c: number }).c;

  const riskDist = d.prepare(`
    SELECT risk_level, COUNT(*) as count FROM events WHERE timestamp >= ? GROUP BY risk_level
  `).all(today + 'T00:00:00') as Array<{ risk_level: string; count: number }>;

  const dangerCount = (d.prepare(`SELECT COUNT(*) as c FROM events WHERE risk_level = 'danger' AND timestamp >= ?`).get(today + 'T00:00:00') as { c: number }).c;
  const warnCount = (d.prepare(`SELECT COUNT(*) as c FROM events WHERE risk_level = 'warn' AND timestamp >= ?`).get(today + 'T00:00:00') as { c: number }).c;

  // Daily event counts for last 7 days
  const dailyCounts: Array<{ date: string; count: number }> = [];
  for (let i = 6; i >= 0; i--) {
    const d2 = new Date();
    d2.setDate(d2.getDate() - i);
    const dateStr = d2.toISOString().split('T')[0];
    const count = (d.prepare(`SELECT COUNT(*) as c FROM events WHERE timestamp >= ? AND timestamp < ?`).get(dateStr + 'T00:00:00', dateStr + 'T23:59:59') as { c: number }).c;
    dailyCounts.push({ date: dateStr, count });
  }

  return {
    today: { totalEvents, filesChanged, commandsRun, alertCount, unreviewedAlerts, dangerCount, warnCount },
    riskDistribution: riskDist,
    dailyCounts,
  };
}

export function getProjectStats() {
  const rows = db.prepare(`
    SELECT
      project_name,
      COUNT(*) as session_count,
      SUM(total_events) as total_events,
      SUM(danger_count) as danger_count,
      SUM(warn_count) as warn_count,
      MAX(started_at) as last_active
    FROM sessions
    GROUP BY project_name
    ORDER BY last_active DESC
  `).all() as Array<Record<string, unknown>>;
  return rows;
}

export function getLiveEvents(since: string): TrackerEvent[] {
  const rows = db.prepare('SELECT * FROM events WHERE timestamp > ? ORDER BY timestamp ASC').all(since) as Array<Record<string, unknown>>;
  return rows.map(hydrateEvent);
}

export function getAgentStats(sessionId: string): Array<{ agent_id: string; event_count: number; first_seen: string; last_seen: string }> {
  return db.prepare(`
    SELECT agent_id, COUNT(*) as event_count, MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
    FROM events WHERE session_id = ? AND agent_id != 'main' AND agent_id != 'user' AND agent_id != 'system' AND agent_id != 'assistant'
    GROUP BY agent_id ORDER BY first_seen ASC
  `).all(sessionId) as Array<{ agent_id: string; event_count: number; first_seen: string; last_seen: string }>;
}

export function getEventById(id: number): TrackerEvent | undefined {
  const row = db.prepare('SELECT * FROM events WHERE id = ?').get(id) as Record<string, unknown> | undefined;
  return row ? hydrateEvent(row) : undefined;
}

export function getEventsByFile(filePath: string, limit = 100): TrackerEvent[] {
  const rows = db.prepare(
    `SELECT * FROM events WHERE file_paths LIKE ? ORDER BY timestamp DESC LIMIT ?`
  ).all(`%${filePath}%`, limit) as Array<Record<string, unknown>>;
  return rows.map(hydrateEvent);
}

export function getSessionsByProject(projectName: string, limit = 50): SessionInfo[] {
  return db.prepare(
    'SELECT * FROM sessions WHERE project_name = ? ORDER BY started_at DESC LIMIT ?'
  ).all(projectName, limit) as SessionInfo[];
}

// ── Full-text search across events ──

export function searchEvents(query: string, limit = 100): TrackerEvent[] {
  const like = `%${query}%`;
  const rows = db.prepare(`
    SELECT * FROM events
    WHERE summary LIKE ? OR command LIKE ? OR file_paths LIKE ? OR tool_name LIKE ?
    ORDER BY timestamp DESC LIMIT ?
  `).all(like, like, like, like, limit) as Array<Record<string, unknown>>;
  return rows.map(hydrateEvent);
}

// ── Bulk acknowledge all alerts ──

export function acknowledgeAllAlerts() {
  db.prepare('UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0').run();
}

// ── Enhanced stats with session counts + time range ──

export function getStatsForRange(startDate: string, endDate: string) {
  const d = db;

  const totalEvents = (d.prepare(`SELECT COUNT(*) as c FROM events WHERE timestamp >= ? AND timestamp < ?`).get(startDate, endDate) as { c: number }).c;
  const filesChanged = (d.prepare(`SELECT COUNT(DISTINCT e.id) as c FROM events e WHERE event_type IN ('file_write','file_create','file_delete') AND timestamp >= ? AND timestamp < ?`).get(startDate, endDate) as { c: number }).c;
  const commandsRun = (d.prepare(`SELECT COUNT(*) as c FROM events WHERE event_type IN ('terminal_command','git_commit','git_push','git_reset','git_checkout','git_operation') AND timestamp >= ? AND timestamp < ?`).get(startDate, endDate) as { c: number }).c;
  const alertCount = (d.prepare(`SELECT COUNT(*) as c FROM alerts WHERE timestamp >= ? AND timestamp < ?`).get(startDate, endDate) as { c: number }).c;
  const unreviewedAlerts = (d.prepare(`SELECT COUNT(*) as c FROM alerts WHERE acknowledged = 0`).get() as { c: number }).c;
  const dangerCount = (d.prepare(`SELECT COUNT(*) as c FROM events WHERE risk_level = 'danger' AND timestamp >= ? AND timestamp < ?`).get(startDate, endDate) as { c: number }).c;
  const warnCount = (d.prepare(`SELECT COUNT(*) as c FROM events WHERE risk_level = 'warn' AND timestamp >= ? AND timestamp < ?`).get(startDate, endDate) as { c: number }).c;

  const riskDist = d.prepare(`
    SELECT risk_level, COUNT(*) as count FROM events WHERE timestamp >= ? AND timestamp < ? GROUP BY risk_level
  `).all(startDate, endDate) as Array<{ risk_level: string; count: number }>;

  const sessionCount = (d.prepare(`SELECT COUNT(*) as c FROM sessions WHERE started_at >= ? AND started_at < ?`).get(startDate, endDate) as { c: number }).c;
  const activeSessions = (d.prepare(`SELECT COUNT(*) as c FROM sessions WHERE ended_at IS NULL`).get() as { c: number }).c;

  // Top files (most events)
  const topFiles = d.prepare(`
    SELECT file_paths, COUNT(*) as hits FROM events
    WHERE timestamp >= ? AND timestamp < ? AND file_paths != '[]'
    GROUP BY file_paths ORDER BY hits DESC LIMIT 10
  `).all(startDate, endDate) as Array<{ file_paths: string; hits: number }>;

  // Top commands
  const topCommands = d.prepare(`
    SELECT command, COUNT(*) as hits FROM events
    WHERE timestamp >= ? AND timestamp < ? AND command IS NOT NULL AND command != ''
    GROUP BY command ORDER BY hits DESC LIMIT 5
  `).all(startDate, endDate) as Array<{ command: string; hits: number }>;

  return {
    today: { totalEvents, filesChanged, commandsRun, alertCount, unreviewedAlerts, dangerCount, warnCount },
    riskDistribution: riskDist,
    sessionCount,
    activeSessions,
    topFiles: topFiles.map(r => {
      try {
        const paths = JSON.parse(r.file_paths);
        return { path: Array.isArray(paths) ? paths[0] : r.file_paths, hits: r.hits };
      } catch { return { path: r.file_paths, hits: r.hits }; }
    }),
    topCommands,
  };
}

// ── Session ended_at update ──

export function markSessionEnded(sessionId: string, endedAt: string) {
  db.prepare('UPDATE sessions SET ended_at = ? WHERE id = ? AND ended_at IS NULL').run(endedAt, sessionId);
}

// ── Composite alert detection ──

export function getRecentSessionAlertBurst(sessionId: string, windowMinutes: number, threshold: number): boolean {
  const since = new Date(Date.now() - windowMinutes * 60000).toISOString();
  const count = (db.prepare(
    `SELECT COUNT(*) as c FROM alerts WHERE session_id = ? AND timestamp >= ? AND severity IN ('warn','danger')`
  ).get(sessionId, since) as { c: number }).c;
  return count >= threshold;
}
