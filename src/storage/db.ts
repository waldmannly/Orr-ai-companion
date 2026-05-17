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
  fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o700 });
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

  // Tailer offset persistence (avoids reprocessing files from byte 0 on restart)
  db.exec(`
    CREATE TABLE IF NOT EXISTS tailer_offsets (
      file_path TEXT PRIMARY KEY,
      byte_offset INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL
    );
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
  // Additive: risk_signals column for structured risk explanations
  try {
    db.prepare("SELECT risk_signals FROM events LIMIT 0").run();
  } catch {
    db.exec(`ALTER TABLE events ADD COLUMN risk_signals TEXT`);
  }
  // Additive: token_count on events for cost tracking
  try {
    db.prepare("SELECT token_count FROM events LIMIT 0").run();
  } catch {
    db.exec(`ALTER TABLE events ADD COLUMN token_count INTEGER`);
  }
  // Additive: anomaly_score on events
  try {
    db.prepare("SELECT anomaly_score FROM events LIMIT 0").run();
  } catch {
    db.exec(`ALTER TABLE events ADD COLUMN anomaly_score REAL`);
  }
  // Additive: token_count on sessions
  try {
    db.prepare("SELECT token_count FROM sessions LIMIT 0").run();
  } catch {
    db.exec(`ALTER TABLE sessions ADD COLUMN token_count INTEGER NOT NULL DEFAULT 0`);
  }
  // Baselines table
  db.exec(`
    CREATE TABLE IF NOT EXISTS baselines (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      project_name TEXT NOT NULL,
      metric TEXT NOT NULL,
      value REAL NOT NULL,
      sample_count INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL,
      UNIQUE(project_name, metric)
    );
    CREATE INDEX IF NOT EXISTS idx_baselines_project ON baselines(project_name);
  `);

  // Trust scores table
  db.exec(`
    CREATE TABLE IF NOT EXISTS trust_scores (
      provider TEXT PRIMARY KEY,
      score REAL NOT NULL DEFAULT 85,
      total_sessions INTEGER NOT NULL DEFAULT 0,
      clean_sessions INTEGER NOT NULL DEFAULT 0,
      incidents INTEGER NOT NULL DEFAULT 0,
      last_updated TEXT NOT NULL
    );
  `);

  // Audit chain table (hash chain for compliance)
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_chain (
      seq INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id INTEGER NOT NULL,
      hash TEXT NOT NULL,
      previous_hash TEXT NOT NULL,
      timestamp TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_chain_event ON audit_chain(event_id);
  `);

  // Guardrail violations table
  db.exec(`
    CREATE TABLE IF NOT EXISTS guardrail_violations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id INTEGER,
      session_id TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      rule TEXT NOT NULL,
      severity TEXT NOT NULL,
      message TEXT NOT NULL,
      blocked INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_guardrail_session ON guardrail_violations(session_id);
  `);

  // Additive: git_branch on sessions
  try {
    db.prepare("SELECT git_branch FROM sessions LIMIT 0").run();
  } catch {
    db.exec(`ALTER TABLE sessions ADD COLUMN git_branch TEXT`);
  }

  // Session linking: task_group for linking related sessions
  try {
    db.prepare("SELECT task_group FROM sessions LIMIT 0").run();
  } catch {
    db.exec(`ALTER TABLE sessions ADD COLUMN task_group TEXT`);
    // Auto-populate task_group from project+branch for existing sessions
    db.exec(`UPDATE sessions SET task_group = project_name || ':' || COALESCE(git_branch, 'default') WHERE task_group IS NULL AND project_name != ''`);
  }

  // One-time dedup cleanup (tracked by pragma so it only runs once)
  const dedupDone = db.pragma('user_version', { simple: true }) as number;
  if (dedupDone < 2) {
    db.exec(`
      DELETE FROM events WHERE id NOT IN (
        SELECT MIN(id) FROM events GROUP BY session_id, timestamp, event_type, summary
      )
    `);
    db.exec(`
      DELETE FROM alerts WHERE id NOT IN (
        SELECT MIN(id) FROM alerts GROUP BY session_id, timestamp, alert_type, message
      )
    `);
    // Auto-acknowledge old noisy alerts (historical cleanup)
    db.exec(`UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0`);
    db.pragma('user_version = 2');
  }

  // Unique indexes for dedup (prevents duplicate events/alerts across restarts)
  // Must run AFTER dedup cleanup above so existing duplicates don't block index creation
  db.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_events_dedup ON events(session_id, timestamp, event_type, summary);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(session_id, timestamp, alert_type, message);
  `);

  // Prompts table for full untruncated prompt history
  db.exec(`
    CREATE TABLE IF NOT EXISTS prompts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id INTEGER NOT NULL,
      session_id TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      content TEXT NOT NULL,
      provider TEXT NOT NULL DEFAULT '',
      project_name TEXT NOT NULL DEFAULT '',
      token_count INTEGER NOT NULL DEFAULT 0,
      seq INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_prompts_session ON prompts(session_id);
    CREATE INDEX IF NOT EXISTS idx_prompts_timestamp ON prompts(timestamp);
    CREATE INDEX IF NOT EXISTS idx_prompts_event ON prompts(event_id);
  `);

  // Command queue for persistent blocked command tracking
  db.exec(`
    CREATE TABLE IF NOT EXISTS command_queue (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      event_id INTEGER NOT NULL,
      provider TEXT NOT NULL DEFAULT '',
      project_name TEXT NOT NULL DEFAULT '',
      action_type TEXT NOT NULL DEFAULT 'command',
      original_command TEXT NOT NULL,
      modified_command TEXT,
      rule TEXT NOT NULL,
      severity TEXT NOT NULL,
      message TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'blocked',
      blocked_at TEXT NOT NULL,
      resolved_at TEXT,
      resolved_by TEXT,
      notes TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_cmdq_session ON command_queue(session_id);
    CREATE INDEX IF NOT EXISTS idx_cmdq_status ON command_queue(status);
    CREATE INDEX IF NOT EXISTS idx_cmdq_blocked_at ON command_queue(blocked_at);
  `);

  // Agent hierarchy / sub-agent authority
  db.exec(`
    CREATE TABLE IF NOT EXISTS agent_nodes (
      id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      parent_id TEXT,
      provider TEXT NOT NULL DEFAULT '',
      allowed_scopes TEXT NOT NULL DEFAULT '[]',
      denied_scopes TEXT NOT NULL DEFAULT '[]',
      trust_level TEXT NOT NULL DEFAULT 'limited',
      created_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      event_count INTEGER NOT NULL DEFAULT 0,
      danger_count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (id, session_id)
    );
    CREATE INDEX IF NOT EXISTS idx_agents_session ON agent_nodes(session_id);
    CREATE INDEX IF NOT EXISTS idx_agents_parent ON agent_nodes(parent_id);

    CREATE TABLE IF NOT EXISTS delegation_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      parent_agent_id TEXT NOT NULL,
      child_agent_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      delegated_scopes TEXT NOT NULL DEFAULT '[]',
      timestamp TEXT NOT NULL,
      reason TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_deleg_session ON delegation_records(session_id);

    CREATE TABLE IF NOT EXISTS authority_violations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      violation_type TEXT NOT NULL,
      message TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'warn'
    );
    CREATE INDEX IF NOT EXISTS idx_authviol_session ON authority_violations(session_id);
  `);

  // Team / multi-user
  db.exec(`
    CREATE TABLE IF NOT EXISTS team_users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'viewer',
      api_key_hash TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      last_seen_at TEXT,
      active INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS shared_rules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      pattern TEXT NOT NULL,
      is_regex INTEGER NOT NULL DEFAULT 0,
      severity TEXT NOT NULL DEFAULT 'warn',
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS team_activity (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      action TEXT NOT NULL,
      detail TEXT,
      timestamp TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_team_activity_ts ON team_activity(timestamp);
  `);

  // Automated response actions
  db.exec(`
    CREATE TABLE IF NOT EXISTS auto_actions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      action_type TEXT NOT NULL,
      reason TEXT NOT NULL,
      trigger_event_id INTEGER,
      reversed INTEGER NOT NULL DEFAULT 0,
      reversed_at TEXT,
      reversed_by TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_autoact_session ON auto_actions(session_id);
    CREATE INDEX IF NOT EXISTS idx_autoact_type ON auto_actions(action_type);
  `);

  // Policy engine tables
  db.exec(`
    CREATE TABLE IF NOT EXISTS org_policies (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      org_id TEXT NOT NULL,
      org_name TEXT NOT NULL,
      version INTEGER NOT NULL,
      tier TEXT NOT NULL,
      policy_json TEXT NOT NULL,
      applied_at TEXT NOT NULL,
      applied_by TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_orgpol_orgid ON org_policies(org_id);

    CREATE TABLE IF NOT EXISTS policy_violations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      session_id TEXT,
      user_id TEXT,
      rule_id TEXT NOT NULL,
      rule_name TEXT NOT NULL,
      category TEXT NOT NULL,
      enforcement TEXT NOT NULL,
      detail TEXT NOT NULL,
      resolved INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_polviol_ts ON policy_violations(timestamp);
    CREATE INDEX IF NOT EXISTS idx_polviol_cat ON policy_violations(category);

    CREATE TABLE IF NOT EXISTS policy_metrics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      metric_name TEXT NOT NULL,
      metric_value TEXT NOT NULL,
      session_id TEXT,
      metadata TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_polmet_name ON policy_metrics(metric_name);
    CREATE INDEX IF NOT EXISTS idx_polmet_ts ON policy_metrics(timestamp);
  `);

  // Session kill tracking
  try {
    db.prepare("SELECT killed_at FROM sessions LIMIT 0").run();
  } catch {
    db.exec(`ALTER TABLE sessions ADD COLUMN killed_at TEXT`);
    db.exec(`ALTER TABLE sessions ADD COLUMN kill_reason TEXT`);
  }

  // Daily token usage tracking
  db.exec(`
    CREATE TABLE IF NOT EXISTS daily_token_usage (
      date TEXT NOT NULL,
      session_id TEXT NOT NULL,
      tokens INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (date, session_id)
    );
    CREATE INDEX IF NOT EXISTS idx_daily_tokens_date ON daily_token_usage(date);
  `);
}

// ── Storage maintenance ──

export function vacuumDb(): { before: number; after: number } {
  const dbPath = db.name;
  const before = fs.statSync(dbPath).size;
  db.pragma('wal_checkpoint(TRUNCATE)');
  db.exec('VACUUM');
  const after = fs.statSync(dbPath).size;
  return { before, after };
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

  // Auto-set task_group if not set (links sessions by project+branch)
  const session = db.prepare('SELECT task_group, git_branch FROM sessions WHERE id = ?').get(info.id) as any;
  if (!session?.task_group && info.project_name) {
    const branch = session?.git_branch || 'default';
    db.prepare('UPDATE sessions SET task_group = ? WHERE id = ? AND (task_group IS NULL OR task_group = \'\')').run(
      `${info.project_name}:${branch}`, info.id
    );
  }
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
    INSERT OR IGNORE INTO events (session_id, timestamp, agent_id, parent_agent_id, event_type, tool_name, risk_level, summary, file_paths, command, parameters, duration_ms, raw_log, source_tool, risk_signals, token_count, anomaly_score)
    VALUES (@session_id, @timestamp, @agent_id, @parent_agent_id, @event_type, @tool_name, @risk_level, @summary, @file_paths, @command, @parameters, @duration_ms, @raw_log, @source_tool, @risk_signals, @token_count, @anomaly_score)
  `);
  const result = stmt.run({
    ...event,
    file_paths: JSON.stringify(event.file_paths),
    parameters: event.parameters ? JSON.stringify(event.parameters) : null,
    risk_signals: (event as any).risk_signals ? JSON.stringify((event as any).risk_signals) : null,
    token_count: event.token_count ?? null,
    anomaly_score: event.anomaly_score ?? null,
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
    risk_signals: row.risk_signals ? JSON.parse(row.risk_signals as string) : null,
  } as unknown as TrackerEvent;
}

// ── Alert CRUD ──

export function insertAlert(alert: Alert): number {
  const stmt = db.prepare(`
    INSERT OR IGNORE INTO alerts (event_id, session_id, timestamp, alert_type, severity, message, acknowledged)
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

// ── Session kill tracking ──

export function markSessionKilled(sessionId: string, reason: string): void {
  const now = new Date().toISOString();
  db.prepare('UPDATE sessions SET killed_at = ?, kill_reason = ?, ended_at = COALESCE(ended_at, ?) WHERE id = ?')
    .run(now, reason, now, sessionId);
}

export function isSessionKilledInDb(sessionId: string): boolean {
  const row = db.prepare('SELECT killed_at FROM sessions WHERE id = ?').get(sessionId) as { killed_at: string | null } | undefined;
  return !!row?.killed_at;
}

export function getKilledSessions(): Array<{ id: string; project_name: string; killed_at: string; kill_reason: string }> {
  return db.prepare('SELECT id, project_name, killed_at, kill_reason FROM sessions WHERE killed_at IS NOT NULL ORDER BY killed_at DESC')
    .all() as Array<{ id: string; project_name: string; killed_at: string; kill_reason: string }>;
}

// ── Daily token usage ──

export function addDailyTokens(sessionId: string, tokens: number): void {
  const date = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  db.prepare(`
    INSERT INTO daily_token_usage (date, session_id, tokens) VALUES (?, ?, ?)
    ON CONFLICT(date, session_id) DO UPDATE SET tokens = tokens + excluded.tokens
  `).run(date, sessionId, tokens);
}

export function getDailyTokenTotal(): number {
  const date = new Date().toISOString().slice(0, 10);
  const row = db.prepare('SELECT SUM(tokens) as total FROM daily_token_usage WHERE date = ?').get(date) as { total: number | null };
  return row?.total || 0;
}

// ── Composite alert detection ──

export function getRecentSessionAlertBurst(sessionId: string, windowMinutes: number, threshold: number): boolean {
  const since = new Date(Date.now() - windowMinutes * 60000).toISOString();
  const count = (db.prepare(
    `SELECT COUNT(*) as c FROM alerts WHERE session_id = ? AND timestamp >= ? AND severity IN ('warn','danger')`
  ).get(sessionId, since) as { c: number }).c;
  return count >= threshold;
}

// ── Baselines ──

export function upsertBaseline(projectName: string, metric: string, value: number, sampleCount: number) {
  db.prepare(`
    INSERT INTO baselines (project_name, metric, value, sample_count, updated_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(project_name, metric) DO UPDATE SET
      value = (value * sample_count + ?) / (sample_count + 1),
      sample_count = sample_count + 1,
      updated_at = ?
  `).run(projectName, metric, value, sampleCount, new Date().toISOString(), value, new Date().toISOString());
}

export function getBaseline(projectName: string, metric: string): { value: number; sample_count: number } | undefined {
  return db.prepare('SELECT value, sample_count FROM baselines WHERE project_name = ? AND metric = ?')
    .get(projectName, metric) as { value: number; sample_count: number } | undefined;
}

export function getAllBaselines(projectName: string): Array<{ metric: string; value: number; sample_count: number }> {
  return db.prepare('SELECT metric, value, sample_count FROM baselines WHERE project_name = ? ORDER BY metric')
    .all(projectName) as Array<{ metric: string; value: number; sample_count: number }>;
}

// ── Token tracking ──

export function getSessionTokens(sessionId: string): number {
  const row = db.prepare('SELECT COALESCE(SUM(token_count), 0) as total FROM events WHERE session_id = ? AND token_count IS NOT NULL')
    .get(sessionId) as { total: number };
  return row.total;
}

export function getProjectTokens(projectName: string): number {
  const row = db.prepare(`
    SELECT COALESCE(SUM(e.token_count), 0) as total FROM events e
    JOIN sessions s ON e.session_id = s.id
    WHERE s.project_name = ? AND e.token_count IS NOT NULL
  `).get(projectName) as { total: number };
  return row.total;
}

// ── Memory lineage ──

export function getMemoryLineage(memoryPath: string): MemoryOperation[] {
  return db.prepare(
    'SELECT * FROM memory_operations WHERE memory_path = ? ORDER BY timestamp ASC'
  ).all(memoryPath) as MemoryOperation[];
}

export function getMemoryHealth(): Array<{ memory_path: string; scope: string; write_count: number; read_count: number; last_write: string; sessions: number; risk: string }> {
  return db.prepare(`
    SELECT
      memory_path,
      memory_scope as scope,
      SUM(CASE WHEN operation = 'write' THEN 1 ELSE 0 END) as write_count,
      SUM(CASE WHEN operation = 'read' THEN 1 ELSE 0 END) as read_count,
      MAX(CASE WHEN operation = 'write' THEN timestamp ELSE NULL END) as last_write,
      COUNT(DISTINCT session_id) as sessions,
      MAX(risk_level) as risk
    FROM memory_operations
    GROUP BY memory_path
    ORDER BY last_write DESC
  `).all() as Array<{ memory_path: string; scope: string; write_count: number; read_count: number; last_write: string; sessions: number; risk: string }>;
}

// ── Advanced event queries with date range ──

export function getEventsFiltered(opts: {
  sessionId?: string; startDate?: string; endDate?: string;
  riskLevel?: string; eventType?: string; search?: string;
  limit?: number; offset?: number;
}): TrackerEvent[] {
  let sql = 'SELECT * FROM events WHERE 1=1';
  const params: unknown[] = [];
  if (opts.sessionId) { sql += ' AND session_id = ?'; params.push(opts.sessionId); }
  if (opts.startDate) { sql += ' AND timestamp >= ?'; params.push(opts.startDate); }
  if (opts.endDate) { sql += ' AND timestamp < ?'; params.push(opts.endDate); }
  if (opts.riskLevel) { sql += ' AND risk_level = ?'; params.push(opts.riskLevel); }
  if (opts.eventType) { sql += ' AND event_type = ?'; params.push(opts.eventType); }
  if (opts.search) { const like = `%${opts.search}%`; sql += ' AND (summary LIKE ? OR command LIKE ? OR file_paths LIKE ?)'; params.push(like, like, like); }
  sql += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
  params.push(opts.limit || 200, opts.offset || 0);
  return (db.prepare(sql).all(...params) as Array<Record<string, unknown>>).map(hydrateEvent);
}

// ── Computed metrics ──

export function getSessionHealthMetrics(sessionId: string): {
  totalEvents: number; dangerCount: number; warnCount: number;
  tokenCount: number; durationMinutes: number; eventsPerMinute: number;
  grade: string; riskVelocity: number;
} {
  const session = getSession(sessionId);
  if (!session) return { totalEvents: 0, dangerCount: 0, warnCount: 0, tokenCount: 0, durationMinutes: 0, eventsPerMinute: 0, grade: 'A', riskVelocity: 0 };

  const tokens = getSessionTokens(sessionId);
  const start = new Date(session.started_at).getTime();
  const end = session.ended_at ? new Date(session.ended_at).getTime() : Date.now();
  const durationMinutes = Math.max(1, (end - start) / 60000);
  const eventsPerMinute = session.total_events / durationMinutes;
  const riskVelocity = (session.danger_count * 3 + session.warn_count) / durationMinutes;

  // Grade: A-F based on risk signals
  let grade = 'A';
  if (session.danger_count >= 5) grade = 'F';
  else if (session.danger_count >= 3) grade = 'D';
  else if (session.danger_count >= 1 || session.warn_count >= 10) grade = 'C';
  else if (session.warn_count >= 3) grade = 'B';

  return {
    totalEvents: session.total_events,
    dangerCount: session.danger_count,
    warnCount: session.warn_count,
    tokenCount: tokens,
    durationMinutes: Math.round(durationMinutes),
    eventsPerMinute: Math.round(eventsPerMinute * 10) / 10,
    grade,
    riskVelocity: Math.round(riskVelocity * 100) / 100,
  };
}

export function getGlobalMetrics(): {
  totalSessions: number; totalEvents: number; totalAlerts: number;
  unreviewedAlerts: number; acknowledgedAlerts: number; alertFatigueIndex: number;
  avgTimeToFirstDanger: number; projectsCovered: number;
} {
  const d = db;
  const totalSessions = (d.prepare('SELECT COUNT(*) as c FROM sessions').get() as { c: number }).c;
  const totalEvents = (d.prepare('SELECT COUNT(*) as c FROM events').get() as { c: number }).c;
  const totalAlerts = (d.prepare('SELECT COUNT(*) as c FROM alerts').get() as { c: number }).c;
  const unreviewedAlerts = (d.prepare('SELECT COUNT(*) as c FROM alerts WHERE acknowledged = 0').get() as { c: number }).c;
  const acknowledgedAlerts = (d.prepare('SELECT COUNT(*) as c FROM alerts WHERE acknowledged = 1').get() as { c: number }).c;
  const alertFatigueIndex = totalAlerts > 0 ? Math.round((unreviewedAlerts / totalAlerts) * 100) : 0;
  const projectsCovered = (d.prepare('SELECT COUNT(DISTINCT project_name) as c FROM sessions').get() as { c: number }).c;

  // Average time from session start to first danger event (in minutes)
  const avgRow = d.prepare(`
    SELECT AVG(diff) as avg_diff FROM (
      SELECT MIN((julianday(e.timestamp) - julianday(s.started_at)) * 1440) as diff
      FROM events e JOIN sessions s ON e.session_id = s.id
      WHERE e.risk_level = 'danger'
      GROUP BY e.session_id
    )
  `).get() as { avg_diff: number | null };

  return {
    totalSessions, totalEvents, totalAlerts,
    unreviewedAlerts, acknowledgedAlerts, alertFatigueIndex,
    avgTimeToFirstDanger: Math.round(avgRow.avg_diff || 0),
    projectsCovered,
  };
}

// ── Guardrail violations ──

export function insertGuardrailViolation(v: {
  event_id: number | null; session_id: string; timestamp: string;
  rule: string; severity: string; message: string; blocked: boolean;
}): void {
  db.prepare(`
    INSERT INTO guardrail_violations (event_id, session_id, timestamp, rule, severity, message, blocked)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(v.event_id, v.session_id, v.timestamp, v.rule, v.severity, v.message, v.blocked ? 1 : 0);
}

export function getGuardrailViolations(sessionId?: string, limit = 100): Array<{
  id: number; event_id: number; session_id: string; timestamp: string;
  rule: string; severity: string; message: string; blocked: boolean;
}> {
  let sql = 'SELECT * FROM guardrail_violations';
  const params: unknown[] = [];
  if (sessionId) { sql += ' WHERE session_id = ?'; params.push(sessionId); }
  sql += ' ORDER BY timestamp DESC LIMIT ?';
  params.push(limit);
  return (db.prepare(sql).all(...params) as Array<Record<string, unknown>>).map(r => ({
    id: r.id as number, event_id: r.event_id as number, session_id: r.session_id as string,
    timestamp: r.timestamp as string, rule: r.rule as string, severity: r.severity as string,
    message: r.message as string, blocked: r.blocked === 1,
  }));
}

// ── Branch/PR linking ──

export function setSessionBranch(sessionId: string, branch: string): void {
  db.prepare('UPDATE sessions SET git_branch = ? WHERE id = ?').run(branch, sessionId);
}

export function getSessionsByBranch(branch: string): SessionInfo[] {
  return db.prepare('SELECT * FROM sessions WHERE git_branch = ? ORDER BY started_at DESC')
    .all(branch) as SessionInfo[];
}

export function getBranchSummary(branch: string): {
  sessions: number; totalEvents: number; dangerCount: number; warnCount: number;
  providers: string[]; firstSession: string | null; lastSession: string | null;
} {
  const sessions = db.prepare('SELECT * FROM sessions WHERE git_branch = ?').all(branch) as SessionInfo[];
  const providers = [...new Set(sessions.map(s => s.source_tool))];
  return {
    sessions: sessions.length,
    totalEvents: sessions.reduce((a, s) => a + s.total_events, 0),
    dangerCount: sessions.reduce((a, s) => a + s.danger_count, 0),
    warnCount: sessions.reduce((a, s) => a + s.warn_count, 0),
    providers,
    firstSession: sessions.length > 0 ? sessions[sessions.length - 1].started_at : null,
    lastSession: sessions.length > 0 ? sessions[0].started_at : null,
  };
}

// ── IDE API helpers ──

export function getActiveSessionStatus(): {
  sessionId: string | null; provider: string; grade: string;
  eventsLastMinute: number; dangerCount: number; tokenUsage: number;
} {
  const cutoff = new Date(Date.now() - 5 * 60000).toISOString();
  const session = db.prepare(`
    SELECT * FROM sessions WHERE ended_at IS NULL OR ended_at > ? ORDER BY started_at DESC LIMIT 1
  `).get(cutoff) as SessionInfo | undefined;

  if (!session) {
    return { sessionId: null, provider: 'none', grade: 'A', eventsLastMinute: 0, dangerCount: 0, tokenUsage: 0 };
  }

  const oneMinAgo = new Date(Date.now() - 60000).toISOString();
  const eventsLastMinute = (db.prepare(
    'SELECT COUNT(*) as c FROM events WHERE session_id = ? AND timestamp > ?'
  ).get(session.id, oneMinAgo) as { c: number }).c;

  const tokens = getSessionTokens(session.id);
  const health = getSessionHealthMetrics(session.id);

  return {
    sessionId: session.id,
    provider: session.source_tool,
    grade: health.grade,
    eventsLastMinute,
    dangerCount: session.danger_count,
    tokenUsage: tokens,
  };
}

export function getFileActivity(filePath: string, limit = 50): Array<{
  timestamp: string; event_type: string; risk_level: string;
  summary: string; session_id: string; provider: string;
}> {
  const like = `%${filePath.replace(/\\/g, '/')}%`;
  return db.prepare(`
    SELECT e.timestamp, e.event_type, e.risk_level, e.summary, e.session_id, s.source_tool as provider
    FROM events e
    LEFT JOIN sessions s ON e.session_id = s.id
    WHERE e.file_paths LIKE ?
    ORDER BY e.timestamp DESC LIMIT ?
  `).all(like, limit) as Array<{
    timestamp: string; event_type: string; risk_level: string;
    summary: string; session_id: string; provider: string;
  }>;
}

// ── Session Linking ──

export function setSessionTaskGroup(sessionId: string, taskGroup: string) {
  db.prepare('UPDATE sessions SET task_group = ? WHERE id = ?').run(taskGroup, sessionId);
}

export function getLinkedSessions(taskGroup: string): SessionInfo[] {
  return db.prepare(
    'SELECT * FROM sessions WHERE task_group = ? ORDER BY started_at DESC'
  ).all(taskGroup) as SessionInfo[];
}

export function getTaskGroups(limit = 50): Array<{
  task_group: string; session_count: number; total_events: number;
  danger_count: number; first_session: string; last_session: string;
  project_name: string; git_branch: string | null;
}> {
  return db.prepare(`
    SELECT task_group, COUNT(*) as session_count,
      SUM(total_events) as total_events, SUM(danger_count) as danger_count,
      MIN(started_at) as first_session, MAX(started_at) as last_session,
      project_name, git_branch
    FROM sessions
    WHERE task_group IS NOT NULL AND task_group != ''
    GROUP BY task_group
    ORDER BY last_session DESC
    LIMIT ?
  `).all(limit) as Array<{
    task_group: string; session_count: number; total_events: number;
    danger_count: number; first_session: string; last_session: string;
    project_name: string; git_branch: string | null;
  }>;
}

export function getBranchActivitySummary(projectName: string, branch: string): {
  sessions: SessionInfo[];
  totalEvents: number;
  dangerEvents: number;
  providers: string[];
  timespan: { first: string; last: string };
  topRisks: Array<{ event_type: string; risk_level: string; summary: string; timestamp: string }>;
} {
  const sessions = db.prepare(
    `SELECT * FROM sessions WHERE project_name = ? AND git_branch = ? ORDER BY started_at DESC`
  ).all(projectName, branch) as SessionInfo[];

  const sessionIds = sessions.map(s => s.id);
  if (!sessionIds.length) {
    return { sessions: [], totalEvents: 0, dangerEvents: 0, providers: [], timespan: { first: '', last: '' }, topRisks: [] };
  }

  const placeholders = sessionIds.map(() => '?').join(',');
  const totalEvents = (db.prepare(
    `SELECT COUNT(*) as c FROM events WHERE session_id IN (${placeholders})`
  ).get(...sessionIds) as { c: number }).c;

  const dangerEvents = (db.prepare(
    `SELECT COUNT(*) as c FROM events WHERE session_id IN (${placeholders}) AND risk_level = 'danger'`
  ).get(...sessionIds) as { c: number }).c;

  const providers = [...new Set(sessions.map(s => s.source_tool))];

  const topRisks = db.prepare(`
    SELECT event_type, risk_level, summary, timestamp FROM events
    WHERE session_id IN (${placeholders}) AND risk_level IN ('warn', 'danger')
    ORDER BY timestamp DESC LIMIT 20
  `).all(...sessionIds) as Array<{ event_type: string; risk_level: string; summary: string; timestamp: string }>;

  return {
    sessions,
    totalEvents,
    dangerEvents,
    providers,
    timespan: {
      first: sessions[sessions.length - 1]?.started_at || '',
      last: sessions[0]?.started_at || '',
    },
    topRisks,
  };
}

// ── Tailer Offset Persistence ──

export function getTailerOffset(filePath: string): number {
  const row = db.prepare('SELECT byte_offset FROM tailer_offsets WHERE file_path = ?').get(filePath) as { byte_offset: number } | undefined;
  return row?.byte_offset ?? 0;
}

export function setTailerOffset(filePath: string, offset: number): void {
  db.prepare(`
    INSERT INTO tailer_offsets (file_path, byte_offset, updated_at)
    VALUES (?, ?, ?)
    ON CONFLICT(file_path) DO UPDATE SET byte_offset = excluded.byte_offset, updated_at = excluded.updated_at
  `).run(filePath, offset, new Date().toISOString());
}
