/**
 * Export & Reporting — JSON/CSV export, incident reports, weekly summaries.
 *
 * Provides downloadable exports in multiple formats plus
 * auto-generated incident reports and weekly digest summaries.
 */

import { getDb } from '../storage/db';
import type { RiskLevel } from '../parser/event-types';

// ── Types ──

export interface IncidentReport {
  id: string;
  generatedAt: string;
  period: { start: string; end: string };
  severity: 'critical' | 'high' | 'medium';
  summary: string;
  sessions: Array<{ id: string; provider: string; project: string; dangerCount: number }>;
  dangerEvents: Array<{ timestamp: string; type: string; summary: string; risk: string; files: string[] }>;
  guardrailViolations: Array<{ timestamp: string; rule: string; message: string; blocked: boolean }>;
  recommendations: string[];
}

export interface WeeklySummary {
  period: { start: string; end: string };
  totalSessions: number;
  totalEvents: number;
  dangerEvents: number;
  warnEvents: number;
  topProjects: Array<{ name: string; events: number; dangers: number }>;
  topProviders: Array<{ name: string; sessions: number }>;
  guardrailFires: number;
  commandsBlocked: number;
  promptCount: number;
  trustChanges: Array<{ provider: string; score: number; change: number }>;
  highlights: string[];
}

// ── Export Functions ──

/** Escape a CSV cell to prevent formula injection in spreadsheet applications */
function escapeCsvCell(value: string): string {
  if (!value) return '';
  // Prefix cells starting with formula-trigger characters to neutralize them
  const first = value.charAt(0);
  if (first === '=' || first === '+' || first === '-' || first === '@' || first === '\t' || first === '\r') {
    return "'" + value;
  }
  return value;
}

/**
 * Export all events in a date range as CSV.
 */
export function exportEventsCSV(start: string, end: string, sessionId?: string): string {
  const db = getDb();
  let query = `SELECT * FROM events WHERE timestamp >= ? AND timestamp <= ?`;
  const params: unknown[] = [start, end];
  if (sessionId) {
    query += ' AND session_id = ?';
    params.push(sessionId);
  }
  query += ' ORDER BY timestamp ASC';
  const rows = db.prepare(query).all(...params) as any[];

  const headers = 'timestamp,session_id,event_type,risk_level,summary,file_paths,command,agent_id,source_tool,token_count';
  const lines = rows.map(r => {
    const files = r.file_paths || '[]';
    const summary = escapeCsvCell((r.summary || '').replace(/"/g, '""'));
    const command = escapeCsvCell((r.command || '').replace(/"/g, '""'));
    return `"${r.timestamp}","${r.session_id}","${r.event_type}","${r.risk_level}","${summary}","${files}","${command}","${r.agent_id}","${r.source_tool}",${r.token_count || 0}`;
  });

  return [headers, ...lines].join('\n');
}

/**
 * Export all events in a date range as JSON.
 */
export function exportEventsJSON(start: string, end: string, sessionId?: string): unknown[] {
  const db = getDb();
  let query = `SELECT * FROM events WHERE timestamp >= ? AND timestamp <= ?`;
  const params: unknown[] = [start, end];
  if (sessionId) {
    query += ' AND session_id = ?';
    params.push(sessionId);
  }
  query += ' ORDER BY timestamp ASC';
  const rows = db.prepare(query).all(...params) as any[];
  return rows.map(r => ({
    ...r,
    file_paths: JSON.parse(r.file_paths || '[]'),
    risk_signals: r.risk_signals ? JSON.parse(r.risk_signals) : null,
    parameters: r.parameters ? JSON.parse(r.parameters) : null,
  }));
}

/**
 * Export alerts in a date range.
 */
export function exportAlertsCSV(start: string, end: string): string {
  const db = getDb();
  const rows = db.prepare(
    'SELECT * FROM alerts WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp ASC'
  ).all(start, end) as any[];
  const headers = 'timestamp,session_id,alert_type,severity,message,acknowledged';
  const lines = rows.map(r =>
    `"${r.timestamp}","${r.session_id}","${r.alert_type}","${r.severity}","${(r.message || '').replace(/"/g, '""')}",${r.acknowledged}`
  );
  return [headers, ...lines].join('\n');
}

// ── Incident Report ──

/**
 * Generate an incident report for a date range focusing on danger-level events.
 */
export function generateIncidentReport(start: string, end: string): IncidentReport {
  const db = getDb();

  const dangerEvents = db.prepare(`
    SELECT timestamp, event_type, risk_level, summary, file_paths, command, session_id
    FROM events WHERE timestamp >= ? AND timestamp <= ? AND risk_level = 'danger'
    ORDER BY timestamp ASC
  `).all(start, end) as any[];

  const sessions = db.prepare(`
    SELECT s.id, s.source_tool as provider, s.project_name as project, s.danger_count
    FROM sessions s
    WHERE s.started_at >= ? AND (s.ended_at <= ? OR s.ended_at IS NULL)
    AND s.danger_count > 0
    ORDER BY s.danger_count DESC
  `).all(start, end) as any[];

  const violations = db.prepare(`
    SELECT timestamp, rule, message, blocked
    FROM guardrail_violations WHERE timestamp >= ? AND timestamp <= ?
    ORDER BY timestamp ASC
  `).all(start, end) as any[];

  // Generate severity assessment
  const totalDangers = dangerEvents.length;
  const severity: IncidentReport['severity'] =
    totalDangers >= 10 ? 'critical' : totalDangers >= 3 ? 'high' : 'medium';

  // Generate recommendations
  const recommendations: string[] = [];
  if (violations.filter((v: any) => v.blocked).length > 0) {
    recommendations.push('Review guardrail blocking rules — some actions were auto-blocked');
  }
  if (dangerEvents.some((e: any) => e.event_type === 'git_push')) {
    recommendations.push('Audit git push events — potential unauthorized deployments detected');
  }
  if (dangerEvents.some((e: any) => (e.summary || '').toLowerCase().includes('ssh'))) {
    recommendations.push('SSH access detected — verify authorized remote connections');
  }
  if (dangerEvents.some((e: any) => e.event_type === 'web_fetch')) {
    recommendations.push('External network calls detected — verify data exfiltration risk');
  }
  if (sessions.length > 3) {
    recommendations.push(`${sessions.length} sessions had danger events — consider tightening guardrails`);
  }
  if (recommendations.length === 0) {
    recommendations.push('No critical patterns detected in this period');
  }

  const summary = `${totalDangers} danger event(s) across ${sessions.length} session(s) in the reporting period. ` +
    `${violations.length} guardrail violation(s), ${violations.filter((v: any) => v.blocked).length} blocked.`;

  return {
    id: `report-${Date.now()}`,
    generatedAt: new Date().toISOString(),
    period: { start, end },
    severity,
    summary,
    sessions: sessions.map((s: any) => ({
      id: s.id, provider: s.provider, project: s.project, dangerCount: s.danger_count
    })),
    dangerEvents: dangerEvents.map((e: any) => ({
      timestamp: e.timestamp,
      type: e.event_type,
      summary: e.summary,
      risk: e.risk_level,
      files: JSON.parse(e.file_paths || '[]'),
    })),
    guardrailViolations: violations.map((v: any) => ({
      timestamp: v.timestamp, rule: v.rule, message: v.message, blocked: !!v.blocked,
    })),
    recommendations,
  };
}

// ── Weekly Summary ──

/**
 * Generate a weekly summary digest.
 */
export function generateWeeklySummary(weekStart?: string): WeeklySummary {
  const db = getDb();
  const start = weekStart || new Date(Date.now() - 7 * 86400_000).toISOString();
  const end = new Date().toISOString();

  const eventStats = db.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN risk_level = 'danger' THEN 1 ELSE 0 END) as dangers,
      SUM(CASE WHEN risk_level = 'warn' THEN 1 ELSE 0 END) as warns
    FROM events WHERE timestamp >= ? AND timestamp <= ?
  `).get(start, end) as any;

  const sessionCount = (db.prepare(
    'SELECT COUNT(*) as cnt FROM sessions WHERE started_at >= ? AND started_at <= ?'
  ).get(start, end) as any)?.cnt || 0;

  const topProjects = db.prepare(`
    SELECT project_name as name,
      COUNT(*) as events,
      SUM(CASE WHEN risk_level = 'danger' THEN 1 ELSE 0 END) as dangers
    FROM events e
    JOIN sessions s ON e.session_id = s.id
    WHERE e.timestamp >= ? AND e.timestamp <= ?
    GROUP BY s.project_name
    ORDER BY events DESC LIMIT 5
  `).all(start, end) as any[];

  const topProviders = db.prepare(`
    SELECT source_tool as name, COUNT(*) as sessions
    FROM sessions WHERE started_at >= ? AND started_at <= ?
    GROUP BY source_tool ORDER BY sessions DESC
  `).all(start, end) as any[];

  const guardrailFires = (db.prepare(
    'SELECT COUNT(*) as cnt FROM guardrail_violations WHERE timestamp >= ? AND timestamp <= ?'
  ).get(start, end) as any)?.cnt || 0;

  const commandsBlocked = (db.prepare(
    'SELECT COUNT(*) as cnt FROM command_queue WHERE blocked_at >= ? AND blocked_at <= ?'
  ).get(start, end) as any)?.cnt || 0;

  const promptCount = (db.prepare(
    'SELECT COUNT(*) as cnt FROM prompts WHERE timestamp >= ? AND timestamp <= ?'
  ).get(start, end) as any)?.cnt || 0;

  // Trust changes
  const trustRows = db.prepare('SELECT * FROM trust_scores').all() as any[];
  const trustChanges = trustRows.map(t => ({
    provider: t.provider,
    score: t.score,
    change: 0, // Would need historical data to compute real delta
  }));

  // Generate highlights
  const highlights: string[] = [];
  if ((eventStats?.dangers || 0) > 0) highlights.push(`⚠️ ${eventStats.dangers} danger event(s) this week`);
  if (guardrailFires > 0) highlights.push(`🚧 ${guardrailFires} guardrail violation(s)`);
  if (commandsBlocked > 0) highlights.push(`🛑 ${commandsBlocked} command(s) blocked`);
  if (promptCount > 0) highlights.push(`💬 ${promptCount} prompt(s) captured`);
  if (sessionCount > 0) highlights.push(`📋 ${sessionCount} session(s) tracked`);
  if (highlights.length === 0) highlights.push('✅ Quiet week — no significant activity');

  return {
    period: { start, end },
    totalSessions: sessionCount,
    totalEvents: eventStats?.total || 0,
    dangerEvents: eventStats?.dangers || 0,
    warnEvents: eventStats?.warns || 0,
    topProjects: topProjects || [],
    topProviders: topProviders || [],
    guardrailFires,
    commandsBlocked,
    promptCount,
    trustChanges,
    highlights,
  };
}
