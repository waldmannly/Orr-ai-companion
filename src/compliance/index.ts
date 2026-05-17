/**
 * Compliance Module
 * 
 * Provides tamper-evident audit logging via hash chains,
 * evidence report generation, and immutable session exports.
 */

import * as crypto from 'crypto';
import { getDb } from '../storage/db';
import { TrackerEvent, SessionInfo, Alert } from '../parser/event-types';

// ── Hash Chain (tamper-evident audit log) ──

let lastHash: string = '0000000000000000000000000000000000000000000000000000000000000000';

/**
 * Initialize chain from the last stored hash.
 */
export function initHashChain(): void {
  const db = getDb();
  const row = db.prepare('SELECT hash FROM audit_chain ORDER BY seq DESC LIMIT 1').get() as { hash: string } | undefined;
  if (row) lastHash = row.hash;
}

/**
 * Append an event to the audit chain. Returns the new hash.
 * Each entry is: SHA-256(previous_hash + event_id + timestamp + event_type + risk_level + summary)
 */
export function appendToChain(event: TrackerEvent): string {
  const db = getDb();
  const payload = `${lastHash}|${event.id}|${event.timestamp}|${event.event_type}|${event.risk_level}|${event.summary || ''}`;
  const hash = crypto.createHash('sha256').update(payload).digest('hex');

  db.prepare(`
    INSERT INTO audit_chain (event_id, hash, previous_hash, timestamp)
    VALUES (?, ?, ?, ?)
  `).run(event.id, hash, lastHash, event.timestamp);

  lastHash = hash;
  return hash;
}

/**
 * Verify the entire audit chain integrity.
 * Returns { valid: true } or { valid: false, brokenAt: seq }
 */
export function verifyChain(): { valid: boolean; brokenAt?: number; totalEntries: number } {
  const db = getDb();
  const rows = db.prepare(`
    SELECT ac.seq, ac.event_id, ac.hash, ac.previous_hash, ac.timestamp,
           e.event_type, e.risk_level, e.summary
    FROM audit_chain ac
    LEFT JOIN events e ON e.id = ac.event_id
    ORDER BY ac.seq ASC
  `).all() as Array<{
    seq: number; event_id: number; hash: string; previous_hash: string;
    timestamp: string; event_type: string; risk_level: string; summary: string;
  }>;

  if (rows.length === 0) return { valid: true, totalEntries: 0 };

  let prevHash = '0000000000000000000000000000000000000000000000000000000000000000';
  let prevSeq: number | null = null;
  for (const row of rows) {
    // Detect gaps in sequence (deleted rows)
    if (prevSeq !== null && row.seq !== prevSeq + 1) {
      return { valid: false, brokenAt: row.seq, totalEntries: rows.length };
    }
    const payload = `${prevHash}|${row.event_id}|${row.timestamp}|${row.event_type}|${row.risk_level}|${row.summary || ''}`;
    const expectedHash = crypto.createHash('sha256').update(payload).digest('hex');
    if (expectedHash !== row.hash) {
      return { valid: false, brokenAt: row.seq, totalEntries: rows.length };
    }
    if (row.previous_hash !== prevHash) {
      return { valid: false, brokenAt: row.seq, totalEntries: rows.length };
    }
    prevHash = row.hash;
    prevSeq = row.seq;
  }

  return { valid: true, totalEntries: rows.length };
}

// ── Evidence Report Generation ──

export interface EvidenceReport {
  generatedAt: string;
  period: { start: string; end: string };
  summary: {
    totalSessions: number;
    totalEvents: number;
    totalAlerts: number;
    dangerEvents: number;
    providersUsed: string[];
  };
  chainIntegrity: { valid: boolean; totalEntries: number; brokenAt?: number };
  sessions: Array<{
    id: string;
    provider: string;
    project: string;
    started: string;
    ended: string | null;
    events: number;
    dangerCount: number;
    grade: string;
  }>;
  alerts: Array<{
    timestamp: string;
    severity: string;
    type: string;
    message: string;
    sessionId: string;
    acknowledged: boolean;
  }>;
  highRiskEvents: Array<{
    timestamp: string;
    type: string;
    riskLevel: string;
    summary: string;
    sessionId: string;
    command: string | null;
    filePaths: string[];
  }>;
}

/**
 * Generate a compliance evidence report for a time window.
 */
export function generateEvidenceReport(startDate: string, endDate: string): EvidenceReport {
  const db = getDb();

  // Sessions in range
  const sessions = db.prepare(`
    SELECT * FROM sessions WHERE started_at >= ? AND started_at < ? ORDER BY started_at
  `).all(startDate, endDate) as Array<SessionInfo & { source_tool: string }>;

  // Events in range
  const eventCount = (db.prepare(`
    SELECT COUNT(*) as c FROM events WHERE timestamp >= ? AND timestamp < ?
  `).get(startDate, endDate) as { c: number }).c;

  const dangerCount = (db.prepare(`
    SELECT COUNT(*) as c FROM events WHERE timestamp >= ? AND timestamp < ? AND risk_level = 'danger'
  `).get(startDate, endDate) as { c: number }).c;

  // Alerts in range
  const alerts = db.prepare(`
    SELECT * FROM alerts WHERE timestamp >= ? AND timestamp < ? ORDER BY timestamp
  `).all(startDate, endDate) as Array<Alert>;

  // High-risk events (danger level)
  const highRisk = db.prepare(`
    SELECT * FROM events WHERE timestamp >= ? AND timestamp < ? AND risk_level = 'danger' ORDER BY timestamp LIMIT 500
  `).all(startDate, endDate) as Array<TrackerEvent & { file_paths: string }>;

  // Providers used
  const providers = [...new Set(sessions.map(s => s.source_tool))];

  // Grade calculation
  function gradeSession(s: SessionInfo): string {
    if (s.danger_count >= 5) return 'F';
    if (s.danger_count >= 3) return 'D';
    if (s.danger_count >= 1 || s.warn_count >= 10) return 'C';
    if (s.warn_count >= 3) return 'B';
    return 'A';
  }

  return {
    generatedAt: new Date().toISOString(),
    period: { start: startDate, end: endDate },
    summary: {
      totalSessions: sessions.length,
      totalEvents: eventCount,
      totalAlerts: alerts.length,
      dangerEvents: dangerCount,
      providersUsed: providers,
    },
    chainIntegrity: verifyChain(),
    sessions: sessions.map(s => ({
      id: s.id,
      provider: s.source_tool,
      project: s.project_name,
      started: s.started_at,
      ended: s.ended_at,
      events: s.total_events,
      dangerCount: s.danger_count,
      grade: gradeSession(s),
    })),
    alerts: alerts.map(a => ({
      timestamp: a.timestamp,
      severity: a.severity,
      type: a.alert_type,
      message: a.message,
      sessionId: a.session_id,
      acknowledged: a.acknowledged,
    })),
    highRiskEvents: highRisk.map(e => ({
      timestamp: e.timestamp,
      type: e.event_type,
      riskLevel: e.risk_level,
      summary: e.summary,
      sessionId: e.session_id,
      command: e.command,
      filePaths: typeof e.file_paths === 'string' ? JSON.parse(e.file_paths || '[]') : (e.file_paths || []),
    })),
  };
}

/**
 * Export a signed session transcript (all events + hash verification).
 */
export function exportSignedSession(sessionId: string): {
  session: SessionInfo | null;
  events: TrackerEvent[];
  chainHashes: string[];
  signatureHash: string;
} {
  const db = getDb();
  const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId) as SessionInfo | null;
  const events = db.prepare('SELECT * FROM events WHERE session_id = ? ORDER BY timestamp').all(sessionId) as TrackerEvent[];
  const hashes = db.prepare('SELECT hash FROM audit_chain WHERE event_id IN (SELECT id FROM events WHERE session_id = ?) ORDER BY seq')
    .all(sessionId) as Array<{ hash: string }>;

  // Generate a session-level signature hash
  const allContent = events.map(e => `${e.timestamp}|${e.event_type}|${e.risk_level}|${e.summary}`).join('\n');
  const signatureHash = crypto.createHash('sha256').update(allContent).digest('hex');

  return {
    session,
    events,
    chainHashes: hashes.map(h => h.hash),
    signatureHash,
  };
}
