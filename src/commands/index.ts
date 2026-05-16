/**
 * Command Queue — persistent blocking, editing, and re-release of AI agent commands.
 *
 * When guardrails block a command (or file op / network call), it lands here
 * as a queued entry. The user can:
 *   - View all blocked commands (persisted in DB, survives crashes)
 *   - Deny a command permanently
 *   - Approve the original command as-is
 *   - Edit the command and release the modified version
 *
 * Unlike the in-memory intervention queue (which handles real-time 30s
 * approve/deny), this is the persistent layer that keeps full history
 * and supports delayed review + modification.
 *
 * Flow:
 *   watcher → guardrails fire → queueBlockedCommand() → SSE 'command-blocked'
 *   dashboard → user reviews → approveCommand() / denyCommand() / modifyAndRelease()
 *   SSE 'command-released' fires with original or modified command
 */

import { getDb } from '../storage/db';
import type { RiskLevel } from '../parser/event-types';

// ── Types ──

export type CommandStatus = 'blocked' | 'approved' | 'denied' | 'modified' | 'expired';

export interface QueuedCommand {
  id: number;
  session_id: string;
  event_id: number;
  provider: string;
  project_name: string;
  /** What the AI tried to do: command, file, network, other */
  action_type: string;
  /** Original command/path/URL the agent tried */
  original_command: string;
  /** User-edited version (null until modified) */
  modified_command: string | null;
  /** Which guardrail rule caught it */
  rule: string;
  severity: RiskLevel;
  /** Why it was blocked */
  message: string;
  status: CommandStatus;
  blocked_at: string;
  resolved_at: string | null;
  resolved_by: string | null;
  /** User notes about why they modified/approved/denied */
  notes: string | null;
}

export interface CommandQueueStats {
  blocked: number;
  approved: number;
  denied: number;
  modified: number;
  expired: number;
  total: number;
  avgResolutionMs: number;
}

// ── DB Migration ──

export function migrateCommandQueue(): void {
  const db = getDb();
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
}

// ── Core Operations ──

const insertStmt = () => getDb().prepare(`
  INSERT INTO command_queue
    (session_id, event_id, provider, project_name, action_type, original_command,
     rule, severity, message, status, blocked_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'blocked', ?)
`);

/**
 * Queue a blocked command. Returns the new queue entry ID.
 */
export function queueBlockedCommand(params: {
  session_id: string;
  event_id: number;
  provider: string;
  project_name: string;
  action_type: string;
  original_command: string;
  rule: string;
  severity: RiskLevel;
  message: string;
}): QueuedCommand {
  const now = new Date().toISOString();
  const info = insertStmt().run(
    params.session_id, params.event_id, params.provider, params.project_name,
    params.action_type, params.original_command,
    params.rule, params.severity, params.message, now
  );
  return getCommandById(Number(info.lastInsertRowid))!;
}

/** Get a single command by ID */
export function getCommandById(id: number): QueuedCommand | null {
  return getDb().prepare('SELECT * FROM command_queue WHERE id = ?').get(id) as QueuedCommand | null;
}

/** Get all blocked (pending) commands */
export function getBlockedCommands(): QueuedCommand[] {
  return getDb().prepare(
    'SELECT * FROM command_queue WHERE status = ? ORDER BY blocked_at DESC'
  ).all('blocked') as QueuedCommand[];
}

/** Get resolved commands (approved, denied, modified, expired) */
export function getResolvedCommands(limit = 50): QueuedCommand[] {
  return getDb().prepare(
    'SELECT * FROM command_queue WHERE status != ? ORDER BY resolved_at DESC LIMIT ?'
  ).all('blocked', limit) as QueuedCommand[];
}

/** Get all commands for a session */
export function getSessionCommands(sessionId: string): QueuedCommand[] {
  return getDb().prepare(
    'SELECT * FROM command_queue WHERE session_id = ? ORDER BY blocked_at DESC'
  ).all(sessionId) as QueuedCommand[];
}

/** Get recent commands (any status) */
export function getRecentCommands(limit = 100): QueuedCommand[] {
  return getDb().prepare(
    'SELECT * FROM command_queue ORDER BY blocked_at DESC LIMIT ?'
  ).all(limit) as QueuedCommand[];
}

// ── Resolution Actions ──

/**
 * Approve a blocked command as-is. Returns the updated entry or null.
 */
export function approveCommand(id: number, resolvedBy = 'user', notes?: string): QueuedCommand | null {
  const cmd = getCommandById(id);
  if (!cmd || cmd.status !== 'blocked') return null;

  const now = new Date().toISOString();
  getDb().prepare(
    'UPDATE command_queue SET status = ?, resolved_at = ?, resolved_by = ?, notes = ? WHERE id = ?'
  ).run('approved', now, resolvedBy, notes || null, id);

  return getCommandById(id);
}

/**
 * Deny a blocked command permanently. Returns the updated entry or null.
 */
export function denyCommand(id: number, resolvedBy = 'user', notes?: string): QueuedCommand | null {
  const cmd = getCommandById(id);
  if (!cmd || cmd.status !== 'blocked') return null;

  const now = new Date().toISOString();
  getDb().prepare(
    'UPDATE command_queue SET status = ?, resolved_at = ?, resolved_by = ?, notes = ? WHERE id = ?'
  ).run('denied', now, resolvedBy, notes || null, id);

  return getCommandById(id);
}

/**
 * Edit the command and release the modified version.
 * This is the key feature — user fixes what the AI tried to do and sends it back.
 */
export function modifyAndRelease(
  id: number,
  modifiedCommand: string,
  resolvedBy = 'user',
  notes?: string
): QueuedCommand | null {
  const cmd = getCommandById(id);
  if (!cmd || cmd.status !== 'blocked') return null;

  const now = new Date().toISOString();
  getDb().prepare(
    `UPDATE command_queue
     SET status = ?, modified_command = ?, resolved_at = ?, resolved_by = ?, notes = ?
     WHERE id = ?`
  ).run('modified', modifiedCommand, now, resolvedBy, notes || null, id);

  return getCommandById(id);
}

/**
 * Deny all currently blocked commands (emergency kill-all).
 * Returns the count of commands denied.
 */
export function denyAllBlocked(resolvedBy = 'user-kill-all'): number {
  const now = new Date().toISOString();
  const info = getDb().prepare(
    'UPDATE command_queue SET status = ?, resolved_at = ?, resolved_by = ? WHERE status = ?'
  ).run('denied', now, resolvedBy, 'blocked');
  return info.changes;
}

/**
 * Expire old blocked commands that have been sitting too long.
 * Called periodically or on startup.
 */
export function expireStaleCommands(maxAgeMs = 3600_000): number {
  const cutoff = new Date(Date.now() - maxAgeMs).toISOString();
  const info = getDb().prepare(
    `UPDATE command_queue
     SET status = 'expired', resolved_at = ?, resolved_by = 'auto-expire'
     WHERE status = 'blocked' AND blocked_at < ?`
  ).run(new Date().toISOString(), cutoff);
  return info.changes;
}

// ── Stats ──

export function getCommandQueueStats(): CommandQueueStats {
  const db = getDb();
  const counts = db.prepare(`
    SELECT
      SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked,
      SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
      SUM(CASE WHEN status = 'denied' THEN 1 ELSE 0 END) as denied,
      SUM(CASE WHEN status = 'modified' THEN 1 ELSE 0 END) as modified,
      SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END) as expired,
      COUNT(*) as total
    FROM command_queue
  `).get() as any;

  // Average resolution time for user-resolved commands
  const avgRow = db.prepare(`
    SELECT AVG(
      (julianday(resolved_at) - julianday(blocked_at)) * 86400000
    ) as avg_ms
    FROM command_queue
    WHERE resolved_at IS NOT NULL AND resolved_by IN ('user', 'user-kill-all')
  `).get() as any;

  return {
    blocked: counts?.blocked || 0,
    approved: counts?.approved || 0,
    denied: counts?.denied || 0,
    modified: counts?.modified || 0,
    expired: counts?.expired || 0,
    total: counts?.total || 0,
    avgResolutionMs: Math.round(avgRow?.avg_ms || 0),
  };
}

/**
 * Get blocked commands that were pending when the app last crashed/restarted.
 * Useful for showing "these were waiting for your review when the session died".
 */
export function getOrphanedBlocked(): QueuedCommand[] {
  return getDb().prepare(
    'SELECT * FROM command_queue WHERE status = ? ORDER BY blocked_at ASC'
  ).all('blocked') as QueuedCommand[];
}
