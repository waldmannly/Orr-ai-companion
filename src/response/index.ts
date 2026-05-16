/**
 * Automated Response — kill terminal, block writes, pause agent (opt-in only).
 *
 * When guardrails or trust scores cross thresholds, this module can
 * take automated actions:
 *   - Kill an active terminal session (via tracked process)
 *   - Block file writes by creating intervention barriers
 *   - Pause agent activity (stop processing new events until resumed)
 *
 * ALL actions are opt-in and require explicit configuration.
 * The system logs every automated action for audit purposes.
 */

import { getDb } from '../storage/db';
import type { RiskLevel } from '../parser/event-types';

// ── Types ──

export interface AutoResponseConfig {
  enabled: boolean;
  /** Auto-kill terminal on danger command detection */
  killOnDanger: boolean;
  /** Auto-block file writes when trust score drops below threshold */
  blockWritesBelowTrust: number; // 0 = disabled, e.g. 40 = block if trust < 40
  /** Pause agent when danger event count in session exceeds threshold */
  pauseAfterDangers: number; // 0 = disabled, e.g. 5 = pause after 5 danger events
  /** Sessions currently paused */
  pausedSessions: string[];
}

export interface AutoAction {
  id: number;
  session_id: string;
  timestamp: string;
  action_type: 'kill_terminal' | 'block_writes' | 'pause_session' | 'resume_session';
  reason: string;
  trigger_event_id: number | null;
  reversed: boolean;
  reversed_at: string | null;
  reversed_by: string | null;
}

export interface AutoResponseStats {
  totalActions: number;
  killActions: number;
  blockActions: number;
  pauseActions: number;
  reversedActions: number;
  activePauses: number;
}

// ── Config ──

const DEFAULT_CONFIG: AutoResponseConfig = {
  enabled: false,
  killOnDanger: false,
  blockWritesBelowTrust: 0,
  pauseAfterDangers: 0,
  pausedSessions: [],
};

let config: AutoResponseConfig = { ...DEFAULT_CONFIG };

export function getAutoResponseConfig(): AutoResponseConfig {
  return { ...config };
}

export function updateAutoResponseConfig(updates: Partial<AutoResponseConfig>): AutoResponseConfig {
  config = { ...config, ...updates };
  return { ...config };
}

// ── DB Migration ──

export function migrateAutoResponse(): void {
  const db = getDb();
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
}

// ── Action Logging ──

function logAction(params: {
  session_id: string;
  action_type: AutoAction['action_type'];
  reason: string;
  trigger_event_id?: number;
}): AutoAction {
  const now = new Date().toISOString();
  const info = getDb().prepare(`
    INSERT INTO auto_actions (session_id, timestamp, action_type, reason, trigger_event_id)
    VALUES (?, ?, ?, ?, ?)
  `).run(params.session_id, now, params.action_type, params.reason, params.trigger_event_id || null);
  return getDb().prepare('SELECT * FROM auto_actions WHERE id = ?')
    .get(Number(info.lastInsertRowid)) as AutoAction;
}

// ── Core Actions ──

/**
 * Evaluate whether an automated response should fire for a given event.
 * Returns the actions taken (may be empty).
 */
export function evaluateAutoResponse(params: {
  session_id: string;
  event_id: number;
  event_type: string;
  risk_level: RiskLevel;
  danger_count: number;
  trust_score?: number;
}): AutoAction[] {
  if (!config.enabled) return [];

  const actions: AutoAction[] = [];

  // Kill terminal on danger command
  if (config.killOnDanger && params.risk_level === 'danger' && params.event_type === 'terminal_command') {
    actions.push(logAction({
      session_id: params.session_id,
      action_type: 'kill_terminal',
      reason: `Danger-level terminal command detected (event #${params.event_id})`,
      trigger_event_id: params.event_id,
    }));
  }

  // Block writes when trust is low
  if (config.blockWritesBelowTrust > 0 && params.trust_score !== undefined
    && params.trust_score < config.blockWritesBelowTrust
    && (params.event_type === 'file_write' || params.event_type === 'file_create')) {
    actions.push(logAction({
      session_id: params.session_id,
      action_type: 'block_writes',
      reason: `Trust score (${params.trust_score}) below threshold (${config.blockWritesBelowTrust})`,
      trigger_event_id: params.event_id,
    }));
  }

  // Pause after N danger events
  if (config.pauseAfterDangers > 0 && params.danger_count >= config.pauseAfterDangers
    && !config.pausedSessions.includes(params.session_id)) {
    config.pausedSessions.push(params.session_id);
    actions.push(logAction({
      session_id: params.session_id,
      action_type: 'pause_session',
      reason: `${params.danger_count} danger events exceeded threshold (${config.pauseAfterDangers})`,
      trigger_event_id: params.event_id,
    }));
  }

  return actions;
}

/** Check if a session is paused */
export function isSessionPaused(sessionId: string): boolean {
  return config.pausedSessions.includes(sessionId);
}

/** Manually pause a session */
export function pauseSession(sessionId: string, reason = 'Manual pause'): AutoAction {
  if (!config.pausedSessions.includes(sessionId)) {
    config.pausedSessions.push(sessionId);
  }
  return logAction({ session_id: sessionId, action_type: 'pause_session', reason });
}

/** Resume a paused session */
export function resumeSession(sessionId: string, resumedBy = 'user'): AutoAction | null {
  const idx = config.pausedSessions.indexOf(sessionId);
  if (idx === -1) return null;
  config.pausedSessions.splice(idx, 1);

  const action = logAction({
    session_id: sessionId,
    action_type: 'resume_session',
    reason: `Resumed by ${resumedBy}`,
  });

  // Mark the original pause action as reversed
  getDb().prepare(`
    UPDATE auto_actions SET reversed = 1, reversed_at = ?, reversed_by = ?
    WHERE session_id = ? AND action_type = 'pause_session' AND reversed = 0
    ORDER BY timestamp DESC LIMIT 1
  `).run(new Date().toISOString(), resumedBy, sessionId);

  return action;
}

/** Reverse any automated action by ID */
export function reverseAction(actionId: number, reversedBy = 'user'): AutoAction | null {
  const action = getDb().prepare('SELECT * FROM auto_actions WHERE id = ?').get(actionId) as AutoAction | null;
  if (!action || action.reversed) return null;

  getDb().prepare(
    'UPDATE auto_actions SET reversed = 1, reversed_at = ?, reversed_by = ? WHERE id = ?'
  ).run(new Date().toISOString(), reversedBy, actionId);

  // If it was a pause, also unpause the session
  if (action.action_type === 'pause_session') {
    const idx = config.pausedSessions.indexOf(action.session_id);
    if (idx !== -1) config.pausedSessions.splice(idx, 1);
  }

  return getDb().prepare('SELECT * FROM auto_actions WHERE id = ?').get(actionId) as AutoAction;
}

// ── Query ──

export function getAutoActions(sessionId?: string, limit = 50): AutoAction[] {
  if (sessionId) {
    return getDb().prepare(
      'SELECT * FROM auto_actions WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?'
    ).all(sessionId, limit) as AutoAction[];
  }
  return getDb().prepare(
    'SELECT * FROM auto_actions ORDER BY timestamp DESC LIMIT ?'
  ).all(limit) as AutoAction[];
}

export function getAutoResponseStats(): AutoResponseStats {
  const db = getDb();
  const row = db.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN action_type = 'kill_terminal' THEN 1 ELSE 0 END) as kills,
      SUM(CASE WHEN action_type = 'block_writes' THEN 1 ELSE 0 END) as blocks,
      SUM(CASE WHEN action_type = 'pause_session' THEN 1 ELSE 0 END) as pauses,
      SUM(CASE WHEN reversed = 1 THEN 1 ELSE 0 END) as reversed
    FROM auto_actions
  `).get() as any;

  return {
    totalActions: row?.total || 0,
    killActions: row?.kills || 0,
    blockActions: row?.blocks || 0,
    pauseActions: row?.pauses || 0,
    reversedActions: row?.reversed || 0,
    activePauses: config.pausedSessions.length,
  };
}
