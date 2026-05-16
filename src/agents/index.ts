/**
 * Sub-Agent Authority — trust hierarchy, scope enforcement, delegation tree.
 *
 * Models parent→child agent relationships with scope inheritance.
 * Parent agents can delegate sub-scopes to children; children cannot
 * exceed their parent's authority. The delegation tree is persisted
 * and visualized in the dashboard.
 */

import { getDb } from '../storage/db';
import type { RiskLevel } from '../parser/event-types';

// ── Types ──

export interface AgentNode {
  id: string;
  session_id: string;
  parent_id: string | null;
  provider: string;
  /** What scopes this agent is allowed (file globs, command patterns) */
  allowed_scopes: string[];
  /** What scopes are explicitly denied */
  denied_scopes: string[];
  trust_level: 'full' | 'limited' | 'sandboxed';
  created_at: string;
  last_seen_at: string;
  event_count: number;
  danger_count: number;
}

export interface DelegationRecord {
  id: number;
  parent_agent_id: string;
  child_agent_id: string;
  session_id: string;
  delegated_scopes: string[];
  timestamp: string;
  reason: string;
}

export interface AuthorityViolation {
  id: number;
  agent_id: string;
  session_id: string;
  timestamp: string;
  violation_type: 'scope_exceeded' | 'unauthorized_delegation' | 'trust_violation';
  message: string;
  severity: RiskLevel;
}

export interface DelegationTree {
  agent: AgentNode;
  children: DelegationTree[];
}

// ── DB Migration ──

export function migrateAgents(): void {
  const db = getDb();
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
}

// ── Agent Node Management ──

/**
 * Register or update an agent node. Called from the watcher when events come in.
 */
export function upsertAgentNode(params: {
  id: string;
  session_id: string;
  parent_id: string | null;
  provider: string;
  trust_level?: 'full' | 'limited' | 'sandboxed';
}): AgentNode {
  const db = getDb();
  const now = new Date().toISOString();
  const existing = db.prepare(
    'SELECT * FROM agent_nodes WHERE id = ? AND session_id = ?'
  ).get(params.id, params.session_id) as any;

  if (existing) {
    db.prepare(`
      UPDATE agent_nodes SET last_seen_at = ?, event_count = event_count + 1,
        parent_id = COALESCE(?, parent_id)
      WHERE id = ? AND session_id = ?
    `).run(now, params.parent_id, params.id, params.session_id);
  } else {
    db.prepare(`
      INSERT INTO agent_nodes (id, session_id, parent_id, provider, trust_level, created_at, last_seen_at, event_count)
      VALUES (?, ?, ?, ?, ?, ?, ?, 1)
    `).run(params.id, params.session_id, params.parent_id, params.provider,
      params.trust_level || 'limited', now, now);
  }
  return getAgentNode(params.id, params.session_id)!;
}

/** Increment danger count for an agent */
export function incrementAgentDanger(agentId: string, sessionId: string): void {
  getDb().prepare(
    'UPDATE agent_nodes SET danger_count = danger_count + 1 WHERE id = ? AND session_id = ?'
  ).run(agentId, sessionId);
}

/** Set scopes for an agent */
export function setAgentScopes(agentId: string, sessionId: string, allowed: string[], denied: string[]): void {
  getDb().prepare(
    'UPDATE agent_nodes SET allowed_scopes = ?, denied_scopes = ? WHERE id = ? AND session_id = ?'
  ).run(JSON.stringify(allowed), JSON.stringify(denied), agentId, sessionId);
}

export function getAgentNode(id: string, sessionId: string): AgentNode | null {
  const row = getDb().prepare(
    'SELECT * FROM agent_nodes WHERE id = ? AND session_id = ?'
  ).get(id, sessionId) as any;
  return row ? hydrateAgent(row) : null;
}

export function getSessionAgentNodes(sessionId: string): AgentNode[] {
  const rows = getDb().prepare(
    'SELECT * FROM agent_nodes WHERE session_id = ? ORDER BY created_at ASC'
  ).all(sessionId) as any[];
  return rows.map(hydrateAgent);
}

function hydrateAgent(row: any): AgentNode {
  return {
    ...row,
    allowed_scopes: JSON.parse(row.allowed_scopes || '[]'),
    denied_scopes: JSON.parse(row.denied_scopes || '[]'),
  };
}

// ── Delegation ──

export function recordDelegation(params: {
  parent_agent_id: string;
  child_agent_id: string;
  session_id: string;
  delegated_scopes: string[];
  reason: string;
}): DelegationRecord {
  const now = new Date().toISOString();
  const info = getDb().prepare(`
    INSERT INTO delegation_records (parent_agent_id, child_agent_id, session_id, delegated_scopes, timestamp, reason)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(params.parent_agent_id, params.child_agent_id, params.session_id,
    JSON.stringify(params.delegated_scopes), now, params.reason);
  return getDelegation(Number(info.lastInsertRowid))!;
}

export function getDelegation(id: number): DelegationRecord | null {
  const row = getDb().prepare('SELECT * FROM delegation_records WHERE id = ?').get(id) as any;
  return row ? { ...row, delegated_scopes: JSON.parse(row.delegated_scopes || '[]') } : null;
}

export function getSessionDelegations(sessionId: string): DelegationRecord[] {
  const rows = getDb().prepare(
    'SELECT * FROM delegation_records WHERE session_id = ? ORDER BY timestamp ASC'
  ).all(sessionId) as any[];
  return rows.map(r => ({ ...r, delegated_scopes: JSON.parse(r.delegated_scopes || '[]') }));
}

// ── Authority Violations ──

export function recordAuthorityViolation(params: {
  agent_id: string;
  session_id: string;
  violation_type: AuthorityViolation['violation_type'];
  message: string;
  severity: RiskLevel;
}): AuthorityViolation {
  const now = new Date().toISOString();
  const info = getDb().prepare(`
    INSERT INTO authority_violations (agent_id, session_id, timestamp, violation_type, message, severity)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(params.agent_id, params.session_id, now, params.violation_type, params.message, params.severity);
  return getDb().prepare('SELECT * FROM authority_violations WHERE id = ?')
    .get(Number(info.lastInsertRowid)) as AuthorityViolation;
}

export function getAuthorityViolations(sessionId?: string, limit = 50): AuthorityViolation[] {
  if (sessionId) {
    return getDb().prepare(
      'SELECT * FROM authority_violations WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?'
    ).all(sessionId, limit) as AuthorityViolation[];
  }
  return getDb().prepare(
    'SELECT * FROM authority_violations ORDER BY timestamp DESC LIMIT ?'
  ).all(limit) as AuthorityViolation[];
}

// ── Delegation Tree Builder ──

export function buildDelegationTree(sessionId: string): DelegationTree[] {
  const agents = getSessionAgentNodes(sessionId);
  const map = new Map<string, DelegationTree>();
  const roots: DelegationTree[] = [];

  for (const agent of agents) {
    map.set(agent.id, { agent, children: [] });
  }
  for (const agent of agents) {
    const node = map.get(agent.id)!;
    if (agent.parent_id && map.has(agent.parent_id)) {
      map.get(agent.parent_id)!.children.push(node);
    } else {
      roots.push(node);
    }
  }
  return roots;
}

// ── Scope Enforcement ──

/**
 * Check if an agent is authorized for a given action.
 * Returns null if OK, or an AuthorityViolation if not.
 */
export function checkAgentAuthority(
  agentId: string,
  sessionId: string,
  action: { type: string; target: string }
): AuthorityViolation | null {
  const agent = getAgentNode(agentId, sessionId);
  if (!agent) return null; // Unknown agent — no scope to check

  // Check denied scopes
  for (const pattern of agent.denied_scopes) {
    if (action.target.includes(pattern) || minimatchLite(action.target, pattern)) {
      return recordAuthorityViolation({
        agent_id: agentId,
        session_id: sessionId,
        violation_type: 'scope_exceeded',
        message: `Agent "${agentId}" attempted "${action.target}" which matches denied scope "${pattern}"`,
        severity: 'danger',
      });
    }
  }

  // If allowed scopes set, target must match at least one
  if (agent.allowed_scopes.length > 0) {
    const allowed = agent.allowed_scopes.some(p =>
      action.target.includes(p) || minimatchLite(action.target, p)
    );
    if (!allowed) {
      return recordAuthorityViolation({
        agent_id: agentId,
        session_id: sessionId,
        violation_type: 'scope_exceeded',
        message: `Agent "${agentId}" attempted "${action.target}" outside allowed scopes`,
        severity: 'warn',
      });
    }
  }

  // Sandboxed agents cannot perform danger-level operations
  if (agent.trust_level === 'sandboxed' && (action.type === 'terminal_command' || action.type === 'git_push')) {
    return recordAuthorityViolation({
      agent_id: agentId,
      session_id: sessionId,
      violation_type: 'trust_violation',
      message: `Sandboxed agent "${agentId}" attempted ${action.type}`,
      severity: 'danger',
    });
  }

  return null;
}

/** Lightweight glob-like match (no dependency) */
function minimatchLite(target: string, pattern: string): boolean {
  if (pattern === '*' || pattern === '**') return true;
  if (pattern.startsWith('**/')) return target.includes(pattern.slice(3));
  if (pattern.endsWith('/**')) return target.startsWith(pattern.slice(0, -3));
  if (pattern.includes('*')) {
    const re = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
    return re.test(target);
  }
  return target === pattern;
}
