/**
 * Team Dashboard — API key auth, multi-user event tagging, shared rules.
 *
 * Provides a lightweight auth layer so multiple users can share one tracker
 * instance, each with their own API key and event attribution.
 */

import { getDb } from '../storage/db';
import * as crypto from 'crypto';

// ── Types ──

export interface TeamUser {
  id: string;
  name: string;
  role: 'admin' | 'viewer' | 'operator';
  api_key_hash: string;
  created_at: string;
  last_seen_at: string | null;
  active: boolean;
}

export interface SharedRule {
  id: number;
  name: string;
  description: string;
  pattern: string;
  is_regex: boolean;
  severity: string;
  created_by: string;
  created_at: string;
  enabled: boolean;
}

export interface TeamStats {
  totalUsers: number;
  activeUsers: number;
  sharedRules: number;
  recentActivity: Array<{ user: string; action: string; timestamp: string }>;
}

// ── DB Migration ──

export function migrateTeam(): void {
  const db = getDb();
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
}

// ── API Key Management ──

function hashKey(key: string): string {
  return crypto.createHash('sha256').update(key).digest('hex');
}

function generateApiKey(): string {
  return 'alt_' + crypto.randomBytes(24).toString('hex');
}

/**
 * Create a new team user. Returns the plaintext API key (only shown once).
 */
export function createUser(name: string, role: 'admin' | 'viewer' | 'operator' = 'viewer'): { user: TeamUser; apiKey: string } {
  const id = crypto.randomUUID();
  const apiKey = generateApiKey();
  const keyHash = hashKey(apiKey);
  const now = new Date().toISOString();

  getDb().prepare(`
    INSERT INTO team_users (id, name, role, api_key_hash, created_at) VALUES (?, ?, ?, ?, ?)
  `).run(id, name, role, keyHash, now);

  return { user: getUser(id)!, apiKey };
}

/** Authenticate by API key. Returns the user or null. */
export function authenticateByKey(apiKey: string): TeamUser | null {
  const keyHash = hashKey(apiKey);
  const row = getDb().prepare(
    'SELECT * FROM team_users WHERE api_key_hash = ? AND active = 1'
  ).get(keyHash) as any;
  if (!row) return null;

  // Update last_seen
  getDb().prepare('UPDATE team_users SET last_seen_at = ? WHERE id = ?')
    .run(new Date().toISOString(), row.id);

  return row as TeamUser;
}

/** Get user by ID */
export function getUser(id: string): TeamUser | null {
  return getDb().prepare('SELECT * FROM team_users WHERE id = ?').get(id) as TeamUser | null;
}

/** List all users */
export function listUsers(): TeamUser[] {
  return getDb().prepare('SELECT * FROM team_users ORDER BY created_at ASC').all() as TeamUser[];
}

/** Deactivate a user */
export function deactivateUser(id: string): boolean {
  const info = getDb().prepare('UPDATE team_users SET active = 0 WHERE id = ?').run(id);
  return info.changes > 0;
}

/** Regenerate API key. Returns new plaintext key. */
export function regenerateApiKey(userId: string): string | null {
  const user = getUser(userId);
  if (!user) return null;
  const apiKey = generateApiKey();
  getDb().prepare('UPDATE team_users SET api_key_hash = ? WHERE id = ?')
    .run(hashKey(apiKey), userId);
  return apiKey;
}

// ── Shared Rules ──

export function createSharedRule(params: {
  name: string;
  description?: string;
  pattern: string;
  is_regex?: boolean;
  severity?: string;
  created_by: string;
}): SharedRule {
  const now = new Date().toISOString();
  const info = getDb().prepare(`
    INSERT INTO shared_rules (name, description, pattern, is_regex, severity, created_by, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(params.name, params.description || '', params.pattern,
    params.is_regex ? 1 : 0, params.severity || 'warn', params.created_by, now);
  return getDb().prepare('SELECT * FROM shared_rules WHERE id = ?')
    .get(Number(info.lastInsertRowid)) as SharedRule;
}

export function getSharedRules(): SharedRule[] {
  return getDb().prepare('SELECT * FROM shared_rules ORDER BY created_at DESC').all() as SharedRule[];
}

export function toggleSharedRule(id: number, enabled: boolean): boolean {
  const info = getDb().prepare('UPDATE shared_rules SET enabled = ? WHERE id = ?')
    .run(enabled ? 1 : 0, id);
  return info.changes > 0;
}

export function deleteSharedRule(id: number): boolean {
  const info = getDb().prepare('DELETE FROM shared_rules WHERE id = ?').run(id);
  return info.changes > 0;
}

// ── Activity Logging ──

export function logTeamActivity(userId: string, action: string, detail?: string): void {
  getDb().prepare(`
    INSERT INTO team_activity (user_id, action, detail, timestamp) VALUES (?, ?, ?, ?)
  `).run(userId, action, detail || null, new Date().toISOString());
}

// ── Stats ──

export function getTeamStats(): TeamStats {
  const db = getDb();
  const users = listUsers();
  const rules = getSharedRules();
  const activity = db.prepare(`
    SELECT ta.user_id, tu.name as user, ta.action, ta.timestamp
    FROM team_activity ta
    LEFT JOIN team_users tu ON ta.user_id = tu.id
    ORDER BY ta.timestamp DESC LIMIT 20
  `).all() as any[];

  return {
    totalUsers: users.length,
    activeUsers: users.filter(u => u.active).length,
    sharedRules: rules.filter(r => r.enabled).length,
    recentActivity: activity.map(a => ({ user: a.user || a.user_id, action: a.action, timestamp: a.timestamp })),
  };
}

// ── Express Middleware ──

/**
 * Optional auth middleware. If team_users table has any users,
 * requires X-API-Key header. Otherwise passes through (single-user mode).
 */
export function teamAuthMiddleware(req: any, res: any, next: any): void {
  const users = listUsers();
  if (users.length === 0) {
    // No users configured — single-user mode, skip auth
    return next();
  }

  const apiKey = req.headers['x-api-key'] as string;
  if (!apiKey) {
    return res.status(401).json({ error: 'API key required. Set X-API-Key header.' });
  }

  const user = authenticateByKey(apiKey);
  if (!user) {
    return res.status(403).json({ error: 'Invalid or deactivated API key' });
  }

  // Attach user to request
  (req as any).teamUser = user;
  next();
}
