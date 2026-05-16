/**
 * Prompt History — capture, store, and replay user prompts to AI agents.
 *
 * Stores the FULL untruncated text of every user prompt, linked to its
 * session and event. Provides crash-recovery context generation: when an
 * agent session dies, we can build a summary of what the user was doing
 * and what instructions to feed back to restart the work.
 */

import { getDb } from '../storage/db';

// ── Types ──

export interface StoredPrompt {
  id?: number;
  event_id: number;
  session_id: string;
  timestamp: string;
  /** Full untruncated prompt text */
  content: string;
  /** Which AI tool this was sent to */
  provider: string;
  /** Project context */
  project_name: string;
  /** Estimated token count */
  token_count: number;
  /** Sequence number within the session (1st, 2nd, 3rd prompt...) */
  seq: number;
}

export interface CrashRecoveryContext {
  sessionId: string;
  provider: string;
  project: string;
  branch: string | null;
  /** When the session started */
  startedAt: string;
  /** When the last activity happened */
  lastActivityAt: string;
  /** Total prompts in the session */
  totalPrompts: number;
  /** Total events (actions the agent took) */
  totalEvents: number;
  /** Summary of what was being worked on */
  workSummary: string;
  /** The last N prompts (most recent context) */
  recentPrompts: Array<{ seq: number; timestamp: string; content: string }>;
  /** Files that were touched during the session */
  filesTouched: string[];
  /** Key actions taken (danger/warn events) */
  keyActions: Array<{ type: string; summary: string; risk: string }>;
  /** A ready-to-paste recovery prompt */
  recoveryPrompt: string;
}

// ── DB Operations ──

/** Initialize the prompts table (called from db.ts migrate) */
export function migratePrompts(): void {
  const db = getDb();
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
}

/** Store a prompt */
export function insertPrompt(prompt: Omit<StoredPrompt, 'id'>): number {
  const db = getDb();
  const result = db.prepare(`
    INSERT INTO prompts (event_id, session_id, timestamp, content, provider, project_name, token_count, seq)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    prompt.event_id, prompt.session_id, prompt.timestamp,
    prompt.content, prompt.provider, prompt.project_name,
    prompt.token_count, prompt.seq
  );
  return Number(result.lastInsertRowid);
}

/** Get all prompts for a session, ordered by sequence */
export function getSessionPrompts(sessionId: string): StoredPrompt[] {
  const db = getDb();
  return db.prepare(
    'SELECT * FROM prompts WHERE session_id = ? ORDER BY seq ASC'
  ).all(sessionId) as StoredPrompt[];
}

/** Get recent prompts across all sessions */
export function getRecentPrompts(limit = 50): StoredPrompt[] {
  const db = getDb();
  return db.prepare(
    'SELECT * FROM prompts ORDER BY timestamp DESC LIMIT ?'
  ).all(limit) as StoredPrompt[];
}

/** Get prompts for a project */
export function getProjectPrompts(projectName: string, limit = 100): StoredPrompt[] {
  const db = getDb();
  return db.prepare(
    'SELECT * FROM prompts WHERE project_name = ? ORDER BY timestamp DESC LIMIT ?'
  ).all(projectName, limit) as StoredPrompt[];
}

/** Search prompts by content */
export function searchPrompts(query: string, limit = 50): StoredPrompt[] {
  const db = getDb();
  const escaped = query.replace(/[%_]/g, c => '\\' + c);
  return db.prepare(
    "SELECT * FROM prompts WHERE content LIKE ? ESCAPE '\\' ORDER BY timestamp DESC LIMIT ?"
  ).all(`%${escaped}%`, limit) as StoredPrompt[];
}

/** Get prompt count per session (for determining seq of next prompt) */
export function getSessionPromptCount(sessionId: string): number {
  const db = getDb();
  const row = db.prepare('SELECT COUNT(*) as c FROM prompts WHERE session_id = ?').get(sessionId) as { c: number };
  return row.c;
}

/** Get prompt stats */
export function getPromptStats(): {
  totalPrompts: number;
  totalSessions: number;
  avgPromptsPerSession: number;
  avgTokensPerPrompt: number;
  topProjects: Array<{ project: string; count: number }>;
} {
  const db = getDb();
  const total = (db.prepare('SELECT COUNT(*) as c FROM prompts').get() as { c: number }).c;
  const sessions = (db.prepare('SELECT COUNT(DISTINCT session_id) as c FROM prompts').get() as { c: number }).c;
  const avgTokens = (db.prepare('SELECT AVG(token_count) as a FROM prompts').get() as { a: number | null }).a || 0;
  const topProjects = db.prepare(
    "SELECT project_name as project, COUNT(*) as count FROM prompts WHERE project_name != '' GROUP BY project_name ORDER BY count DESC LIMIT 10"
  ).all() as Array<{ project: string; count: number }>;

  return {
    totalPrompts: total,
    totalSessions: sessions,
    avgPromptsPerSession: sessions > 0 ? Math.round(total / sessions) : 0,
    avgTokensPerPrompt: Math.round(avgTokens),
    topProjects,
  };
}

// ── Crash Recovery Context Generation ──

/**
 * Generate a crash recovery context for a session.
 * This builds a complete picture of what was happening so you can
 * restart the agent with the right context.
 */
export function generateCrashRecovery(sessionId: string, recentCount = 5): CrashRecoveryContext | null {
  const db = getDb();

  // Get session info
  const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId) as Record<string, unknown> | undefined;
  if (!session) return null;

  // Get prompts
  const prompts = getSessionPrompts(sessionId);
  if (prompts.length === 0) return null;

  // Get events summary
  const totalEvents = (db.prepare('SELECT COUNT(*) as c FROM events WHERE session_id = ?').get(sessionId) as { c: number }).c;

  // Get files touched
  const fileRows = db.prepare(
    "SELECT DISTINCT file_paths FROM events WHERE session_id = ? AND file_paths != '[]' AND file_paths != ''"
  ).all(sessionId) as Array<{ file_paths: string }>;
  const filesTouched: string[] = [];
  for (const row of fileRows) {
    try {
      const paths = JSON.parse(row.file_paths);
      if (Array.isArray(paths)) filesTouched.push(...paths);
    } catch {}
  }
  const uniqueFiles = [...new Set(filesTouched)].slice(0, 30);

  // Get key actions (warn/danger events)
  const keyEvents = db.prepare(
    "SELECT event_type, summary, risk_level FROM events WHERE session_id = ? AND risk_level IN ('warn', 'danger') ORDER BY timestamp DESC LIMIT 20"
  ).all(sessionId) as Array<{ event_type: string; summary: string; risk_level: string }>;

  // Get branch
  const branch = (session.git_branch as string) || null;

  // Recent prompts
  const recentPrompts = prompts.slice(-recentCount).map(p => ({
    seq: p.seq,
    timestamp: p.timestamp,
    content: p.content,
  }));

  // Build work summary from prompt content
  const workSummary = buildWorkSummary(prompts);

  // Build recovery prompt
  const recoveryPrompt = buildRecoveryPrompt({
    project: session.project_name as string,
    branch,
    prompts: recentPrompts,
    filesTouched: uniqueFiles,
    workSummary,
  });

  return {
    sessionId,
    provider: session.source_tool as string,
    project: session.project_name as string,
    branch,
    startedAt: session.started_at as string,
    lastActivityAt: prompts[prompts.length - 1].timestamp,
    totalPrompts: prompts.length,
    totalEvents,
    workSummary,
    recentPrompts,
    filesTouched: uniqueFiles,
    keyActions: keyEvents.map(e => ({ type: e.event_type, summary: e.summary, risk: e.risk_level })),
    recoveryPrompt,
  };
}

/** Build a concise work summary from all prompts in a session */
function buildWorkSummary(prompts: StoredPrompt[]): string {
  if (prompts.length === 0) return 'No prompts recorded.';
  if (prompts.length === 1) return prompts[0].content.substring(0, 300);

  // Take first prompt (sets context) + last few (most recent work)
  const first = prompts[0].content.substring(0, 200);
  const lastFew = prompts.slice(-3).map(p => p.content.substring(0, 150));

  let summary = `Started with: "${first}"`;
  if (prompts.length > 1) {
    summary += `\nThen ${prompts.length - 1} more prompts, most recently: ${lastFew.map(t => `"${t}"`).join(' → ')}`;
  }
  return summary;
}

/** Build a ready-to-paste recovery prompt */
function buildRecoveryPrompt(ctx: {
  project: string;
  branch: string | null;
  prompts: Array<{ seq: number; content: string }>;
  filesTouched: string[];
  workSummary: string;
}): string {
  const lines: string[] = [];

  lines.push(`I'm picking up where a previous session left off. Here's the context:`);
  lines.push('');
  if (ctx.project) lines.push(`**Project:** ${ctx.project}`);
  if (ctx.branch) lines.push(`**Branch:** ${ctx.branch}`);
  lines.push('');

  if (ctx.filesTouched.length > 0) {
    lines.push(`**Files that were being worked on:**`);
    for (const f of ctx.filesTouched.slice(0, 15)) {
      lines.push(`- ${f}`);
    }
    if (ctx.filesTouched.length > 15) lines.push(`- ... and ${ctx.filesTouched.length - 15} more`);
    lines.push('');
  }

  lines.push(`**What I was asking the previous agent to do:**`);
  for (const p of ctx.prompts) {
    lines.push(`${p.seq}. ${p.content}`);
    lines.push('');
  }

  lines.push(`Please review the current state of those files and continue from where the previous session left off. If anything looks incomplete or broken, fix it first before moving forward.`);

  return lines.join('\n');
}
