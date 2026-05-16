/**
 * Multi-Agent Correlation — cross-session views, conflict detection, interleaved timeline.
 *
 * When multiple AI agents work on the same project (or even different projects),
 * this module detects overlaps, file conflicts, and builds an interleaved timeline.
 */

import { getDb } from '../storage/db';

// ── Types ──

export interface CorrelationGroup {
  project_name: string;
  sessions: Array<{
    id: string;
    provider: string;
    started_at: string;
    ended_at: string | null;
    event_count: number;
    danger_count: number;
  }>;
  overlapPeriods: Array<{ start: string; end: string; sessions: string[] }>;
  conflicts: FileConflict[];
}

export interface FileConflict {
  file_path: string;
  sessions: Array<{ session_id: string; provider: string; event_type: string; timestamp: string }>;
  conflict_type: 'concurrent_write' | 'write_after_write' | 'delete_after_write';
}

export interface InterleavedEvent {
  id: number;
  session_id: string;
  provider: string;
  timestamp: string;
  event_type: string;
  risk_level: string;
  summary: string;
  file_paths: string[];
  command: string | null;
  agent_id: string;
}

export interface CrossSessionStats {
  totalProjects: number;
  projectsWithMultiAgent: number;
  totalConflicts: number;
  overlappingSessions: number;
}

// ── Cross-Session Queries ──

/**
 * Find projects where multiple providers/sessions overlap.
 */
export function getMultiAgentProjects(): CorrelationGroup[] {
  const db = getDb();
  // Find projects with 2+ sessions from different providers
  const projects = db.prepare(`
    SELECT project_name, COUNT(DISTINCT id) as session_count, COUNT(DISTINCT source_tool) as provider_count
    FROM sessions
    WHERE project_name != '' AND project_name != 'unknown'
    GROUP BY project_name
    HAVING session_count >= 2
    ORDER BY provider_count DESC, session_count DESC
  `).all() as any[];

  return projects.map(p => buildCorrelationGroup(p.project_name));
}

function buildCorrelationGroup(projectName: string): CorrelationGroup {
  const db = getDb();

  const sessions = db.prepare(`
    SELECT id, source_tool as provider, started_at, ended_at, total_events as event_count, danger_count
    FROM sessions WHERE project_name = ?
    ORDER BY started_at ASC
  `).all(projectName) as any[];

  // Detect overlapping time periods
  const overlapPeriods: CorrelationGroup['overlapPeriods'] = [];
  for (let i = 0; i < sessions.length; i++) {
    for (let j = i + 1; j < sessions.length; j++) {
      const a = sessions[i];
      const b = sessions[j];
      const aEnd = a.ended_at || new Date().toISOString();
      const bEnd = b.ended_at || new Date().toISOString();
      const overlapStart = a.started_at > b.started_at ? a.started_at : b.started_at;
      const overlapEnd = aEnd < bEnd ? aEnd : bEnd;
      if (overlapStart < overlapEnd) {
        overlapPeriods.push({
          start: overlapStart,
          end: overlapEnd,
          sessions: [a.id, b.id],
        });
      }
    }
  }

  // Detect file conflicts
  const conflicts = detectFileConflicts(sessions.map(s => s.id));

  return { project_name: projectName, sessions, overlapPeriods, conflicts };
}

/**
 * Detect file-level conflicts across sessions.
 */
function detectFileConflicts(sessionIds: string[]): FileConflict[] {
  if (sessionIds.length < 2) return [];
  const db = getDb();
  const placeholders = sessionIds.map(() => '?').join(',');

  // Find files written by multiple sessions
  const rows = db.prepare(`
    SELECT e.file_paths, e.session_id, e.event_type, e.timestamp, s.source_tool as provider
    FROM events e JOIN sessions s ON e.session_id = s.id
    WHERE e.session_id IN (${placeholders})
    AND e.event_type IN ('file_write', 'file_create', 'file_delete')
    AND e.file_paths != '[]'
    ORDER BY e.timestamp ASC
  `).all(...sessionIds) as any[];

  // Group by file path
  const fileMap = new Map<string, Array<{ session_id: string; provider: string; event_type: string; timestamp: string }>>();
  for (const row of rows) {
    const paths: string[] = JSON.parse(row.file_paths || '[]');
    for (const fp of paths) {
      if (!fileMap.has(fp)) fileMap.set(fp, []);
      fileMap.get(fp)!.push({
        session_id: row.session_id,
        provider: row.provider,
        event_type: row.event_type,
        timestamp: row.timestamp,
      });
    }
  }

  const conflicts: FileConflict[] = [];
  for (const [filePath, ops] of fileMap) {
    // Only count as conflict if multiple sessions touch same file
    const uniqueSessions = new Set(ops.map(o => o.session_id));
    if (uniqueSessions.size < 2) continue;

    // Determine conflict type
    const hasDelete = ops.some(o => o.event_type === 'file_delete');
    const hasWrite = ops.some(o => o.event_type === 'file_write' || o.event_type === 'file_create');
    const conflictType: FileConflict['conflict_type'] = hasDelete && hasWrite
      ? 'delete_after_write'
      : 'concurrent_write';

    conflicts.push({ file_path: filePath, sessions: ops, conflict_type: conflictType });
  }

  return conflicts;
}

// ── Interleaved Timeline ──

/**
 * Build an interleaved timeline across multiple sessions (same project or explicit list).
 */
export function getInterleavedTimeline(params: {
  project_name?: string;
  session_ids?: string[];
  limit?: number;
  offset?: number;
}): InterleavedEvent[] {
  const db = getDb();
  const limit = Math.min(params.limit || 200, 1000);
  const offset = params.offset || 0;

  let query: string;
  let queryParams: unknown[];

  if (params.session_ids && params.session_ids.length > 0) {
    const placeholders = params.session_ids.map(() => '?').join(',');
    query = `
      SELECT e.id, e.session_id, s.source_tool as provider, e.timestamp, e.event_type,
             e.risk_level, e.summary, e.file_paths, e.command, e.agent_id
      FROM events e JOIN sessions s ON e.session_id = s.id
      WHERE e.session_id IN (${placeholders})
      ORDER BY e.timestamp ASC LIMIT ? OFFSET ?
    `;
    queryParams = [...params.session_ids, limit, offset];
  } else if (params.project_name) {
    query = `
      SELECT e.id, e.session_id, s.source_tool as provider, e.timestamp, e.event_type,
             e.risk_level, e.summary, e.file_paths, e.command, e.agent_id
      FROM events e JOIN sessions s ON e.session_id = s.id
      WHERE s.project_name = ?
      ORDER BY e.timestamp ASC LIMIT ? OFFSET ?
    `;
    queryParams = [params.project_name, limit, offset];
  } else {
    return [];
  }

  const rows = db.prepare(query).all(...queryParams) as any[];
  return rows.map(r => ({
    ...r,
    file_paths: JSON.parse(r.file_paths || '[]'),
  }));
}

// ── Stats ──

export function getCrossSessionStats(): CrossSessionStats {
  const db = getDb();
  const totalProjects = (db.prepare(
    "SELECT COUNT(DISTINCT project_name) as cnt FROM sessions WHERE project_name != '' AND project_name != 'unknown'"
  ).get() as any)?.cnt || 0;

  const multiAgent = (db.prepare(`
    SELECT COUNT(*) as cnt FROM (
      SELECT project_name FROM sessions
      WHERE project_name != '' AND project_name != 'unknown'
      GROUP BY project_name HAVING COUNT(DISTINCT id) >= 2
    )
  `).get() as any)?.cnt || 0;

  // Count conflict files
  const groups = getMultiAgentProjects();
  const totalConflicts = groups.reduce((sum, g) => sum + g.conflicts.length, 0);
  const overlappingSessions = groups.reduce((sum, g) => sum + g.overlapPeriods.length, 0);

  return { totalProjects, projectsWithMultiAgent: multiAgent, totalConflicts, overlappingSessions };
}
