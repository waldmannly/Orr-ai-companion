/**
 * PR Comment Bot — generates accurate Markdown summaries of AI agent activity for a PR.
 *
 * The core challenge: mapping the right sessions to the right PR.
 * We match on git_branch (required) AND optionally project_name for precision.
 * Sessions are further validated by provider filter if configured.
 */

import { SessionInfo, Alert, RiskLevel } from '../parser/event-types';
import { Config, PRBotConfig } from '../config';
import { getSessionsByBranch, getAlerts, getDb } from '../storage/db';
import { getTrustScore } from '../trust';

// ── Types ──

export interface PRCommentRequest {
  /** The branch this PR is for (required — this is how we find sessions) */
  branch: string;
  /** Repo identifier e.g. "owner/repo" — overrides config.prBot.repo */
  repo?: string;
  /** PR number — used for updating existing comments */
  prNumber?: number;
  /** Platform override */
  platform?: 'github' | 'gitlab' | 'bitbucket';
  /** Filter to sessions for this project only */
  projectName?: string;
}

export interface PRCommentData {
  branch: string;
  sessions: SessionInfo[];
  totalEvents: number;
  dangerCount: number;
  warnCount: number;
  criticalCount: number;
  alerts: Alert[];
  providers: string[];
  trustGrades: Record<string, string>;
  filesModified: number;
  terminalCommands: number;
  timespan: { first: string; last: string } | null;
  killedSessions: number;
}

// ── Severity ordering for filtering ──

const SEVERITY_ORDER: RiskLevel[] = ['info', 'watch', 'warn', 'danger', 'critical'];

function severityAtLeast(sev: RiskLevel, min: RiskLevel): boolean {
  return SEVERITY_ORDER.indexOf(sev) >= SEVERITY_ORDER.indexOf(min);
}

// ── Session → PR mapping ──

/**
 * Collect all sessions relevant to a PR branch.
 * This is the smart matching part — we filter by branch AND optionally project/provider.
 */
export function collectPRData(req: PRCommentRequest, config: Config): PRCommentData {
  const db = getDb();
  const prBot = config.prBot;

  // 1. Get all sessions on this branch
  let sessions = getSessionsByBranch(req.branch);

  // 2. Filter by project if specified
  if (req.projectName) {
    sessions = sessions.filter(s => s.project_name === req.projectName);
  }

  // 3. Filter by provider if configured
  if (prBot.filterProviders.length > 0) {
    sessions = sessions.filter(s => prBot.filterProviders.includes(s.source_tool));
  }

  if (sessions.length === 0) {
    return {
      branch: req.branch,
      sessions: [],
      totalEvents: 0,
      dangerCount: 0,
      warnCount: 0,
      criticalCount: 0,
      alerts: [],
      providers: [],
      trustGrades: {},
      filesModified: 0,
      terminalCommands: 0,
      timespan: null,
      killedSessions: 0,
    };
  }

  const sessionIds = sessions.map(s => s.id);
  const placeholders = sessionIds.map(() => '?').join(',');

  // 4. Aggregate event stats from the sessions themselves (already tallied) — single pass
  let totalEvents = 0, dangerCount = 0, warnCount = 0;
  for (const s of sessions) {
    totalEvents += s.total_events;
    dangerCount += s.danger_count;
    warnCount += s.warn_count;
  }

  // 5. Count critical events from the events table
  const criticalCount = (db.prepare(
    `SELECT COUNT(*) as c FROM events WHERE session_id IN (${placeholders}) AND risk_level = 'critical'`
  ).get(...sessionIds) as { c: number }).c;

  // 6. Get files modified by AI (file_write, file_create, file_delete)
  const filesModified = (db.prepare(
    `SELECT COUNT(DISTINCT file_paths) as c FROM events WHERE session_id IN (${placeholders}) AND event_type IN ('file_write', 'file_create', 'file_delete') AND file_paths != '[]'`
  ).get(...sessionIds) as { c: number }).c;

  // 7. Count terminal commands
  const terminalCommands = (db.prepare(
    `SELECT COUNT(*) as c FROM events WHERE session_id IN (${placeholders}) AND event_type = 'terminal_command'`
  ).get(...sessionIds) as { c: number }).c;

  // 8. Get alerts for these sessions — single batch query instead of N queries
  const alertPlaceholders = sessionIds.map(() => '?').join(',');
  let alerts: Alert[] = (db.prepare(
    `SELECT * FROM alerts WHERE session_id IN (${alertPlaceholders}) ORDER BY timestamp DESC LIMIT 1000`
  ).all(...sessionIds) as Array<Record<string, unknown>>).map(r => ({ ...r, acknowledged: !!(r.acknowledged) } as unknown as Alert));
  alerts = alerts.filter(a => severityAtLeast(a.severity, prBot.minSeverity as RiskLevel));
  // Deduplicate alerts — same type+message within the same session is redundant for a PR summary
  const seen = new Set<string>();
  alerts = alerts.filter(a => {
    const key = `${a.session_id}::${a.alert_type}::${a.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // 9. Providers involved
  const providers = [...new Set(sessions.map(s => s.source_tool))];

  // 10. Trust grades per provider
  const trustGrades: Record<string, string> = {};
  for (const p of providers) {
    const ts = getTrustScore(p);
    if (ts) trustGrades[p] = ts.grade;
  }

  // 11. Killed sessions
  const killedSessions = sessions.filter(s => (s as unknown as Record<string, unknown>).killed_at).length;

  // 12. Timespan
  const sortedByTime = [...sessions].sort((a, b) => a.started_at.localeCompare(b.started_at));
  const timespan = {
    first: sortedByTime[0].started_at,
    last: sortedByTime[sortedByTime.length - 1].started_at,
  };

  return {
    branch: req.branch,
    sessions,
    totalEvents,
    dangerCount,
    warnCount,
    criticalCount,
    alerts,
    providers,
    trustGrades,
    filesModified,
    terminalCommands,
    timespan,
    killedSessions,
  };
}

// ── Markdown generation ──

const SEVERITY_EMOJI: Record<string, string> = {
  watch: '👀',
  warn: '⚠️',
  danger: '🔴',
  critical: '☠️',
};

function formatDate(iso: string): string {
  const d = new Date(iso);
  return `${d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })} ${d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false })}`;
}

function sessionGrade(s: SessionInfo): string {
  if (s.danger_count >= 5) return 'F';
  if (s.danger_count >= 1) return 'C';
  if (s.warn_count > 5) return 'C';
  if (s.warn_count > 2) return 'B';
  return 'A';
}

export function generatePRComment(data: PRCommentData, config: Config): string {
  const prBot = config.prBot;

  if (data.sessions.length === 0) {
    return `## 🤖 AI Agent Activity Summary\n\n**Branch:** \`${data.branch}\`\n\nNo AI agent sessions found for this branch.\n\n---\n*Generated by AL Companion Tracker*`;
  }

  const lines: string[] = [];

  // Header
  lines.push('## 🤖 AI Agent Activity Summary');
  lines.push('');
  lines.push(`**Branch:** \`${data.branch}\``);
  lines.push(`**Sessions:** ${data.sessions.length}${data.timespan ? ` (${formatDate(data.timespan.first)} → ${formatDate(data.timespan.last)})` : ''}`);

  // Provider + trust info
  if (prBot.includeTrustScore && data.providers.length > 0) {
    const providerInfo = data.providers.map(p => {
      const grade = data.trustGrades[p];
      return grade ? `${p} (Grade: **${grade}**)` : p;
    }).join(', ');
    lines.push(`**Providers:** ${providerInfo}`);
  } else {
    lines.push(`**Providers:** ${data.providers.join(', ')}`);
  }

  // Killed session warning
  if (data.killedSessions > 0) {
    lines.push('');
    lines.push(`> 🚨 **${data.killedSessions} session${data.killedSessions > 1 ? 's were' : ' was'} auto-killed** due to critical threat detection`);
  }

  lines.push('');

  // Activity table
  lines.push('### Activity Overview');
  lines.push('| Metric | Value |');
  lines.push('|--------|-------|');
  lines.push(`| Total events | ${data.totalEvents} |`);
  lines.push(`| Files modified by AI | ${data.filesModified} |`);
  lines.push(`| Terminal commands run | ${data.terminalCommands} |`);

  if (data.criticalCount > 0) {
    lines.push(`| ☠️ Critical threats | **${data.criticalCount}** |`);
  }
  if (data.dangerCount > 0) {
    lines.push(`| 🔴 Danger alerts | **${data.dangerCount}** |`);
  }
  if (data.warnCount > 0) {
    lines.push(`| ⚠️ Warnings | ${data.warnCount} |`);
  }
  lines.push('');

  // Alerts section
  if (prBot.includeAlerts && data.alerts.length > 0) {
    lines.push('### Alerts Fired');

    // Group by severity, critical first
    const grouped = new Map<string, Alert[]>();
    for (const sev of ['critical', 'danger', 'warn', 'watch']) {
      const matching = data.alerts.filter(a => a.severity === sev);
      if (matching.length > 0) grouped.set(sev, matching);
    }

    for (const [sev, alerts] of grouped) {
      const emoji = SEVERITY_EMOJI[sev] || '📋';
      for (const a of alerts.slice(0, 15)) { // Cap at 15 per severity to avoid huge comments
        lines.push(`- ${emoji} **${a.alert_type}** — ${a.message}`);
      }
      if (alerts.length > 15) {
        lines.push(`- *...and ${alerts.length - 15} more ${sev} alerts*`);
      }
    }
    lines.push('');
  }

  // Session timeline
  if (prBot.includeSessions) {
    lines.push('### Session Timeline');
    // Show up to 20 sessions; if more, summarize
    const shown = data.sessions.slice(0, 20);
    for (let i = 0; i < shown.length; i++) {
      const s = shown[i];
      const grade = sessionGrade(s);
      const killed = (s as unknown as Record<string, unknown>).killed_at ? ' 🚨 KILLED' : '';
      const details: string[] = [];
      details.push(`${s.total_events} events`);
      details.push(`grade ${grade}`);
      if (s.danger_count > 0) details.push(`${s.danger_count} danger`);
      if (s.warn_count > 0) details.push(`${s.warn_count} warn`);
      lines.push(`${i + 1}. \`${formatDate(s.started_at)}\` — ${s.source_tool} · ${details.join(', ')}${killed}`);
    }
    if (data.sessions.length > 20) {
      lines.push(`\n*...and ${data.sessions.length - 20} more sessions*`);
    }
    lines.push('');
  }

  // Overall verdict
  lines.push('---');
  const verdict = getVerdict(data);
  lines.push(verdict);
  lines.push('');
  lines.push('---');
  lines.push('*Generated by [AL Companion Tracker](https://github.com/your-username/al-companion-tracker)*');

  return lines.join('\n');
}

function getVerdict(data: PRCommentData): string {
  if (data.criticalCount > 0 || data.killedSessions > 0) {
    return '> ☠️ **HIGH RISK** — Critical threats detected during AI agent sessions. Review carefully before merging.';
  }
  if (data.dangerCount >= 5) {
    return '> 🔴 **ELEVATED RISK** — Multiple danger-level alerts fired. Recommend thorough review of AI-generated changes.';
  }
  if (data.dangerCount >= 1) {
    return '> ⚠️ **CAUTION** — Danger alerts were raised during AI agent work. Check flagged items above.';
  }
  if (data.warnCount > 10) {
    return '> ⚠️ **REVIEW** — Elevated number of warnings. AI sessions may warrant closer inspection.';
  }
  if (data.warnCount > 0) {
    return '> ✅ **LOW RISK** — Minor warnings only. AI agent activity appears routine.';
  }
  return '> ✅ **CLEAN** — No alerts fired. AI agent sessions were clean.';
}

// ── Comment signature for idempotent updates ──

export const PR_COMMENT_SIGNATURE = '<!-- al-companion-tracker-pr-bot -->';

/**
 * Wraps the comment with a hidden signature so we can find and update it later.
 */
export function wrapComment(body: string): string {
  return `${PR_COMMENT_SIGNATURE}\n${body}`;
}
