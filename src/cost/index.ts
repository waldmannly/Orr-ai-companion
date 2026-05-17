/**
 * Cost Estimation — maps token usage to real dollars per provider/model.
 *
 * Pricing is approximate and configurable. Users can override rates in config.
 * Default rates reflect May 2026 public pricing for popular models.
 *
 * The estimator also analyzes spending patterns and recommends ways to reduce costs.
 */

import { getDb } from '../storage/db';
import { Config } from '../config';

// ── Pricing table: $ per 1M tokens (input/output averaged for simplicity) ──
// These are rough blended rates (input + output averaged) since we don't
// distinguish input vs output tokens in the tracker.

export interface ModelPricing {
  /** Model identifier */
  model: string;
  /** Provider (source_tool) this model belongs to */
  provider: string;
  /** Display name */
  name: string;
  /** Cost per 1M tokens (blended input+output) */
  costPer1MTokens: number;
}

// Default pricing table — users can override/extend in config
export const DEFAULT_PRICING: ModelPricing[] = [
  // Claude (via Claude Code CLI)
  { model: 'claude-opus', provider: 'claude-code', name: 'Claude Opus 4', costPer1MTokens: 25.00 },
  { model: 'claude-sonnet', provider: 'claude-code', name: 'Claude Sonnet 4', costPer1MTokens: 6.00 },
  { model: 'claude-haiku', provider: 'claude-code', name: 'Claude Haiku 3.5', costPer1MTokens: 1.60 },

  // VS Code Copilot (GPT-4o, Claude Sonnet, Gemini via Copilot)
  { model: 'gpt-4o', provider: 'vscode-copilot', name: 'GPT-4o (Copilot)', costPer1MTokens: 7.50 },
  { model: 'gpt-4o-mini', provider: 'vscode-copilot', name: 'GPT-4o Mini (Copilot)', costPer1MTokens: 0.60 },
  { model: 'copilot-default', provider: 'vscode-copilot', name: 'Copilot (blended)', costPer1MTokens: 5.00 },

  // Gemini CLI
  { model: 'gemini-2.5-pro', provider: 'gemini-cli', name: 'Gemini 2.5 Pro', costPer1MTokens: 5.00 },
  { model: 'gemini-2.5-flash', provider: 'gemini-cli', name: 'Gemini 2.5 Flash', costPer1MTokens: 0.60 },
  { model: 'gemini-default', provider: 'gemini-cli', name: 'Gemini (blended)', costPer1MTokens: 3.00 },
];

// Fallback rate per provider when we can't determine the specific model
const PROVIDER_FALLBACK_RATE: Record<string, number> = {
  'claude-code': 10.00,     // Assume a mix of Opus + Sonnet
  'vscode-copilot': 5.00,   // Copilot blended rate
  'gemini-cli': 3.00,       // Gemini blended
};
const DEFAULT_FALLBACK_RATE = 5.00; // Unknown providers

// ── Cost calculation ──

export interface CostEstimate {
  tokens: number;
  costUSD: number;
  ratePer1M: number;
  provider: string;
  model: string;
}

export interface SessionCost {
  sessionId: string;
  provider: string;
  tokens: number;
  costUSD: number;
  startedAt: string;
  projectName: string;
}

export interface DailyCost {
  date: string;
  tokens: number;
  costUSD: number;
  byProvider: Record<string, { tokens: number; costUSD: number }>;
}

export interface CostSummary {
  totalTokens: number;
  totalCostUSD: number;
  dailyAvgUSD: number;
  monthlyEstimateUSD: number;
  byProvider: Record<string, { tokens: number; costUSD: number; sessions: number }>;
  topSessions: SessionCost[];
  dailyCosts: DailyCost[];
  daysTracked: number;
}

/**
 * Get the cost rate for a provider. Uses custom pricing from config if available,
 * otherwise falls back to the default table.
 */
export function getRateForProvider(provider: string, config: Config): number {
  const customPricing = config.costEstimation?.customPricing;
  if (customPricing && customPricing.length > 0) {
    const match = customPricing.find(p => p.provider === provider);
    if (match) return match.costPer1MTokens;
  }
  return PROVIDER_FALLBACK_RATE[provider] || DEFAULT_FALLBACK_RATE;
}

/**
 * Estimate cost for a given token count and provider.
 */
export function estimateCost(tokens: number, provider: string, config: Config): CostEstimate {
  const rate = getRateForProvider(provider, config);
  return {
    tokens,
    costUSD: (tokens / 1_000_000) * rate,
    ratePer1M: rate,
    provider,
    model: 'default',
  };
}

/**
 * Get cost breakdown for a specific session.
 */
export function getSessionCost(sessionId: string, config: Config): SessionCost | null {
  const db = getDb();
  const session = db.prepare('SELECT id, source_tool, started_at, project_name FROM sessions WHERE id = ?')
    .get(sessionId) as { id: string; source_tool: string; started_at: string; project_name: string } | undefined;
  if (!session) return null;

  const tokens = (db.prepare('SELECT COALESCE(SUM(token_count), 0) as total FROM events WHERE session_id = ? AND token_count IS NOT NULL')
    .get(sessionId) as { total: number }).total;

  const rate = getRateForProvider(session.source_tool, config);
  return {
    sessionId,
    provider: session.source_tool,
    tokens,
    costUSD: (tokens / 1_000_000) * rate,
    startedAt: session.started_at,
    projectName: session.project_name,
  };
}

/**
 * Get full cost summary over N days (default: 30).
 */
export function getCostSummary(config: Config, days = 30): CostSummary {
  const db = getDb();
  const since = new Date(Date.now() - days * 86400000).toISOString();

  // Get all sessions in the time window
  const sessions = db.prepare(`
    SELECT id, source_tool, started_at, project_name, token_count
    FROM sessions WHERE started_at >= ? ORDER BY started_at DESC
  `).all(since) as Array<{ id: string; source_tool: string; started_at: string; project_name: string; token_count: number }>;

  // Aggregate by provider
  const byProvider: Record<string, { tokens: number; costUSD: number; sessions: number }> = {};
  const sessionCosts: SessionCost[] = [];

  // Batch token query — single query instead of N queries
  const sessionIds = sessions.map(s => s.id);
  const tokensBySession = new Map<string, number>();
  if (sessionIds.length > 0) {
    const placeholders = sessionIds.map(() => '?').join(',');
    const tokenRows = db.prepare(
      `SELECT session_id, COALESCE(SUM(token_count), 0) as total
       FROM events WHERE session_id IN (${placeholders}) AND token_count IS NOT NULL
       GROUP BY session_id`
    ).all(...sessionIds) as Array<{ session_id: string; total: number }>;
    for (const r of tokenRows) tokensBySession.set(r.session_id, r.total);
  }

  for (const s of sessions) {
    const tokens = tokensBySession.get(s.id) || s.token_count || 0;

    const rate = getRateForProvider(s.source_tool, config);
    const cost = (tokens / 1_000_000) * rate;

    if (!byProvider[s.source_tool]) {
      byProvider[s.source_tool] = { tokens: 0, costUSD: 0, sessions: 0 };
    }
    byProvider[s.source_tool].tokens += tokens;
    byProvider[s.source_tool].costUSD += cost;
    byProvider[s.source_tool].sessions += 1;

    sessionCosts.push({
      sessionId: s.id,
      provider: s.source_tool,
      tokens,
      costUSD: cost,
      startedAt: s.started_at,
      projectName: s.project_name,
    });
  }

  // Daily costs from daily_token_usage table
  const dailyRows = db.prepare(`
    SELECT dtu.date, dtu.tokens, s.source_tool
    FROM daily_token_usage dtu
    JOIN sessions s ON dtu.session_id = s.id
    WHERE dtu.date >= ?
    ORDER BY dtu.date DESC
  `).all(since.slice(0, 10)) as Array<{ date: string; tokens: number; source_tool: string }>;

  const dailyMap = new Map<string, DailyCost>();
  for (const row of dailyRows) {
    if (!dailyMap.has(row.date)) {
      dailyMap.set(row.date, { date: row.date, tokens: 0, costUSD: 0, byProvider: {} });
    }
    const day = dailyMap.get(row.date)!;
    const rate = getRateForProvider(row.source_tool, config);
    const cost = (row.tokens / 1_000_000) * rate;
    day.tokens += row.tokens;
    day.costUSD += cost;
    if (!day.byProvider[row.source_tool]) {
      day.byProvider[row.source_tool] = { tokens: 0, costUSD: 0 };
    }
    day.byProvider[row.source_tool].tokens += row.tokens;
    day.byProvider[row.source_tool].costUSD += cost;
  }

  const dailyCosts = [...dailyMap.values()].sort((a, b) => b.date.localeCompare(a.date));

  // Totals
  const totalTokens = Object.values(byProvider).reduce((a, p) => a + p.tokens, 0);
  const totalCostUSD = Object.values(byProvider).reduce((a, p) => a + p.costUSD, 0);
  const daysTracked = Math.max(1, dailyCosts.length);
  const dailyAvgUSD = totalCostUSD / daysTracked;

  // Top sessions by cost (most expensive first)
  const topSessions = sessionCosts
    .sort((a, b) => b.costUSD - a.costUSD)
    .slice(0, 10);

  return {
    totalTokens,
    totalCostUSD,
    dailyAvgUSD,
    monthlyEstimateUSD: dailyAvgUSD * 30,
    byProvider,
    topSessions,
    dailyCosts,
    daysTracked,
  };
}

// ── Cost Reduction Recommendations ──

export interface CostRecommendation {
  id: string;
  priority: 'high' | 'medium' | 'low';
  title: string;
  detail: string;
  estimatedSavings: string;
}

/**
 * Analyze spending patterns and generate recommendations to reduce costs.
 */
export function getCostRecommendations(config: Config): CostRecommendation[] {
  const db = getDb();
  const recommendations: CostRecommendation[] = [];
  const since7d = new Date(Date.now() - 7 * 86400000).toISOString();

  // 1. Check for expensive providers — suggest cheaper alternatives
  const providerTokens = db.prepare(`
    SELECT source_tool, SUM(token_count) as total_tokens, COUNT(*) as event_count
    FROM events WHERE timestamp >= ? AND token_count IS NOT NULL
    GROUP BY source_tool ORDER BY total_tokens DESC
  `).all(since7d) as Array<{ source_tool: string; total_tokens: number; event_count: number }>;

  for (const p of providerTokens) {
    const rate = getRateForProvider(p.source_tool, config);
    if (rate >= 15) {
      // Using an expensive model like Opus
      const currentCost = (p.total_tokens / 1_000_000) * rate;
      const cheaperCost = (p.total_tokens / 1_000_000) * 5;
      recommendations.push({
        id: `expensive-provider-${p.source_tool}`,
        priority: 'high',
        title: `Switch ${p.source_tool} to a cheaper model tier`,
        detail: `You used ${(p.total_tokens / 1000).toFixed(0)}K tokens on ${p.source_tool} this week at ~$${rate}/1M tokens. Consider using Sonnet/Haiku for routine tasks and reserving Opus for complex work.`,
        estimatedSavings: `~$${(currentCost - cheaperCost).toFixed(2)}/week`,
      });
    }
  }

  // 2. Find sessions with very high token counts (runaway sessions)
  const bigSessions = db.prepare(`
    SELECT session_id, SUM(token_count) as tokens, COUNT(*) as events
    FROM events WHERE timestamp >= ? AND token_count IS NOT NULL
    GROUP BY session_id HAVING tokens > 50000
    ORDER BY tokens DESC LIMIT 5
  `).all(since7d) as Array<{ session_id: string; tokens: number; events: number }>;

  if (bigSessions.length > 0) {
    const biggest = bigSessions[0];
    recommendations.push({
      id: 'runaway-sessions',
      priority: 'high',
      title: 'Set token budget to catch runaway sessions',
      detail: `Your biggest session this week used ${(biggest.tokens / 1000).toFixed(0)}K tokens (${biggest.events} events). Set tokenBudget.maxPerSession to cap spending. Recommended: ${Math.round(biggest.tokens * 0.8)} tokens.`,
      estimatedSavings: `Prevents sessions exceeding ${(biggest.tokens / 1000).toFixed(0)}K tokens`,
    });
  }

  // 3. Check for long assistant messages (verbose responses burn tokens)
  const verboseMessages = db.prepare(`
    SELECT AVG(LENGTH(raw_log)) as avg_len, COUNT(*) as count
    FROM events WHERE event_type = 'assistant_message' AND timestamp >= ?
  `).get(since7d) as { avg_len: number | null; count: number };

  if (verboseMessages.avg_len && verboseMessages.avg_len > 2000) {
    recommendations.push({
      id: 'verbose-responses',
      priority: 'medium',
      title: 'AI responses are verbose — add conciseness instructions',
      detail: `Average AI response length is ${Math.round(verboseMessages.avg_len)} chars (~${Math.round(verboseMessages.avg_len / 4)} tokens). Add "be concise" or "minimal explanation" to your system prompts. Even 30% reduction on ${verboseMessages.count} responses saves significant tokens.`,
      estimatedSavings: `~${Math.round(verboseMessages.count * verboseMessages.avg_len * 0.3 / 4)} tokens/week`,
    });
  }

  // 4. Identify repeated/similar prompts (duplicate work)
  const repeatedPrompts = db.prepare(`
    SELECT content, COUNT(*) as times, SUM(token_count) as total_tokens
    FROM prompts WHERE timestamp >= ?
    GROUP BY content HAVING times > 2
    ORDER BY total_tokens DESC LIMIT 3
  `).all(since7d) as Array<{ content: string; times: number; total_tokens: number }>;

  if (repeatedPrompts.length > 0) {
    const totalWasted = repeatedPrompts.reduce((a, p) => a + p.total_tokens * (p.times - 1) / p.times, 0);
    recommendations.push({
      id: 'repeated-prompts',
      priority: 'medium',
      title: 'Duplicate prompts detected — cache or template them',
      detail: `Found ${repeatedPrompts.length} prompts sent 3+ times this week. The most repeated was sent ${repeatedPrompts[0].times} times. Consider using saved prompts, templates, or fixing the workflow that causes retries.`,
      estimatedSavings: `~${Math.round(totalWasted)} tokens/week from dedup`,
    });
  }

  // 5. Check for high file_read token usage (reading large files repeatedly)
  const fileReads = db.prepare(`
    SELECT SUM(token_count) as tokens, COUNT(*) as count
    FROM events WHERE event_type = 'file_read' AND timestamp >= ? AND token_count IS NOT NULL
  `).get(since7d) as { tokens: number | null; count: number };

  if (fileReads.tokens && fileReads.count > 50 && fileReads.tokens > 20000) {
    recommendations.push({
      id: 'excessive-file-reads',
      priority: 'low',
      title: 'High token usage from file reads',
      detail: `${fileReads.count} file reads consumed ${(fileReads.tokens / 1000).toFixed(0)}K tokens this week. Large files sent to the AI cost tokens. Consider using targeted reads (line ranges) instead of full-file reads, or add files to .copilotignore.`,
      estimatedSavings: `~${Math.round(fileReads.tokens * 0.4)} tokens/week with targeted reads`,
    });
  }

  // 6. Check for sessions without token budgets
  if (!config.tokenBudget.maxPerSession && !config.tokenBudget.maxPerDay) {
    recommendations.push({
      id: 'no-budget-set',
      priority: 'medium',
      title: 'No token budget configured',
      detail: 'Without a budget, there\'s no safety net for runaway sessions. Set tokenBudget.maxPerSession and tokenBudget.maxPerDay to prevent surprise bills.',
      estimatedSavings: 'Prevents unlimited spend',
    });
  }

  // 7. Time-of-day analysis — late night sessions tend to be longer/wasteful
  const lateNight = db.prepare(`
    SELECT COUNT(DISTINCT session_id) as sessions, SUM(token_count) as tokens
    FROM events WHERE timestamp >= ?
      AND CAST(strftime('%H', timestamp) AS INTEGER) BETWEEN 0 AND 5
      AND token_count IS NOT NULL
  `).get(since7d) as { sessions: number; tokens: number | null };

  if (lateNight.sessions > 2 && lateNight.tokens && lateNight.tokens > 10000) {
    recommendations.push({
      id: 'late-night-sessions',
      priority: 'low',
      title: 'Late-night sessions tend to be more expensive',
      detail: `${lateNight.sessions} sessions between midnight and 5am used ${(lateNight.tokens / 1000).toFixed(0)}K tokens. Tired developers tend to have more retries and longer debugging loops with AI.`,
      estimatedSavings: 'Qualitative — fewer retries = fewer tokens',
    });
  }

  // 8. Suggest model downgrade for specific task types
  const taskTypes = db.prepare(`
    SELECT event_type, SUM(token_count) as tokens, COUNT(*) as count
    FROM events WHERE timestamp >= ? AND token_count IS NOT NULL
    GROUP BY event_type ORDER BY tokens DESC LIMIT 3
  `).all(since7d) as Array<{ event_type: string; tokens: number; count: number }>;

  const simpleTypes = ['file_read', 'terminal_command', 'search'];
  const highTokenSimple = taskTypes.filter(t => simpleTypes.includes(t.event_type) && t.tokens > 10000);
  if (highTokenSimple.length > 0) {
    recommendations.push({
      id: 'model-downgrade-simple-tasks',
      priority: 'low',
      title: 'Use a smaller model for simple tasks',
      detail: `Simple operations (file reads, searches, terminal commands) consumed ${(highTokenSimple.reduce((a, t) => a + t.tokens, 0) / 1000).toFixed(0)}K tokens. If your provider supports model routing, use a cheaper model (Haiku, Flash, Mini) for these.`,
      estimatedSavings: '50-80% on routed tasks',
    });
  }

  return recommendations.sort((a, b) => {
    const order = { high: 0, medium: 1, low: 2 };
    return order[a.priority] - order[b.priority];
  });
}

/**
 * Get a quick cost estimate for today.
 */
export function getTodayCost(config: Config): { tokens: number; costUSD: number; budget: number; percentUsed: number } {
  const db = getDb();
  const today = new Date().toISOString().slice(0, 10);

  const row = db.prepare(`
    SELECT COALESCE(SUM(dtu.tokens), 0) as tokens
    FROM daily_token_usage dtu WHERE dtu.date = ?
  `).get(today) as { tokens: number };

  // Try to get per-provider breakdown for better estimate
  const providerRows = db.prepare(`
    SELECT s.source_tool, SUM(dtu.tokens) as tokens
    FROM daily_token_usage dtu
    JOIN sessions s ON dtu.session_id = s.id
    WHERE dtu.date = ?
    GROUP BY s.source_tool
  `).all(today) as Array<{ source_tool: string; tokens: number }>;

  let costUSD = 0;
  if (providerRows.length > 0) {
    for (const pr of providerRows) {
      const rate = getRateForProvider(pr.source_tool, config);
      costUSD += (pr.tokens / 1_000_000) * rate;
    }
  } else {
    costUSD = (row.tokens / 1_000_000) * DEFAULT_FALLBACK_RATE;
  }

  const budget = config.tokenBudget.maxPerDay || 0;
  const percentUsed = budget > 0 ? (row.tokens / budget) * 100 : 0;

  return { tokens: row.tokens, costUSD, budget, percentUsed };
}

/**
 * Get the available pricing models (for UI display).
 */
export function getAvailablePricing(config: Config): ModelPricing[] {
  const customPricing = config.costEstimation?.customPricing;
  return (customPricing && customPricing.length > 0) ? customPricing : DEFAULT_PRICING;
}
