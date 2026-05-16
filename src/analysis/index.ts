/**
 * Memory Content Analysis — injection scoring beyond regex, cross-session diffs.
 *
 * Analyzes memory operation contents for sophistication of injection attempts,
 * tracks content changes across sessions, and generates diff reports.
 */

import { getDb } from '../storage/db';
import type { RiskLevel } from '../parser/event-types';

// ── Types ──

export interface InjectionScore {
  score: number; // 0-100
  level: 'clean' | 'suspicious' | 'likely_injection' | 'confirmed_injection';
  signals: Array<{ pattern: string; weight: number; matched: string }>;
}

export interface MemoryDiff {
  memory_path: string;
  sessions: Array<{
    session_id: string;
    provider: string;
    timestamp: string;
    operation: string;
    content_summary: string;
  }>;
  changeCount: number;
  hasContentDrift: boolean;
  riskEscalation: boolean;
}

export interface MemoryAnalysisReport {
  totalPaths: number;
  pathsWithMultiSessionWrites: number;
  injectionRiskPaths: number;
  diffs: MemoryDiff[];
  topRiskPaths: Array<{ path: string; score: number; writeCount: number }>;
}

// ── Injection Scoring ──

/**
 * Score content for injection sophistication (0-100).
 * Goes beyond simple regex — uses weighted multi-signal analysis.
 */
export function scoreInjection(content: string): InjectionScore {
  const signals: InjectionScore['signals'] = [];
  const lower = content.toLowerCase();

  // Weight table — higher = more suspicious
  const patterns: Array<{ regex: RegExp; name: string; weight: number }> = [
    // Direct instruction override
    { regex: /ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|rules?|prompts?)/i, name: 'instruction_override', weight: 30 },
    { regex: /you\s+are\s+now\s+/i, name: 'persona_hijack', weight: 25 },
    { regex: /system\s*:\s*/i, name: 'system_prompt_injection', weight: 28 },
    { regex: /\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>/i, name: 'format_injection', weight: 35 },

    // Role manipulation
    { regex: /act\s+as\s+(if\s+you\s+are|a|an)\s+/i, name: 'role_assignment', weight: 15 },
    { regex: /pretend\s+(to\s+be|you\s+are)/i, name: 'pretend_directive', weight: 18 },
    { regex: /from\s+now\s+on/i, name: 'persistence_attempt', weight: 12 },
    { regex: /do\s+not\s+follow\s+(your|the)\s+(rules?|instructions?)/i, name: 'rule_bypass', weight: 30 },

    // Data extraction
    { regex: /what\s+(is|are)\s+(your|the)\s+(system|secret|api|hidden)/i, name: 'secret_extraction', weight: 22 },
    { regex: /reveal\s+(your|the)\s+(prompt|instructions?|system)/i, name: 'prompt_reveal', weight: 25 },
    { regex: /output\s+(your|the)\s+(entire|full|complete)\s+(prompt|instructions?|context)/i, name: 'context_dump', weight: 28 },

    // Encoding/obfuscation
    { regex: /base64|rot13|hex\s*encode|atob|btoa/i, name: 'encoding_reference', weight: 10 },
    { regex: /\\u[0-9a-f]{4}/i, name: 'unicode_escape', weight: 8 },
    { regex: /&#x?[0-9a-f]+;/i, name: 'html_entity_encoding', weight: 8 },

    // Boundary markers
    { regex: /={3,}|#{3,}|-{5,}/i, name: 'visual_boundary', weight: 5 },
    { regex: /```\s*(system|admin|root|sudo)/i, name: 'privileged_code_block', weight: 20 },

    // Multi-step / indirect
    { regex: /step\s*1.*step\s*2/is, name: 'multi_step_injection', weight: 15 },
    { regex: /when\s+(asked|prompted|questioned)\s+about/i, name: 'conditional_trigger', weight: 18 },
    { regex: /if\s+anyone\s+asks/i, name: 'conditional_response_override', weight: 20 },
  ];

  for (const p of patterns) {
    const match = content.match(p.regex);
    if (match) {
      signals.push({ pattern: p.name, weight: p.weight, matched: match[0].substring(0, 50) });
    }
  }

  // Additional heuristic: high density of suspicious keywords
  const suspiciousKeywords = ['ignore', 'override', 'bypass', 'inject', 'hijack', 'escalat', 'jailbreak', 'unrestrict'];
  const keywordCount = suspiciousKeywords.filter(k => lower.includes(k)).length;
  if (keywordCount >= 3) {
    signals.push({ pattern: 'keyword_density', weight: keywordCount * 5, matched: `${keywordCount} suspicious keywords` });
  }

  const totalScore = Math.min(100, signals.reduce((sum, s) => sum + s.weight, 0));
  const level: InjectionScore['level'] =
    totalScore >= 60 ? 'confirmed_injection'
    : totalScore >= 35 ? 'likely_injection'
    : totalScore >= 15 ? 'suspicious'
    : 'clean';

  return { score: totalScore, level, signals };
}

// ── Cross-Session Memory Diffs ──

/**
 * Analyze memory operations across sessions to find content drift / conflicts.
 */
export function getMemoryDiffs(memoryPath?: string): MemoryDiff[] {
  const db = getDb();

  let query = `
    SELECT mo.memory_path, mo.session_id, mo.timestamp, mo.operation, mo.content_summary, mo.risk_level,
           s.source_tool as provider
    FROM memory_operations mo
    JOIN sessions s ON mo.session_id = s.id
  `;
  const params: unknown[] = [];
  if (memoryPath) {
    query += ' WHERE mo.memory_path = ?';
    params.push(memoryPath);
  }
  query += ' ORDER BY mo.memory_path, mo.timestamp ASC';

  const rows = db.prepare(query).all(...params) as any[];

  // Group by path
  const pathMap = new Map<string, MemoryDiff>();
  for (const row of rows) {
    if (!pathMap.has(row.memory_path)) {
      pathMap.set(row.memory_path, {
        memory_path: row.memory_path,
        sessions: [],
        changeCount: 0,
        hasContentDrift: false,
        riskEscalation: false,
      });
    }
    const diff = pathMap.get(row.memory_path)!;
    diff.sessions.push({
      session_id: row.session_id,
      provider: row.provider,
      timestamp: row.timestamp,
      operation: row.operation,
      content_summary: row.content_summary,
    });
    if (row.operation === 'write' || row.operation === 'delete') diff.changeCount++;
  }

  // Analyze each path
  for (const diff of pathMap.values()) {
    const uniqueSessions = new Set(diff.sessions.map(s => s.session_id));
    diff.hasContentDrift = uniqueSessions.size > 1 && diff.changeCount > 1;

    // Check for risk escalation (writes getting riskier over time)
    const writes = diff.sessions.filter(s => s.operation === 'write');
    if (writes.length >= 2) {
      const lastWrite = writes[writes.length - 1];
      const injection = scoreInjection(lastWrite.content_summary);
      diff.riskEscalation = injection.score > 15;
    }
  }

  return Array.from(pathMap.values())
    .filter(d => d.sessions.length > 0)
    .sort((a, b) => b.changeCount - a.changeCount);
}

// ── Analysis Report ──

/**
 * Generate a comprehensive memory analysis report.
 */
export function generateMemoryAnalysis(): MemoryAnalysisReport {
  const diffs = getMemoryDiffs();

  // Score all paths for injection risk
  const db = getDb();
  const allWrites = db.prepare(`
    SELECT memory_path, content_summary, COUNT(*) as write_count
    FROM memory_operations WHERE operation = 'write'
    GROUP BY memory_path ORDER BY write_count DESC
  `).all() as any[];

  const topRiskPaths = allWrites.map(w => ({
    path: w.memory_path,
    score: scoreInjection(w.content_summary).score,
    writeCount: w.write_count,
  })).filter(p => p.score > 0).sort((a, b) => b.score - a.score).slice(0, 20);

  return {
    totalPaths: new Set(diffs.map(d => d.memory_path)).size,
    pathsWithMultiSessionWrites: diffs.filter(d => d.hasContentDrift).length,
    injectionRiskPaths: topRiskPaths.filter(p => p.score >= 15).length,
    diffs: diffs.slice(0, 50),
    topRiskPaths,
  };
}
