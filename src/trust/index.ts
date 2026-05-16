/**
 * Trust Scoring System
 * 
 * Tracks cumulative trust per AI provider based on session history.
 * Score decays on incidents, recovers on clean sessions.
 * Provides A-F grading and cross-provider comparison.
 */

import { getDb } from '../storage/db';

export interface TrustScore {
  provider: string;
  score: number;         // 0-100
  grade: string;         // A-F
  totalSessions: number;
  cleanSessions: number;
  incidents: number;
  lastUpdated: string;
}

export interface TrustUpdate {
  provider: string;
  sessionId: string;
  dangerCount: number;
  warnCount: number;
  totalEvents: number;
}

// Score thresholds for grading
function gradeFromScore(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 65) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

/**
 * Update trust score when a session ends.
 * Clean sessions boost score, incidents decay it.
 */
export function updateTrustScore(update: TrustUpdate): TrustScore {
  const db = getDb();
  const now = new Date().toISOString();

  // Get or create existing score
  const existing = db.prepare(
    'SELECT * FROM trust_scores WHERE provider = ?'
  ).get(update.provider) as { provider: string; score: number; total_sessions: number; clean_sessions: number; incidents: number } | undefined;

  let score: number;
  let totalSessions: number;
  let cleanSessions: number;
  let incidents: number;

  if (existing) {
    totalSessions = existing.total_sessions + 1;
    const isClean = update.dangerCount === 0 && update.warnCount <= 2;
    cleanSessions = existing.clean_sessions + (isClean ? 1 : 0);
    const newIncidents = update.dangerCount > 0 ? 1 : 0;
    incidents = existing.incidents + newIncidents;

    // Calculate new score with decay/recovery
    score = existing.score;
    if (update.dangerCount >= 5) {
      score = Math.max(0, score - 15); // Major incident
    } else if (update.dangerCount >= 1) {
      score = Math.max(0, score - (5 * update.dangerCount)); // Each danger costs 5 points
    } else if (update.warnCount > 5) {
      score = Math.max(0, score - 2); // Excessive warnings
    } else if (isClean) {
      score = Math.min(100, score + 1); // Slow recovery for clean sessions
    }

    db.prepare(`
      UPDATE trust_scores SET score = ?, total_sessions = ?, clean_sessions = ?, incidents = ?, last_updated = ?
      WHERE provider = ?
    `).run(score, totalSessions, cleanSessions, incidents, now, update.provider);
  } else {
    // First session for this provider
    totalSessions = 1;
    const isClean = update.dangerCount === 0 && update.warnCount <= 2;
    cleanSessions = isClean ? 1 : 0;
    incidents = update.dangerCount > 0 ? 1 : 0;
    score = isClean ? 85 : Math.max(50, 85 - update.dangerCount * 10);

    db.prepare(`
      INSERT INTO trust_scores (provider, score, total_sessions, clean_sessions, incidents, last_updated)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(update.provider, score, totalSessions, cleanSessions, incidents, now);
  }

  return {
    provider: update.provider,
    score,
    grade: gradeFromScore(score),
    totalSessions,
    cleanSessions,
    incidents,
    lastUpdated: now,
  };
}

/**
 * Get trust score for a specific provider.
 */
export function getTrustScore(provider: string): TrustScore | null {
  const db = getDb();
  const row = db.prepare('SELECT * FROM trust_scores WHERE provider = ?').get(provider) as {
    provider: string; score: number; total_sessions: number; clean_sessions: number; incidents: number; last_updated: string;
  } | undefined;
  if (!row) return null;
  return {
    provider: row.provider,
    score: row.score,
    grade: gradeFromScore(row.score),
    totalSessions: row.total_sessions,
    cleanSessions: row.clean_sessions,
    incidents: row.incidents,
    lastUpdated: row.last_updated,
  };
}

/**
 * Get all provider trust scores for comparison.
 */
export function getAllTrustScores(): TrustScore[] {
  const db = getDb();
  const rows = db.prepare('SELECT * FROM trust_scores ORDER BY score DESC').all() as Array<{
    provider: string; score: number; total_sessions: number; clean_sessions: number; incidents: number; last_updated: string;
  }>;
  return rows.map(row => ({
    provider: row.provider,
    score: row.score,
    grade: gradeFromScore(row.score),
    totalSessions: row.total_sessions,
    cleanSessions: row.clean_sessions,
    incidents: row.incidents,
    lastUpdated: row.last_updated,
  }));
}

/**
 * Get a comparison summary between providers.
 */
export function getProviderComparison(): Array<{
  provider: string;
  grade: string;
  score: number;
  avgDangerPerSession: number;
  cleanRate: string;
}> {
  const scores = getAllTrustScores();
  return scores.map(s => ({
    provider: s.provider,
    grade: s.grade,
    score: s.score,
    avgDangerPerSession: s.totalSessions > 0 ? Math.round((s.incidents / s.totalSessions) * 100) / 100 : 0,
    cleanRate: s.totalSessions > 0 ? `${Math.round((s.cleanSessions / s.totalSessions) * 100)}%` : '0%',
  }));
}
