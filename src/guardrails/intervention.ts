/**
 * Intervention Queue — real-time approve/deny for dangerous agent actions.
 *
 * When guardrails fire in 'block' mode, the action lands here as a pending
 * intervention. The dashboard shows it immediately (via SSE) and the user
 * can approve, deny, or let it auto-deny after a timeout.
 *
 * Flow:
 *   watcher → guardrails fire → createIntervention() → SSE 'intervention-pending'
 *   dashboard → user clicks Approve/Deny → resolveIntervention()
 *   watcher → checks resolution (or auto-deny after timeout)
 */

import { RiskLevel } from '../parser/event-types';

export type InterventionStatus = 'pending' | 'approved' | 'denied' | 'expired';

export interface Intervention {
  id: string;
  sessionId: string;
  timestamp: string;
  /** The guardrail rule that fired */
  rule: string;
  severity: RiskLevel;
  /** Human-readable description of what the agent is trying to do */
  message: string;
  /** What kind of action — file write, command, network, etc. */
  actionType: string;
  /** The specific target: file path, command string, URL, etc. */
  actionTarget: string;
  /** Current status */
  status: InterventionStatus;
  /** Who resolved it: 'user' | 'auto-timeout' | null */
  resolvedBy: string | null;
  /** When it was resolved */
  resolvedAt: string | null;
  /** Provider (copilot, claude-code, etc.) */
  provider: string;
}

// ── In-memory queue (fast, no DB round-trip for real-time decisions) ──

const pendingQueue = new Map<string, Intervention>();
const resolvedQueue: Intervention[] = []; // ring buffer, last 200
const MAX_RESOLVED = 200;

// Listeners for when interventions are resolved
type ResolveListener = (intervention: Intervention) => void;
const resolveListeners = new Map<string, ResolveListener[]>();

let idCounter = 0;

/** Auto-deny timeout in ms. Default 30 seconds — if user doesn't respond, deny. */
let autoDenyMs = 30_000;
const autoDenyTimers = new Map<string, ReturnType<typeof setTimeout>>();

export function setAutoDenyTimeout(ms: number): void {
  autoDenyMs = ms;
}

export function getAutoDenyTimeout(): number {
  return autoDenyMs;
}

/**
 * Create a new pending intervention. Returns the intervention object.
 * The caller (watcher) should broadcast this via SSE.
 */
export function createIntervention(params: {
  sessionId: string;
  rule: string;
  severity: RiskLevel;
  message: string;
  actionType: string;
  actionTarget: string;
  provider: string;
}): Intervention {
  const id = `int-${Date.now()}-${++idCounter}`;
  const intervention: Intervention = {
    id,
    sessionId: params.sessionId,
    timestamp: new Date().toISOString(),
    rule: params.rule,
    severity: params.severity,
    message: params.message,
    actionType: params.actionType,
    actionTarget: params.actionTarget,
    status: 'pending',
    resolvedBy: null,
    resolvedAt: null,
    provider: params.provider,
  };

  pendingQueue.set(id, intervention);

  // Start auto-deny timer
  const timer = setTimeout(() => {
    if (pendingQueue.has(id)) {
      resolveIntervention(id, 'denied', 'auto-timeout');
    }
  }, autoDenyMs);
  autoDenyTimers.set(id, timer);

  return intervention;
}

/**
 * Resolve a pending intervention (approve or deny).
 * Returns the resolved intervention, or null if not found/already resolved.
 */
export function resolveIntervention(
  id: string,
  status: 'approved' | 'denied',
  resolvedBy: string = 'user'
): Intervention | null {
  const intervention = pendingQueue.get(id);
  if (!intervention) return null;

  intervention.status = status;
  intervention.resolvedBy = resolvedBy;
  intervention.resolvedAt = new Date().toISOString();

  // Move from pending to resolved
  pendingQueue.delete(id);

  // Clear auto-deny timer
  const timer = autoDenyTimers.get(id);
  if (timer) {
    clearTimeout(timer);
    autoDenyTimers.delete(id);
  }

  // Add to resolved ring buffer
  resolvedQueue.push(intervention);
  if (resolvedQueue.length > MAX_RESOLVED) resolvedQueue.shift();

  // Notify listeners
  const listeners = resolveListeners.get(id);
  if (listeners) {
    for (const fn of listeners) fn(intervention);
    resolveListeners.delete(id);
  }

  return intervention;
}

/**
 * Wait for an intervention to be resolved (approve/deny/expire).
 * Returns a promise that resolves with the intervention.
 * Has its own timeout fallback in case auto-deny timer is cleared.
 */
export function waitForResolution(id: string, timeoutMs?: number): Promise<Intervention> {
  const intervention = pendingQueue.get(id);
  if (!intervention) {
    // Already resolved? Check resolved queue
    const resolved = resolvedQueue.find(i => i.id === id);
    if (resolved) return Promise.resolve(resolved);
    return Promise.reject(new Error(`Intervention ${id} not found`));
  }

  return new Promise((resolve) => {
    const existing = resolveListeners.get(id) || [];
    existing.push(resolve);
    resolveListeners.set(id, existing);

    // Safety fallback timeout
    const fallback = timeoutMs || autoDenyMs + 5000;
    setTimeout(() => {
      if (pendingQueue.has(id)) {
        resolveIntervention(id, 'denied', 'timeout-fallback');
      }
    }, fallback);
  });
}

/** Get all pending interventions */
export function getPendingInterventions(): Intervention[] {
  return Array.from(pendingQueue.values()).sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );
}

/** Get recent resolved interventions */
export function getResolvedInterventions(limit = 50): Intervention[] {
  return resolvedQueue.slice(-limit).reverse();
}

/** Get all interventions (pending + resolved) */
export function getAllInterventions(limit = 100): Intervention[] {
  const all = [
    ...Array.from(pendingQueue.values()),
    ...resolvedQueue,
  ];
  return all
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, limit);
}

/** Get a single intervention by ID */
export function getIntervention(id: string): Intervention | null {
  return pendingQueue.get(id) || resolvedQueue.find(i => i.id === id) || null;
}

/** Deny all pending interventions (emergency kill-all) */
export function denyAllPending(): Intervention[] {
  const denied: Intervention[] = [];
  for (const [id] of pendingQueue) {
    const result = resolveIntervention(id, 'denied', 'user-kill-all');
    if (result) denied.push(result);
  }
  return denied;
}

/** Stats for the intervention system */
export function getInterventionStats(): {
  pending: number;
  totalResolved: number;
  approved: number;
  denied: number;
  expired: number;
  avgResponseTimeMs: number;
} {
  const approved = resolvedQueue.filter(i => i.status === 'approved').length;
  const denied = resolvedQueue.filter(i => i.status === 'denied' && i.resolvedBy === 'user').length;
  const expired = resolvedQueue.filter(i => i.resolvedBy === 'auto-timeout' || i.resolvedBy === 'timeout-fallback').length;

  // Average response time for user-resolved interventions
  const userResolved = resolvedQueue.filter(i => i.resolvedBy === 'user' || i.resolvedBy === 'user-kill-all');
  const avgMs = userResolved.length > 0
    ? userResolved.reduce((sum, i) => {
        const created = new Date(i.timestamp).getTime();
        const resolved = new Date(i.resolvedAt!).getTime();
        return sum + (resolved - created);
      }, 0) / userResolved.length
    : 0;

  return {
    pending: pendingQueue.size,
    totalResolved: resolvedQueue.length,
    approved,
    denied,
    expired,
    avgResponseTimeMs: Math.round(avgMs),
  };
}

/** Clear all state — for testing */
export function _resetForTesting(): void {
  pendingQueue.clear();
  resolvedQueue.length = 0;
  resolveListeners.clear();
  for (const timer of autoDenyTimers.values()) clearTimeout(timer);
  autoDenyTimers.clear();
  idCounter = 0;
}
