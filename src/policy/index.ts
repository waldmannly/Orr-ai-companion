/**
 * Policy Engine — Enterprise-grade policy enforcement
 *
 * Three deployment tiers:
 *   individual → No policy enforcement, config.json only
 *   team       → Shared rules + RBAC + admin-locked config fields
 *   enterprise → Org-level policy.json that sets floor guardrails (strictest-wins merge)
 *
 * Policy hierarchy: org policy → team rules → user config
 * Merge strategy: "strictest wins" — org sets floors, users can only tighten
 */

import * as fs from 'fs';
import * as path from 'path';
import { getDb } from '../storage/db';
import { GuardrailsConfig, GUARDRAILS_DEFAULTS } from '../guardrails';

// ── Types ──

export type DeploymentTier = 'individual' | 'team' | 'enterprise';

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  /** What the rule controls */
  category: 'command_block' | 'file_scope' | 'network' | 'token_budget' | 'alert_level' | 'compliance' | 'provider_restrict';
  /** The enforcement action */
  enforcement: 'block' | 'alert' | 'log';
  /** Pattern or value for this rule */
  value: string;
  /** Is this rule locked? Locked rules cannot be overridden by lower tiers */
  locked: boolean;
  /** Who created this rule */
  source: 'org' | 'team' | 'user';
  enabled: boolean;
}

/** Org-level policy document (loaded from policy.json or pushed from central server) */
export interface OrgPolicy {
  /** Unique org identifier */
  orgId: string;
  orgName: string;
  /** Policy version for change tracking */
  version: number;
  /** When this policy was last updated */
  updatedAt: string;
  /** Which tier this instance runs at */
  tier: DeploymentTier;

  /** Guardrail floors — merged with config using strictest-wins */
  guardrails: {
    /** Minimum enforcement mode (if org says 'block', user cannot set 'alert') */
    minMode: 'alert' | 'block';
    /** Commands always blocked across the org (merged with user list) */
    blockedCommands: string[];
    /** File patterns always blocked across the org (merged with user list) */
    scopeBlockPatterns: string[];
    /** Allowed outbound domains (if set, user cannot add more — intersection) */
    networkAllowlist: string[];
    /** Max tokens per session (org sets ceiling, user can set lower) */
    maxTokensPerSession: number;
    /** Max tokens per day (org sets ceiling, user can set lower) */
    maxTokensPerDay: number;
  };

  /** Which alert categories must be enabled org-wide */
  mandatoryAlerts: string[];

  /** Compliance requirements */
  compliance: {
    /** Force audit chain to be always enabled */
    auditChainRequired: boolean;
    /** Minimum retention period in days (user cannot set lower) */
    minRetentionDays: number;
    /** Require signed session exports */
    signedExportsRequired: boolean;
  };

  /** Restrict which AI providers are allowed */
  allowedProviders: string[];

  /** Metrics that must be collected and cannot be disabled */
  mandatoryMetrics: string[];

  /** Config fields that are locked by org policy (users cannot change these) */
  lockedFields: string[];

  /** Custom policy rules */
  rules: PolicyRule[];
}

/** Effective guardrails after policy merge */
export interface EffectiveGuardrails extends GuardrailsConfig {
  /** Which fields came from org policy (for UI display) */
  policyOverrides: string[];
  /** Merge conflicts that were resolved (for audit) */
  mergeLog: Array<{ field: string; orgValue: any; userValue: any; resolved: 'org' | 'user' }>;
}

// ── Defaults ──

const DEFAULT_ORG_POLICY: OrgPolicy = {
  orgId: '',
  orgName: '',
  version: 0,
  updatedAt: '',
  tier: 'individual',
  guardrails: {
    minMode: 'alert',
    blockedCommands: [],
    scopeBlockPatterns: [],
    networkAllowlist: [],
    maxTokensPerSession: 0,
    maxTokensPerDay: 0,
  },
  mandatoryAlerts: [],
  compliance: {
    auditChainRequired: false,
    minRetentionDays: 0,
    signedExportsRequired: false,
  },
  allowedProviders: [],
  mandatoryMetrics: [],
  lockedFields: [],
  rules: [],
};

// ── State ──

let currentPolicy: OrgPolicy = { ...DEFAULT_ORG_POLICY };
let policyPath = '';

// ── DB Setup ──

export function initPolicyDb(): void {
  // Tables are created in storage/db.ts migrate() — this is a no-op kept for API compat
}

// ── Policy Loading ──

/** Load org policy from policy.json file */
export function loadPolicy(customPath?: string): OrgPolicy {
  policyPath = customPath || path.join(process.cwd(), 'policy.json');

  if (!fs.existsSync(policyPath)) {
    currentPolicy = { ...DEFAULT_ORG_POLICY };
    return currentPolicy;
  }

  try {
    const raw = fs.readFileSync(policyPath, 'utf-8');
    const parsed = JSON.parse(raw);
    currentPolicy = deepMerge(DEFAULT_ORG_POLICY, parsed) as OrgPolicy;
    console.log(`[policy] Loaded org policy: ${currentPolicy.orgName} v${currentPolicy.version} (${currentPolicy.tier})`);
    return currentPolicy;
  } catch (err) {
    console.error('[policy] Failed to parse policy.json, using defaults:', err);
    currentPolicy = { ...DEFAULT_ORG_POLICY };
    return currentPolicy;
  }
}

/** Get current active policy */
export function getPolicy(): OrgPolicy {
  return currentPolicy;
}

/** Get current deployment tier */
export function getTier(): DeploymentTier {
  return currentPolicy.tier;
}

/** Check if a specific config field is locked by org policy */
export function isFieldLocked(fieldPath: string): boolean {
  if (currentPolicy.tier === 'individual') return false;
  return currentPolicy.lockedFields.includes(fieldPath);
}

// ── Policy Merge (strictest-wins) ──

/**
 * Merge org policy guardrails with user guardrails config.
 * Strategy: org sets the floor, user can only tighten.
 *  - Blocked commands: union (org + user)
 *  - Block patterns: union (org + user)
 *  - Network allowlist: intersection (if org restricts, user can't add more)
 *  - Token budgets: org wins if stricter (lower non-zero value)
 *  - Mode: 'block' is stricter than 'alert' (org can force 'block')
 */
export function mergeGuardrails(userConfig: GuardrailsConfig): EffectiveGuardrails {
  const policy = currentPolicy;
  const mergeLog: EffectiveGuardrails['mergeLog'] = [];
  const policyOverrides: string[] = [];

  if (policy.tier === 'individual') {
    return {
      ...userConfig,
      policyOverrides: [],
      mergeLog: [],
    };
  }

  // Mode: block is stricter than alert
  let mode = userConfig.mode;
  if (policy.guardrails.minMode === 'block' && mode === 'alert') {
    mergeLog.push({ field: 'mode', orgValue: 'block', userValue: mode, resolved: 'org' });
    mode = 'block';
    policyOverrides.push('mode');
  }

  // Blocked commands: union
  const blockedCommands = [...new Set([
    ...userConfig.blockedCommands,
    ...policy.guardrails.blockedCommands,
  ])];
  if (policy.guardrails.blockedCommands.length > 0) {
    policyOverrides.push('blockedCommands');
  }

  // Scope block patterns: union
  const scopeBlockPatterns = [...new Set([
    ...userConfig.scopeBlockPatterns,
    ...policy.guardrails.scopeBlockPatterns,
  ])];
  if (policy.guardrails.scopeBlockPatterns.length > 0) {
    policyOverrides.push('scopeBlockPatterns');
  }

  // Network allowlist: intersection (if org specifies one)
  let networkAllowlist = userConfig.networkAllowlist;
  if (policy.guardrails.networkAllowlist.length > 0) {
    if (userConfig.networkAllowlist.length > 0) {
      // Intersection: only domains in BOTH lists
      networkAllowlist = userConfig.networkAllowlist.filter(
        d => policy.guardrails.networkAllowlist.includes(d)
      );
    } else {
      // User had no restriction, org does — use org's list
      networkAllowlist = [...policy.guardrails.networkAllowlist];
    }
    policyOverrides.push('networkAllowlist');
    mergeLog.push({
      field: 'networkAllowlist',
      orgValue: policy.guardrails.networkAllowlist,
      userValue: userConfig.networkAllowlist,
      resolved: 'org',
    });
  }

  // Token budget: lower non-zero wins (stricter)
  let tokenBudget = userConfig.tokenBudget;
  const orgTokens = policy.guardrails.maxTokensPerSession;
  if (orgTokens > 0) {
    if (tokenBudget === 0 || tokenBudget > orgTokens) {
      mergeLog.push({ field: 'tokenBudget', orgValue: orgTokens, userValue: tokenBudget, resolved: 'org' });
      tokenBudget = orgTokens;
      policyOverrides.push('tokenBudget');
    }
  }

  return {
    enabled: userConfig.enabled || true,
    tokenBudget,
    scopeAllowPatterns: userConfig.scopeAllowPatterns,
    scopeBlockPatterns,
    blockedCommands,
    networkAllowlist,
    mode,
    policyOverrides,
    mergeLog,
  };
}

// ── Policy Enforcement ──

export interface PolicyCheckResult {
  allowed: boolean;
  violations: Array<{
    ruleId: string;
    ruleName: string;
    category: string;
    enforcement: 'block' | 'alert' | 'log';
    message: string;
  }>;
}

/** Check an event against all active policy rules */
export function checkPolicy(event: {
  event_type?: string;
  command?: string;
  file_paths?: string[];
  summary?: string;
  session_id?: string;
  provider?: string;
}): PolicyCheckResult {
  const violations: PolicyCheckResult['violations'] = [];
  const policy = currentPolicy;

  if (policy.tier === 'individual') {
    return { allowed: true, violations: [] };
  }

  // Check provider restrictions
  if (policy.allowedProviders.length > 0 && event.provider) {
    if (!policy.allowedProviders.includes(event.provider)) {
      violations.push({
        ruleId: 'org-provider-restrict',
        ruleName: 'Restricted Provider',
        category: 'provider_restrict',
        enforcement: 'block',
        message: `Provider "${event.provider}" is not in the approved list: ${policy.allowedProviders.join(', ')}`,
      });
    }
  }

  // Check custom policy rules
  for (const rule of policy.rules) {
    if (!rule.enabled) continue;

    let matched = false;
    const searchText = [event.command || '', event.summary || '', ...(event.file_paths || [])].join(' ');

    switch (rule.category) {
      case 'command_block':
        if (event.command && event.command.toLowerCase().includes(rule.value.toLowerCase())) {
          matched = true;
        }
        break;
      case 'file_scope':
        if (event.file_paths?.some(f => f.includes(rule.value))) {
          matched = true;
        }
        break;
      case 'network':
        if (searchText.includes(rule.value)) {
          matched = true;
        }
        break;
      default:
        if (searchText.toLowerCase().includes(rule.value.toLowerCase())) {
          matched = true;
        }
    }

    if (matched) {
      violations.push({
        ruleId: rule.id,
        ruleName: rule.name,
        category: rule.category,
        enforcement: rule.enforcement,
        message: `Policy rule "${rule.name}" triggered: ${rule.description}`,
      });
    }
  }

  const blocked = violations.some(v => v.enforcement === 'block');
  return { allowed: !blocked, violations };
}

/** Record a policy violation to the database */
export function recordPolicyViolation(violation: {
  session_id?: string;
  user_id?: string;
  rule_id: string;
  rule_name: string;
  category: string;
  enforcement: string;
  detail: string;
}): void {
  const db = getDb();
  db.prepare(`
    INSERT INTO policy_violations (timestamp, session_id, user_id, rule_id, rule_name, category, enforcement, detail)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    new Date().toISOString(),
    violation.session_id || null,
    violation.user_id || null,
    violation.rule_id,
    violation.rule_name,
    violation.category,
    violation.enforcement,
    violation.detail,
  );
}

/** Record a policy metric */
export function recordPolicyMetric(name: string, value: string, sessionId?: string, metadata?: Record<string, any>): void {
  const db = getDb();
  db.prepare(`
    INSERT INTO policy_metrics (timestamp, metric_name, metric_value, session_id, metadata)
    VALUES (?, ?, ?, ?, ?)
  `).run(
    new Date().toISOString(),
    name,
    value,
    sessionId || null,
    metadata ? JSON.stringify(metadata) : null,
  );
}

// ── Policy Queries ──

export function getPolicyViolations(opts?: { limit?: number; category?: string }): any[] {
  const db = getDb();
  const limit = opts?.limit || 100;
  if (opts?.category) {
    return db.prepare('SELECT * FROM policy_violations WHERE category = ? ORDER BY timestamp DESC LIMIT ?')
      .all(opts.category, limit);
  }
  return db.prepare('SELECT * FROM policy_violations ORDER BY timestamp DESC LIMIT ?').all(limit);
}

export function getPolicyMetrics(opts?: { name?: string; since?: string }): any[] {
  const db = getDb();
  if (opts?.name && opts?.since) {
    return db.prepare('SELECT * FROM policy_metrics WHERE metric_name = ? AND timestamp >= ? ORDER BY timestamp DESC')
      .all(opts.name, opts.since);
  }
  if (opts?.name) {
    return db.prepare('SELECT * FROM policy_metrics WHERE metric_name = ? ORDER BY timestamp DESC LIMIT 100')
      .all(opts.name);
  }
  return db.prepare('SELECT * FROM policy_metrics ORDER BY timestamp DESC LIMIT 100').all();
}

export function getPolicyHistory(): any[] {
  const db = getDb();
  return db.prepare('SELECT id, org_id, org_name, version, tier, applied_at, applied_by FROM org_policies ORDER BY applied_at DESC LIMIT 50').all();
}

export function getPolicySummary(): {
  tier: DeploymentTier;
  orgName: string;
  version: number;
  totalRules: number;
  blockedCommands: number;
  lockedFields: number;
  violationCount: number;
  metricsCount: number;
} {
  const db = getDb();
  const violationCount = (db.prepare('SELECT COUNT(*) as cnt FROM policy_violations').get() as any)?.cnt || 0;
  const metricsCount = (db.prepare('SELECT COUNT(*) as cnt FROM policy_metrics').get() as any)?.cnt || 0;

  return {
    tier: currentPolicy.tier,
    orgName: currentPolicy.orgName,
    version: currentPolicy.version,
    totalRules: currentPolicy.rules.length,
    blockedCommands: currentPolicy.guardrails.blockedCommands.length,
    lockedFields: currentPolicy.lockedFields.length,
    violationCount,
    metricsCount,
  };
}

// ── Policy Update (for enterprise central management) ──

/** Apply a new org policy (e.g., pushed from central server) */
export function applyPolicy(newPolicy: OrgPolicy, appliedBy?: string): OrgPolicy {
  const db = getDb();

  // Record the policy change
  db.prepare(`
    INSERT INTO org_policies (org_id, org_name, version, tier, policy_json, applied_at, applied_by)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    newPolicy.orgId,
    newPolicy.orgName,
    newPolicy.version,
    newPolicy.tier,
    JSON.stringify(newPolicy),
    new Date().toISOString(),
    appliedBy || 'system',
  );

  // Also write to disk so it persists across restarts
  if (policyPath) {
    fs.writeFileSync(policyPath, JSON.stringify(newPolicy, null, 2));
  }

  currentPolicy = newPolicy;

  // Record metric
  recordPolicyMetric('policy_applied', `v${newPolicy.version}`, undefined, {
    org: newPolicy.orgName,
    tier: newPolicy.tier,
    ruleCount: newPolicy.rules.length,
  });

  return currentPolicy;
}

// ── RBAC ──

export type Permission =
  | 'policy.read' | 'policy.write'
  | 'guardrails.read' | 'guardrails.write'
  | 'team.read' | 'team.write'
  | 'config.read' | 'config.write'
  | 'sessions.read' | 'sessions.delete'
  | 'export.read' | 'compliance.read';

const ROLE_PERMISSIONS: Record<string, Permission[]> = {
  admin: [
    'policy.read', 'policy.write',
    'guardrails.read', 'guardrails.write',
    'team.read', 'team.write',
    'config.read', 'config.write',
    'sessions.read', 'sessions.delete',
    'export.read', 'compliance.read',
  ],
  operator: [
    'policy.read',
    'guardrails.read', 'guardrails.write',
    'team.read',
    'config.read', 'config.write',
    'sessions.read',
    'export.read', 'compliance.read',
  ],
  viewer: [
    'policy.read',
    'guardrails.read',
    'team.read',
    'config.read',
    'sessions.read',
    'export.read', 'compliance.read',
  ],
};

/** Check if a role has a specific permission */
export function hasPermission(role: string, permission: Permission): boolean {
  if (currentPolicy.tier === 'individual') return true;
  const perms = ROLE_PERMISSIONS[role];
  if (!perms) return false;
  return perms.includes(permission);
}

/** Express middleware that checks RBAC permissions */
export function requirePermission(permission: Permission) {
  return (req: any, res: any, next: any) => {
    // In individual tier, allow everything
    if (currentPolicy.tier === 'individual') return next();

    const user = req.teamUser;
    if (!user) {
      // No user attached (team auth middleware should have caught this)
      return res.status(401).json({ error: 'Authentication required for this operation' });
    }

    if (!hasPermission(user.role, permission)) {
      recordPolicyViolation({
        user_id: user.id,
        rule_id: 'rbac-denied',
        rule_name: 'RBAC Permission Denied',
        category: 'rbac',
        enforcement: 'block',
        detail: `User "${user.name}" (${user.role}) denied permission: ${permission}`,
      });
      return res.status(403).json({
        error: 'Insufficient permissions',
        required: permission,
        role: user.role,
      });
    }

    next();
  };
}

// ── Helper ──

function deepMerge(target: any, source: any): any {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      result[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      result[key] = source[key];
    }
  }
  return result;
}
