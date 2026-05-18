import * as path from 'path';
import * as fs from 'fs';
import { GuardrailsConfig, GUARDRAILS_DEFAULTS } from '../guardrails';

export interface AlertRuleConfig {
  enabled: boolean;
  minSeverity: 'watch' | 'warn' | 'danger';
  /** When true, suppress duplicate alerts of this type within a 30-min window per session. Default: true for bursty rules. */
  dedup?: boolean;
}

export interface WebhookConfig {
  enabled: boolean;
  url: string;
  minSeverity: 'watch' | 'warn' | 'danger';
}

export interface NotificationsConfig {
  slack: WebhookConfig;
  webhook: WebhookConfig;
  teams: WebhookConfig;
  desktop: { enabled: boolean; minSeverity: 'watch' | 'warn' | 'danger' };
}

export interface PRBotConfig {
  enabled: boolean;
  platform: 'github' | 'gitlab' | 'bitbucket';
  /** PAT or app token — prefer ORR_PR_TOKEN env var */
  token: string;
  /** Default repo (owner/repo). Can be overridden per request. */
  repo: string;
  /** Minimum alert severity to include in the comment */
  minSeverity: 'watch' | 'warn' | 'danger' | 'critical';
  /** Include per-session breakdown */
  includeSessions: boolean;
  /** Include trust score */
  includeTrustScore: boolean;
  /** Include individual alerts in the comment */
  includeAlerts: boolean;
  /** Only report on specific providers (empty = all) */
  filterProviders: string[];
}

export interface Config {
  watchPaths: string[];
  sensitiveFiles: {
    patterns: string[];
    exactPaths: string[];
  };
  dangerousCommands: string[];
  alerts: {
    desktopNotifications: boolean;
    minSeverity: string;
  };
  notifications: NotificationsConfig;
  alertRules: {
    destructive_commands: AlertRuleConfig;
    sensitive_files: AlertRuleConfig;
    memory_operations: AlertRuleConfig;
    memory_injection: AlertRuleConfig;
    deployment: AlertRuleConfig;
    ssh_remote: AlertRuleConfig;
    data_exfiltration: AlertRuleConfig;
    suspicious_download: AlertRuleConfig;
    suspicious_fetch: AlertRuleConfig;
    supply_chain: AlertRuleConfig;
    network_access: AlertRuleConfig;
    force_push: AlertRuleConfig;
    file_operations: AlertRuleConfig;
    git_operations: AlertRuleConfig;
    subagent_spawn: AlertRuleConfig;
  };
  dashboard: {
    port: number;
    host: string;
  };
  retention: {
    maxAgeDays: number;
    maxDbSizeMB: number;
  };
  customProviders: Array<{
    id: string;
    name: string;
    paths: string[];
    icon?: string;
  }>;
  guardrails: GuardrailsConfig;
  /** Directory for community rule packs */
  rulePacksDir: string;
  /** Token budget enforcement */
  tokenBudget: {
    /** Max tokens per session (0 = unlimited) */
    maxPerSession: number;
    /** Max tokens per day across all sessions (0 = unlimited) */
    maxPerDay: number;
    /** Action when budget exceeded: 'warn' or 'kill' */
    action: 'warn' | 'kill';
  };
  prBot: PRBotConfig;
  /** Cost estimation settings */
  costEstimation: {
    /** Override cost rates per provider ($/1M tokens blended) */
    customPricing: Array<{
      provider: string;
      model: string;
      name: string;
      costPer1MTokens: number;
    }>;
  };
}

const DEFAULT_RULE: AlertRuleConfig = { enabled: true, minSeverity: 'warn' };

const DEFAULTS: Config = {
  watchPaths: [],
  sensitiveFiles: {
    patterns: ['**/.env*', '**/*.pem', '**/*.key', '**/id_rsa*', '**/credentials*', '**/secrets*', '**/personal/**', '**/private/**'],
    exactPaths: [],
  },
  dangerousCommands: [
    'rm -rf', 'git push --force', 'git push -f', 'git reset --hard',
    'DROP TABLE', 'DROP DATABASE', 'format C:', 'del /f /s /q',
    'Remove-Item -Recurse -Force', 'rmdir /s /q',
  ],
  alerts: { desktopNotifications: false, minSeverity: 'warn' },
  notifications: {
    slack: { enabled: false, url: '', minSeverity: 'warn' },
    webhook: { enabled: false, url: '', minSeverity: 'danger' },
    teams: { enabled: false, url: '', minSeverity: 'warn' },
    desktop: { enabled: true, minSeverity: 'danger' },
  },
  alertRules: {
    destructive_commands: { enabled: true, minSeverity: 'danger' },
    sensitive_files: { enabled: true, minSeverity: 'warn' },
    memory_operations: { enabled: false, minSeverity: 'warn' },
    memory_injection: { enabled: true, minSeverity: 'warn' },
    deployment: { enabled: true, minSeverity: 'danger' },
    ssh_remote: { enabled: true, minSeverity: 'danger', dedup: true },
    data_exfiltration: { enabled: true, minSeverity: 'warn' },
    suspicious_download: { enabled: true, minSeverity: 'warn', dedup: true },
    suspicious_fetch: { enabled: true, minSeverity: 'warn' },
    supply_chain: { enabled: true, minSeverity: 'warn' },
    network_access: { enabled: false, minSeverity: 'watch' },
    force_push: { enabled: true, minSeverity: 'warn' },
    file_operations: { enabled: false, minSeverity: 'watch' },
    git_operations: { enabled: false, minSeverity: 'watch' },
    subagent_spawn: { enabled: false, minSeverity: 'watch' },
  },
  dashboard: { port: 3847, host: '127.0.0.1' },
  retention: { maxAgeDays: 90, maxDbSizeMB: 500 },
  customProviders: [],
  guardrails: GUARDRAILS_DEFAULTS,
  rulePacksDir: '',
  tokenBudget: { maxPerSession: 0, maxPerDay: 0, action: 'warn' },
  prBot: {
    enabled: false,
    platform: 'github',
    token: '',
    repo: '',
    minSeverity: 'warn',
    includeSessions: true,
    includeTrustScore: true,
    includeAlerts: true,
    filterProviders: [],
  },
  costEstimation: {
    customPricing: [],
  },
};

let configPath = '';

export function getConfigPath(): string {
  return configPath;
}

export function loadConfig(): Config {
  configPath = path.join(process.cwd(), 'config.json');
  if (fs.existsSync(configPath)) {
    try {
      const raw = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
      return mergeConfig(raw);
    } catch {
      console.warn('[config] Failed to parse config.json, using defaults');
    }
  }
  return { ...DEFAULTS };
}

/**
 * SECURITY: Recursively strip prototype pollution keys from user-supplied objects.
 */
function sanitizeKeys(obj: Record<string, unknown>): Record<string, unknown> {
  const clean: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    // Recursively sanitize nested objects (but not arrays — arrays are value types here)
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      clean[k] = sanitizeKeys(v as Record<string, unknown>);
    } else {
      clean[k] = v;
    }
  }
  return clean;
}

export function mergeConfig(raw: Record<string, unknown>): Config {
  const safe = sanitizeKeys(raw);
  const rawNotif = sanitizeKeys((safe.notifications || {}) as Record<string, unknown>);
  const rawGuardrails = sanitizeKeys((safe.guardrails || {}) as Record<string, unknown>);
  return {
    ...DEFAULTS,
    ...safe,
    sensitiveFiles: { ...DEFAULTS.sensitiveFiles, ...sanitizeKeys((safe.sensitiveFiles as Record<string, unknown> || {})) },
    alerts: { ...DEFAULTS.alerts, ...sanitizeKeys((safe.alerts as Record<string, unknown> || {})) },
    notifications: {
      slack: { ...DEFAULTS.notifications.slack, ...sanitizeKeys((rawNotif.slack as Record<string, unknown> || {})) },
      teams: { ...DEFAULTS.notifications.teams, ...sanitizeKeys((rawNotif.teams as Record<string, unknown> || {})) },
      webhook: { ...DEFAULTS.notifications.webhook, ...sanitizeKeys((rawNotif.webhook as Record<string, unknown> || {})) },
      desktop: { ...DEFAULTS.notifications.desktop, ...sanitizeKeys((rawNotif.desktop as Record<string, unknown> || {})) },
    },
    alertRules: {
      ...DEFAULTS.alertRules,
      ...(safe.alertRules ? Object.fromEntries(
        Object.entries(sanitizeKeys(safe.alertRules as Record<string, unknown>)).map(([k, v]) => [k, { ...DEFAULT_RULE, ...sanitizeKeys((v as Record<string, unknown>)) }])
      ) : {}),
    },
    guardrails: { ...GUARDRAILS_DEFAULTS, ...rawGuardrails },
    dashboard: { ...DEFAULTS.dashboard, ...sanitizeKeys((safe.dashboard as Record<string, unknown> || {})) },
    retention: { ...DEFAULTS.retention, ...sanitizeKeys((safe.retention as Record<string, unknown> || {})) },
    prBot: { ...DEFAULTS.prBot, ...sanitizeKeys((safe.prBot as Record<string, unknown> || {})) },
    costEstimation: { ...DEFAULTS.costEstimation, ...sanitizeKeys((safe.costEstimation as Record<string, unknown> || {})) },
  } as Config;
}

export function saveConfig(config: Config): void {
  const p = configPath || path.join(process.cwd(), 'config.json');
  fs.writeFileSync(p, JSON.stringify(config, null, 2), { encoding: 'utf-8', mode: 0o600 });
}
