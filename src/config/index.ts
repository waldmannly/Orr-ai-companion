import * as path from 'path';
import * as fs from 'fs';
import { GuardrailsConfig, GUARDRAILS_DEFAULTS } from '../guardrails';

export interface AlertRuleConfig {
  enabled: boolean;
  minSeverity: 'watch' | 'warn' | 'danger';
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
    ssh_remote: { enabled: true, minSeverity: 'danger' },
    data_exfiltration: { enabled: true, minSeverity: 'warn' },
    suspicious_download: { enabled: true, minSeverity: 'warn' },
    suspicious_fetch: { enabled: true, minSeverity: 'warn' },
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

export function mergeConfig(raw: Record<string, unknown>): Config {
  const rawNotif = (raw.notifications || {}) as Record<string, unknown>;
  const rawGuardrails = (raw.guardrails || {}) as Record<string, unknown>;
  return {
    ...DEFAULTS,
    ...raw,
    sensitiveFiles: { ...DEFAULTS.sensitiveFiles, ...(raw.sensitiveFiles as Record<string, unknown> || {}) },
    alerts: { ...DEFAULTS.alerts, ...(raw.alerts as Record<string, unknown> || {}) },
    notifications: {
      slack: { ...DEFAULTS.notifications.slack, ...(rawNotif.slack as Record<string, unknown> || {}) },
      webhook: { ...DEFAULTS.notifications.webhook, ...(rawNotif.webhook as Record<string, unknown> || {}) },
      desktop: { ...DEFAULTS.notifications.desktop, ...(rawNotif.desktop as Record<string, unknown> || {}) },
    },
    alertRules: {
      ...DEFAULTS.alertRules,
      ...(raw.alertRules ? Object.fromEntries(
        Object.entries(raw.alertRules as Record<string, unknown>).map(([k, v]) => [k, { ...DEFAULT_RULE, ...(v as Record<string, unknown>) }])
      ) : {}),
    },
    guardrails: { ...GUARDRAILS_DEFAULTS, ...rawGuardrails },
    dashboard: { ...DEFAULTS.dashboard, ...(raw.dashboard as Record<string, unknown> || {}) },
    retention: { ...DEFAULTS.retention, ...(raw.retention as Record<string, unknown> || {}) },
  } as Config;
}

export function saveConfig(config: Config): void {
  const p = configPath || path.join(process.cwd(), 'config.json');
  fs.writeFileSync(p, JSON.stringify(config, null, 2), 'utf-8');
}
