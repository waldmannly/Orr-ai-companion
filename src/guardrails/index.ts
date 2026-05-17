import { TrackerEvent, RiskLevel } from '../parser/event-types';
import { minimatch } from 'minimatch';

// ── Guardrails Configuration Interface ──

export interface GuardrailsConfig {
  enabled: boolean;
  /** Max tokens per session before flagging (0 = unlimited) */
  tokenBudget: number;
  /** File path patterns this agent IS allowed to touch (empty = allow all) */
  scopeAllowPatterns: string[];
  /** File path patterns that are always blocked */
  scopeBlockPatterns: string[];
  /** Command patterns to intercept/block */
  blockedCommands: string[];
  /** Allowed outbound domains (empty = allow all) */
  networkAllowlist: string[];
  /** What to do when a guardrail fires: 'alert' | 'block' */
  mode: 'alert' | 'block';
}

export const GUARDRAILS_DEFAULTS: GuardrailsConfig = {
  enabled: true,
  tokenBudget: 0,
  scopeAllowPatterns: [],
  scopeBlockPatterns: [
    '**/.env*', '**/id_rsa*', '**/*.pem', '**/*.key',
    '**/node_modules/**', '**/dist/**',
  ],
  blockedCommands: [
    'rm -rf /', 'rm -rf ~', 'rm -rf *',
    'format C:', 'del /f /s /q C:\\',
    ':(){:|:&};:', 'fork bomb',
    'dd if=/dev/zero of=/dev/sda',
    'mkfs', '> /dev/sda',
  ],
  networkAllowlist: [],
  mode: 'alert',
};

// ── Guardrail Violation ──

export interface GuardrailViolation {
  rule: string;
  severity: RiskLevel;
  message: string;
  blocked: boolean;
}

// ── Session Token Tracking (in-memory for speed) ──

const sessionTokenUsage = new Map<string, number>();

export function trackTokenUsage(sessionId: string, tokens: number): number {
  const current = (sessionTokenUsage.get(sessionId) || 0) + tokens;
  sessionTokenUsage.set(sessionId, current);
  return current;
}

export function getSessionTokenUsage(sessionId: string): number {
  return sessionTokenUsage.get(sessionId) || 0;
}

export function resetSessionTokens(sessionId: string): void {
  sessionTokenUsage.delete(sessionId);
}

// ── Core Evaluation ──

export function evaluateGuardrails(
  event: TrackerEvent,
  config: GuardrailsConfig | undefined,
  sessionId: string
): GuardrailViolation[] {
  if (!config || !config.enabled) return [];

  const violations: GuardrailViolation[] = [];
  const isBlocking = config.mode === 'block';

  // 1. Scope lock: check file paths
  if (event.file_paths && event.file_paths.length > 0) {
    for (const fp of event.file_paths) {
      // Check block patterns
      for (const pattern of config.scopeBlockPatterns) {
        if (minimatch(fp, pattern, { dot: true })) {
          violations.push({
            rule: 'scope_blocked',
            severity: 'danger',
            message: `File "${fp}" matches blocked pattern "${pattern}"`,
            blocked: isBlocking,
          });
        }
      }
      // Check allow patterns (if configured, ONLY allowed paths pass)
      if (config.scopeAllowPatterns.length > 0) {
        const allowed = config.scopeAllowPatterns.some(p => minimatch(fp, p, { dot: true }));
        if (!allowed) {
          violations.push({
            rule: 'scope_outside',
            severity: 'warn',
            message: `File "${fp}" is outside allowed scope`,
            blocked: isBlocking,
          });
        }
      }
    }
  }

  // 2. Blocked commands
  if (event.command) {
    const cmdLower = event.command.toLowerCase();
    for (const blocked of config.blockedCommands) {
      if (cmdLower.includes(blocked.toLowerCase())) {
        violations.push({
          rule: 'command_blocked',
          severity: 'danger',
          message: `Command matches blocked pattern: "${blocked}"`,
          blocked: isBlocking,
        });
      }
    }
  }

  // 3. Token budget
  if (config.tokenBudget > 0 && event.token_count) {
    const total = trackTokenUsage(sessionId, event.token_count);
    if (total > config.tokenBudget) {
      violations.push({
        rule: 'token_budget_exceeded',
        severity: 'danger',
        message: `Session token usage (${total}) exceeds budget (${config.tokenBudget})`,
        blocked: isBlocking,
      });
    } else if (total > config.tokenBudget * 0.8) {
      violations.push({
        rule: 'token_budget_warning',
        severity: 'warn',
        message: `Session at ${Math.round((total / config.tokenBudget) * 100)}% of token budget (${total}/${config.tokenBudget})`,
        blocked: false,
      });
    }
  }

  // 4. Network allowlist
  if (config.networkAllowlist.length > 0) {
    // Check web_fetch events
    if (event.event_type === 'web_fetch') {
      const url = event.command || event.summary || '';
      const violation = checkUrlAgainstAllowlist(url, config.networkAllowlist, isBlocking);
      if (violation) violations.push(violation);
    }
    // Check terminal commands for curl/wget/fetch URLs
    if (event.command && (event.event_type === 'terminal_command' || event.event_type === 'tool_call')) {
      const urls = extractUrlsFromCommand(event.command);
      for (const url of urls) {
        const violation = checkUrlAgainstAllowlist(url, config.networkAllowlist, isBlocking);
        if (violation) { violations.push(violation); break; }
      }
    }
  }

  return violations;
}

function checkUrlAgainstAllowlist(url: string, allowlist: string[], isBlocking: boolean): GuardrailViolation | null {
  try {
    const hostname = new URL(url).hostname;
    const allowed = allowlist.some(domain =>
      hostname === domain || hostname.endsWith('.' + domain)
    );
    if (!allowed) {
      return {
        rule: 'network_blocked',
        severity: 'danger',
        message: `Outbound request to "${hostname}" not in allowlist`,
        blocked: isBlocking,
      };
    }
  } catch {
    // Not a valid URL — skip
  }
  return null;
}

function extractUrlsFromCommand(cmd: string): string[] {
  const urls: string[] = [];
  // Match URLs in curl/wget/fetch/Invoke-WebRequest commands
  const urlRegex = /https?:\/\/[^\s'")\]}>]+/gi;
  if (/\b(curl|wget|fetch|Invoke-WebRequest|iwr|http)\b/i.test(cmd)) {
    const matches = cmd.match(urlRegex);
    if (matches) urls.push(...matches);
  }
  return urls;
}
