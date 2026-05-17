/**
 * Community Rule Packs
 * 
 * Loadable detection rule packs that extend the built-in classifier.
 * Supports built-in packs and external JSON rule files.
 */

import * as fs from 'fs';
import * as path from 'path';
import { TrackerEvent, RiskLevel } from '../parser/event-types';
import { RiskSignal } from '../risk/classifier';

// ── Rule Pack Format ──

export interface RuleDefinition {
  id: string;
  name: string;
  description: string;
  level: RiskLevel;
  /** Match conditions (all must be true) */
  match: {
    eventTypes?: string[];
    commandPatterns?: string[];
    summaryPatterns?: string[];
    filePatterns?: string[];
  };
  /** What to put in the signal */
  signal: {
    reason: string;
    danger: string;
  };
}

export interface RulePack {
  id: string;
  name: string;
  version: string;
  description: string;
  author?: string;
  rules: RuleDefinition[];
}

// ── Built-in Packs ──

const SUPPLY_CHAIN_PACK: RulePack = {
  id: 'supply-chain',
  name: 'Supply Chain Security',
  version: '1.0.0',
  description: 'Detects supply chain attack patterns: typosquatting, dependency confusion, lockfile tampering',
  rules: [
    {
      id: 'lockfile_tampering',
      name: 'Lockfile Modification',
      description: 'Package lockfile was modified directly (not via package manager)',
      level: 'warn',
      match: { eventTypes: ['file_write'], filePatterns: ['**/package-lock.json', '**/yarn.lock', '**/pnpm-lock.yaml', '**/Cargo.lock', '**/Gemfile.lock'] },
      signal: { reason: 'Lockfile modified directly — could introduce malicious dependency versions', danger: 'Supply chain attack via dependency version pinning manipulation' },
    },
    {
      id: 'postinstall_script',
      name: 'Postinstall Script Execution',
      description: 'Package with postinstall script was added',
      level: 'warn',
      match: { eventTypes: ['terminal_command'], commandPatterns: ['postinstall', 'preinstall', 'install.*script'] },
      signal: { reason: 'Package lifecycle script detected during install', danger: 'Malicious packages use install scripts to execute arbitrary code' },
    },
    {
      id: 'registry_change',
      name: 'Package Registry Changed',
      description: 'npm/yarn registry was pointed to a non-standard source',
      level: 'danger',
      match: { eventTypes: ['terminal_command', 'file_write'], commandPatterns: ['registry\\s*=', 'set.*registry', '--registry'] },
      signal: { reason: 'Package registry configuration was changed', danger: 'Dependency confusion attack — packages could be fetched from a malicious registry' },
    },
    {
      id: 'unpinned_dependency',
      name: 'Unpinned Dependency Added',
      description: 'Dependency added with * or latest version',
      level: 'watch',
      match: { eventTypes: ['file_write'], filePatterns: ['**/package.json'], summaryPatterns: ['"\\*"', '"latest"', '">='] },
      signal: { reason: 'Dependency added without version pinning', danger: 'Unpinned dependencies can silently upgrade to compromised versions' },
    },
  ],
};

const CREDENTIALS_PACK: RulePack = {
  id: 'credentials',
  name: 'Credential & Secret Detection',
  version: '1.0.0',
  description: 'Detects credential exposure, hardcoded secrets, and API key leaks',
  rules: [
    {
      id: 'hardcoded_api_key',
      name: 'Hardcoded API Key',
      description: 'API key or token hardcoded in source',
      level: 'danger',
      match: { eventTypes: ['file_write', 'file_create'], summaryPatterns: ['api[_-]?key\\s*[=:]\\s*["\'][^"\']{20,}', 'token\\s*[=:]\\s*["\'][^"\']{20,}', 'secret\\s*[=:]\\s*["\'][^"\']{10,}'] },
      signal: { reason: 'Possible hardcoded secret or API key detected in source code', danger: 'Secrets in source code get committed to version control and exposed to anyone with repo access' },
    },
    {
      id: 'env_file_creation',
      name: '.env File Created',
      description: 'New .env file was created (may contain secrets)',
      level: 'warn',
      match: { eventTypes: ['file_create'], filePatterns: ['**/.env', '**/.env.*'] },
      signal: { reason: 'New environment file created — may contain secrets', danger: 'Env files not in .gitignore can leak to version control' },
    },
    {
      id: 'private_key_generated',
      name: 'Private Key Generated',
      description: 'SSH or TLS private key was created',
      level: 'danger',
      match: { eventTypes: ['terminal_command', 'file_create'], commandPatterns: ['ssh-keygen', 'openssl.*genrsa', 'openssl.*genpkey'], filePatterns: ['**/*.pem', '**/*.key', '**/id_rsa*', '**/id_ed25519*'] },
      signal: { reason: 'Private key generation detected', danger: 'Generated keys must be properly secured — exposure means unauthorized access' },
    },
    {
      id: 'credential_in_command',
      name: 'Credential in Command',
      description: 'Password or token passed as command-line argument',
      level: 'danger',
      match: { eventTypes: ['terminal_command'], commandPatterns: ['--password[= ]', '-p\\s+\\S{8,}', '--token[= ]\\S{10,}', 'curl.*-u\\s', 'curl.*Authorization:'] },
      signal: { reason: 'Credential passed as command-line argument', danger: 'Credentials in CLI args are visible in process lists and shell history' },
    },
  ],
};

const CICD_PACK: RulePack = {
  id: 'ci-cd',
  name: 'CI/CD Pipeline Security',
  version: '1.0.0',
  description: 'Detects risky CI/CD configuration changes and pipeline manipulation',
  rules: [
    {
      id: 'workflow_modification',
      name: 'CI Workflow Modified',
      description: 'GitHub Actions or CI config was changed',
      level: 'warn',
      match: { eventTypes: ['file_write', 'file_create'], filePatterns: ['**/.github/workflows/*.yml', '**/.github/workflows/*.yaml', '**/.gitlab-ci.yml', '**/Jenkinsfile', '**/.circleci/**'] },
      signal: { reason: 'CI/CD pipeline configuration was modified', danger: 'Modified pipelines can exfiltrate secrets, deploy malicious code, or mine crypto on CI runners' },
    },
    {
      id: 'dockerfile_modification',
      name: 'Dockerfile Modified',
      description: 'Container build configuration changed',
      level: 'watch',
      match: { eventTypes: ['file_write', 'file_create'], filePatterns: ['**/Dockerfile*', '**/docker-compose*.yml', '**/.dockerignore'] },
      signal: { reason: 'Container configuration was modified', danger: 'Docker modifications can introduce supply chain risks, expose ports, or run as root' },
    },
    {
      id: 'deploy_command',
      name: 'Deploy Command Executed',
      description: 'Production deployment command detected',
      level: 'danger',
      match: { eventTypes: ['terminal_command'], commandPatterns: ['deploy.*prod', 'kubectl.*apply', 'terraform.*apply', 'pulumi.*up', 'aws.*deploy', 'gcloud.*deploy', 'heroku.*push'] },
      signal: { reason: 'Production deployment command executed by AI agent', danger: 'Unreviewed deployments to production can cause outages and security incidents' },
    },
    {
      id: 'secret_in_workflow',
      name: 'Secret Reference Added to Workflow',
      description: 'New secret reference in CI config',
      level: 'watch',
      match: { eventTypes: ['file_write'], filePatterns: ['**/.github/workflows/*.yml'], summaryPatterns: ['\\$\\{\\{\\s*secrets\\.', 'env:.*SECRET', 'env:.*TOKEN'] },
      signal: { reason: 'New secret reference added to CI workflow', danger: 'Review that secret access is intentional and scoped correctly' },
    },
  ],
};

// ── Pack Registry ──

const BUILT_IN_PACKS: RulePack[] = [SUPPLY_CHAIN_PACK, CREDENTIALS_PACK, CICD_PACK];
const loadedPacks: RulePack[] = [...BUILT_IN_PACKS];

/**
 * Get all available packs.
 */
export function getAvailablePacks(): Array<{ id: string; name: string; version: string; description: string; ruleCount: number; enabled: boolean }> {
  return loadedPacks.map(p => ({
    id: p.id,
    name: p.name,
    version: p.version,
    description: p.description,
    ruleCount: p.rules.length,
    enabled: true,
  }));
}

/**
 * Load a rule pack from a JSON file.
 */
export function loadPackFromFile(filePath: string): RulePack {
  const content = fs.readFileSync(filePath, 'utf-8');
  const pack = JSON.parse(content) as RulePack;
  if (!pack.id || !pack.name || !pack.rules || !Array.isArray(pack.rules)) {
    throw new Error('Invalid rule pack format: must have id, name, and rules array');
  }
  // Remove existing pack with same ID
  const idx = loadedPacks.findIndex(p => p.id === pack.id);
  if (idx >= 0) loadedPacks.splice(idx, 1);
  loadedPacks.push(pack);
  return pack;
}

/**
 * Load all .json packs from a directory.
 */
export function loadPacksFromDirectory(dirPath: string): RulePack[] {
  const loaded: RulePack[] = [];
  if (!fs.existsSync(dirPath)) return loaded;
  const files = fs.readdirSync(dirPath).filter(f => f.endsWith('.json'));
  for (const file of files) {
    try {
      loaded.push(loadPackFromFile(path.join(dirPath, file)));
    } catch (err) {
      console.warn(`[rules] Failed to load pack ${file}: ${err}`);
    }
  }
  return loaded;
}

/**
 * Evaluate all pack rules against an event.
 * Returns additional risk signals from community packs.
 */
export function evaluatePackRules(event: TrackerEvent): RiskSignal[] {
  const signals: RiskSignal[] = [];

  for (const pack of loadedPacks) {
    for (const rule of pack.rules) {
      if (matchesRule(event, rule)) {
        signals.push({
          rule: `${pack.id}/${rule.id}`,
          level: rule.level,
          reason: rule.signal.reason,
          danger: rule.signal.danger,
        });
      }
    }
  }

  return signals;
}

/** Safely test a regex pattern with length limits to prevent ReDoS */
function safeRegexTest(pattern: string, text: string): boolean {
  // Reject patterns that are excessively complex
  if (pattern.length > 500) return false;
  // Limit text length to prevent catastrophic backtracking on large inputs
  const safeText = text.length > 10000 ? text.substring(0, 10000) : text;
  try { return new RegExp(pattern, 'i').test(safeText); } catch { return safeText.toLowerCase().includes(pattern.toLowerCase()); }
}

function matchesRule(event: TrackerEvent, rule: RuleDefinition): boolean {
  const m = rule.match;

  // Event type check
  if (m.eventTypes && m.eventTypes.length > 0) {
    if (!m.eventTypes.includes(event.event_type)) return false;
  }

  // Command pattern check (any pattern matches)
  if (m.commandPatterns && m.commandPatterns.length > 0) {
    if (!event.command) return false;
    const cmdMatched = m.commandPatterns.some(pattern => safeRegexTest(pattern, event.command!));
    if (!cmdMatched) return false;
  }

  // Summary pattern check
  if (m.summaryPatterns && m.summaryPatterns.length > 0) {
    const text = (event.summary || '') + (event.raw_log || '');
    if (!text) return false;
    const sumMatched = m.summaryPatterns.some(pattern => safeRegexTest(pattern, text));
    if (!sumMatched) return false;
  }

  // File pattern check (minimatch not available here, use simple matching)
  if (m.filePatterns && m.filePatterns.length > 0) {
    if (!event.file_paths || event.file_paths.length === 0) return false;
    const fileMatched = event.file_paths.some(fp => {
      const normalized = fp.replace(/\\/g, '/');
      return m.filePatterns!.some(pattern => {
        if (pattern.length > 500) return false;
        // Simple glob: ** = anything, * = segment
        const regex = pattern
          .replace(/\./g, '\\.')
          .replace(/\*\*/g, '##DOUBLESTAR##')
          .replace(/\*/g, '[^/]*')
          .replace(/##DOUBLESTAR##/g, '.*');
        try { return new RegExp(regex, 'i').test(normalized); } catch { return normalized.includes(pattern.replace(/\*/g, '')); }
      });
    });
    if (!fileMatched) return false;
  }

  return true;
}
