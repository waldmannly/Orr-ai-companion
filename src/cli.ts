/**
 * CLI — `orr <command>`
 * 
 * Subcommands:
 *   start     — start the tracker (default when no args)
 *   status    — show current session status
 *   replay    — show last N minutes of activity
 *   export    — export events/alerts to file
 *   sessions  — list recent sessions
 *   config    — show or edit configuration
 *   rules     — manage community rule packs
 */

import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import { loadConfig, getConfigPath, saveConfig, Config } from './config';
import { setupAutoStart } from './autostart';

const API_BASE = 'http://127.0.0.1:3847';

export function runCli(args: string[]) {
  const command = args[0];
  const rest = args.slice(1);

  switch (command) {
    case 'start': return cliStart();
    case 'status': return cliStatus();
    case 'replay': return cliReplay(rest);
    case 'export': return cliExport(rest);
    case 'sessions': return cliSessions(rest);
    case 'config': return cliConfig(rest);
    case 'rules': return cliRules(rest);
    case 'autostart': return cliAutoStart(rest);
    case 'compact': return cliCompact();
    case 'pr-comment': return cliPRComment(rest);
    case 'help': case '--help': case '-h': return cliHelp();
    case 'version': case '--version': case '-v':
      console.log(require('../package.json').version);
      return;
    default:
      console.error(`Unknown command: ${command}\n`);
      cliHelp();
      process.exit(1);
  }
}

function cliHelp() {
  console.log(`
  🛡  Orr — AI Agent Activity Monitor

  Usage: orr <command> [options]

  Commands:
    start              Start the tracker (watcher + dashboard)
    status             Show current session status
    replay [minutes]   Show last N minutes of activity (default: 5)
    export [options]   Export events to file
    sessions           List recent sessions
    config [key=val]   Show or update configuration
    rules <subcommand> Manage community detection rule packs
    compact            Compact the database (VACUUM + WAL checkpoint)
    pr-comment         Generate or post a PR comment with AI activity summary
    help               Show this help message

  Export options:
    --format=csv|json  Output format (default: json)
    --output=<file>    Output file path
    --days=<n>         Export last N days (default: 7)

  Rules subcommands:
    rules list                   List loaded rule packs
    rules add <path>             Load a rule pack from file
    rules dir <directory>        Load all packs from a directory

  Autostart subcommands:
    autostart enable             Enable auto-start on login
    autostart disable            Disable auto-start
    autostart status             Check if auto-start is enabled

  Examples:
    orr start
    orr status
    orr replay 10
    orr export --format=csv --output=events.csv
    orr rules add ./my-rules.pack.json

  PR Comment:
    orr pr-comment --branch=feature/foo
    orr pr-comment --branch=feature/foo --pr=42 --repo=owner/repo
    orr pr-comment --pr=42 --repo=owner/repo   (auto-detects branch)
`);
}

function cliStart() {
  // Import and run the full tracker — delegate back to default behavior
  const { loadConfig: lc } = require('./config');
  const { Watcher } = require('./watcher');
  const { startDashboard } = require('./dashboard/server');

  console.log('');
  console.log('  ╔══════════════════════════════════════╗');
  console.log('  ║   🛡  Orr           ║');
  console.log('  ║   AI Agent Activity Monitor           ║');
  console.log('  ╚══════════════════════════════════════╝');
  console.log('');

  const config = lc();
  const watcher = new Watcher(config);
  watcher.start();
  startDashboard(config);

  console.log(`[tracker] Dashboard: http://${config.dashboard.host}:${config.dashboard.port}`);
  console.log('[tracker] Press Ctrl+C to stop\n');

  process.on('SIGINT', () => { watcher.stop(); process.exit(0); });
  process.on('SIGTERM', () => { watcher.stop(); process.exit(0); });
}

async function cliStatus() {
  try {
    const status = await apiGet('/api/ide/status');
    if (!status.sessionId) {
      console.log('  No active session.\n');
      return;
    }
    const summary = await apiGet('/api/ide/session-summary');
    console.log('');
    console.log(`  🛡  Session Status`);
    console.log(`  ${'─'.repeat(40)}`);
    console.log(`  Session:   ${status.sessionId.slice(0, 16)}…`);
    console.log(`  Provider:  ${status.provider}`);
    console.log(`  Grade:     ${status.grade}`);
    console.log(`  Events/min: ${status.eventsLastMinute}`);
    console.log(`  Danger:    ${status.dangerCount}`);
    console.log(`  Tokens:    ${status.tokenUsage?.toLocaleString() || 0}`);

    if (summary.recentViolations?.length) {
      console.log(`\n  ⚠️  Recent Violations:`);
      for (const v of summary.recentViolations.slice(0, 5)) {
        console.log(`    [${v.severity}] ${v.rule} — ${v.message}`);
      }
    }
    console.log('');
  } catch {
    console.error('  ✗ Cannot connect to tracker. Is it running? Try: orr start\n');
    process.exit(1);
  }
}

async function cliReplay(args: string[]) {
  const minutes = parseInt(args[0]) || 5;
  try {
    const data = await apiGet(`/api/events/recent?limit=200`);
    const cutoff = new Date(Date.now() - minutes * 60000).toISOString();
    const events = (data as any[]).filter(e => e.timestamp > cutoff);

    if (!events.length) {
      console.log(`\n  No events in the last ${minutes} minutes.\n`);
      return;
    }

    console.log(`\n  🔄 Last ${minutes} minutes — ${events.length} events\n`);

    const riskIcons: Record<string, string> = { danger: '🔴', warn: '🟡', watch: '🔵', info: '⚪' };
    for (const e of events) {
      const icon = riskIcons[e.risk_level] || '⚪';
      const time = new Date(e.timestamp).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', second: '2-digit' });
      const summary = (e.summary || '').substring(0, 80);
      console.log(`  ${icon} ${time}  ${e.event_type.padEnd(18)} ${summary}`);
    }
    console.log('');
  } catch {
    console.error('  ✗ Cannot connect to tracker. Is it running?\n');
    process.exit(1);
  }
}

async function cliExport(args: string[]) {
  const flags = parseFlags(args);
  const format = flags.format || 'json';
  const days = parseInt(flags.days) || 7;
  const output = flags.output || `events-export.${format}`;

  const start = new Date(Date.now() - days * 86400_000).toISOString();
  const end = new Date().toISOString();

  try {
    const url = `/api/export/events?format=${format}&start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}`;
    const data = await apiGetRaw(url);
    fs.writeFileSync(output, data);
    console.log(`\n  ✓ Exported to ${output} (${format}, last ${days} days)\n`);
  } catch {
    console.error('  ✗ Export failed. Is the tracker running?\n');
    process.exit(1);
  }
}

async function cliSessions(args: string[]) {
  const limit = parseInt(args[0]) || 10;
  try {
    const sessions = await apiGet(`/api/sessions?limit=${limit}`);
    if (!(sessions as any[]).length) {
      console.log('\n  No sessions found.\n');
      return;
    }

    console.log(`\n  📋 Recent Sessions\n`);
    console.log(`  ${'ID'.padEnd(18)} ${'Provider'.padEnd(14)} ${'Events'.padEnd(8)} ${'Danger'.padEnd(8)} Started`);
    console.log(`  ${'─'.repeat(75)}`);

    for (const s of sessions as any[]) {
      const id = (s.id || '').slice(0, 16);
      const provider = (s.source_tool || 'unknown').padEnd(14);
      const events = String(s.total_events || 0).padEnd(8);
      const danger = String(s.danger_count || 0).padEnd(8);
      const started = s.started_at ? new Date(s.started_at).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }) : '';
      console.log(`  ${id.padEnd(18)} ${provider} ${events} ${danger} ${started}`);
    }
    console.log('');
  } catch {
    console.error('  ✗ Cannot connect to tracker.\n');
    process.exit(1);
  }
}

function cliConfig(args: string[]) {
  const config = loadConfig();

  if (args.length === 0) {
    // Show current config
    console.log(`\n  ⚙️  Configuration (${getConfigPath()})\n`);
    console.log(`  Dashboard:    http://${config.dashboard.host}:${config.dashboard.port}`);
    console.log(`  Retention:    ${config.retention.maxAgeDays} days, ${config.retention.maxDbSizeMB}MB max`);
    console.log(`  Guardrails:   ${config.guardrails.enabled ? 'enabled' : 'disabled'}`);
    console.log(`  Notifications:`);
    console.log(`    Desktop:    ${config.notifications.desktop.enabled ? 'on' : 'off'} (min: ${config.notifications.desktop.minSeverity})`);
    console.log(`    Slack:      ${config.notifications.slack.enabled ? 'on' : 'off'}`);
    console.log(`    Webhook:    ${config.notifications.webhook.enabled ? 'on' : 'off'}`);
    console.log(`  Rule packs:   ${config.rulePacksDir || '(none)'}`);
    console.log('');
    return;
  }

  // Set a config value: key=value
  const [keyPath, ...valParts] = args[0].split('=');
  const value = valParts.join('=');
  if (!value) {
    console.error('  Usage: orr config <key>=<value>\n');
    process.exit(1);
  }

  // Navigate the config object
  const parts = keyPath.split('.');
  let obj: any = config;
  for (let i = 0; i < parts.length - 1; i++) {
    if (!(parts[i] in obj)) {
      console.error(`  Unknown config key: ${keyPath}\n`);
      process.exit(1);
    }
    obj = obj[parts[i]];
  }
  const lastKey = parts[parts.length - 1];

  // Type coerce
  if (value === 'true') obj[lastKey] = true;
  else if (value === 'false') obj[lastKey] = false;
  else if (/^\d+$/.test(value)) obj[lastKey] = parseInt(value);
  else obj[lastKey] = value;

  saveConfig(config);
  console.log(`  ✓ Set ${keyPath} = ${value}\n`);
}

async function cliRules(args: string[]) {
  const sub = args[0];

  if (!sub || sub === 'list') {
    try {
      const packs = await apiGet('/api/plugins');
      if (!(packs as any[]).length) {
        console.log('\n  No rule packs loaded.\n');
        return;
      }
      console.log('\n  📦 Loaded Rule Packs\n');
      for (const p of packs as any[]) {
        console.log(`  • ${p.name} v${p.version} — ${p.ruleCount} rules, ${p.widgetCount} widgets`);
      }
      console.log('');
    } catch {
      console.error('  ✗ Cannot connect to tracker.\n');
      process.exit(1);
    }
    return;
  }

  if (sub === 'add' && args[1]) {
    const packPath = path.resolve(args[1]);
    if (!fs.existsSync(packPath)) {
      console.error(`  ✗ File not found: ${packPath}\n`);
      process.exit(1);
    }
    try {
      const result = await apiPost('/api/plugins/load', { path: packPath });
      console.log(`  ✓ Loaded rule pack: ${(result as any).id} (${(result as any).rules} rules)\n`);
    } catch {
      console.error('  ✗ Failed to load rule pack.\n');
      process.exit(1);
    }
    return;
  }

  if (sub === 'dir' && args[1]) {
    const dir = path.resolve(args[1]);
    if (!fs.existsSync(dir)) {
      console.error(`  ✗ Directory not found: ${dir}\n`);
      process.exit(1);
    }
    // Update config
    const config = loadConfig();
    (config as any).rulePacksDir = dir;
    saveConfig(config);
    console.log(`  ✓ Rule packs directory set to: ${dir}\n`);
    console.log('  Restart the tracker to load packs from this directory.\n');
    return;
  }

  console.error('  Usage: orr rules <list|add <file>|dir <directory>>\n');
  process.exit(1);
}

function cliAutoStart(args: string[]) {
  const action = (args[0] || 'status') as 'enable' | 'disable' | 'status';
  if (!['enable', 'disable', 'status'].includes(action)) {
    console.error('  Usage: orr autostart <enable|disable|status>\n');
    process.exit(1);
  }
  setupAutoStart(action);
}

function cliCompact() {
  const { initDb, vacuumDb } = require('./storage/db');
  console.log('  Compacting database...');
  initDb();
  const { before, after } = vacuumDb();
  const savedMB = ((before - after) / 1048576).toFixed(1);
  console.log(`  Before: ${(before / 1048576).toFixed(1)} MB`);
  console.log(`  After:  ${(after / 1048576).toFixed(1)} MB`);
  console.log(`  Saved:  ${savedMB} MB`);
  console.log('  ✓ Done');
}

function cliPRComment(args: string[]) {
  const { initDb } = require('./storage/db');
  const { collectPRData, generatePRComment } = require('./pr-bot');
  const { postOrUpdateComment, getPRBranch } = require('./pr-bot/github');

  // Parse args: --branch=x --pr=n --repo=owner/repo --project=name --post
  const opts: Record<string, string> = {};
  let doPost = false;
  for (const a of args) {
    if (a === '--post') { doPost = true; continue; }
    const m = a.match(/^--(\w[\w-]*)=(.+)$/);
    if (m) opts[m[1]] = m[2];
  }

  const config = loadConfig();
  initDb();

  const prNumber = opts.pr ? parseInt(opts.pr) : undefined;
  const repo = opts.repo || config.prBot.repo;
  const projectName = opts.project;

  // Resolve branch: explicit, or auto-detect from GitHub PR
  const resolveBranch = async (): Promise<string> => {
    if (opts.branch) return opts.branch;
    if (prNumber && repo && config.prBot.platform === 'github') {
      console.log(`  Fetching branch for PR #${prNumber} from ${repo}...`);
      return getPRBranch(repo, prNumber, config);
    }
    console.error('  Error: --branch is required (or provide --pr + --repo for auto-detection on GitHub)');
    process.exit(1);
  };

  resolveBranch().then(async (branch) => {
    const request = { branch, repo, prNumber, projectName };
    const data = collectPRData(request, config);
    const comment = generatePRComment(data, config);

    if (data.sessions.length === 0) {
      console.log(`\n  No AI agent sessions found for branch: ${branch}`);
      if (projectName) console.log(`  (filtered to project: ${projectName})`);
      return;
    }

    console.log(`\n  Branch: ${branch}`);
    console.log(`  Sessions: ${data.sessions.length}`);
    console.log(`  Providers: ${data.providers.join(', ')}`);
    console.log(`  Events: ${data.totalEvents} | Danger: ${data.dangerCount} | Warn: ${data.warnCount} | Critical: ${data.criticalCount}`);
    console.log(`  Alerts: ${data.alerts.length}`);

    if (doPost && prNumber && repo) {
      console.log(`\n  Posting to ${repo}#${prNumber}...`);
      const result = await postOrUpdateComment(repo, prNumber, comment, config);
      console.log(`  ✓ Comment ${result.action} (ID: ${result.commentId})`);
    } else if (doPost && !prNumber) {
      console.error('  Error: --pr is required to post. Use --pr=<number> --repo=<owner/repo> --post');
    } else {
      console.log('\n--- PR Comment Preview ---\n');
      console.log(comment);
      console.log('\n--- End Preview ---');
      console.log('\n  Add --post --pr=<number> --repo=<owner/repo> to post to GitHub.');
    }
  }).catch((e: Error) => {
    console.error(`  Error: ${e.message}`);
    process.exit(1);
  });
}

// ── HTTP Helpers ──

function apiGet(path: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, API_BASE);
    http.get(url, { timeout: 5000 }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error('Invalid JSON')); }
      });
    }).on('error', reject);
  });
}

function apiGetRaw(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, API_BASE);
    http.get(url, { timeout: 30000 }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

function apiPost(path: string, body: Record<string, unknown>): Promise<any> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, API_BASE);
    const postData = JSON.stringify(body);
    const req = http.request(url, {
      method: 'POST', timeout: 5000,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(postData) },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error('Invalid JSON')); }
      });
    });
    req.on('error', reject);
    req.write(postData);
    req.end();
  });
}

function parseFlags(args: string[]): Record<string, string> {
  const flags: Record<string, string> = {};
  for (const a of args) {
    const m = a.match(/^--(\w[\w-]*)=(.+)$/);
    if (m) flags[m[1]] = m[2];
    else if (a.startsWith('--')) flags[a.slice(2)] = 'true';
  }
  return flags;
}
