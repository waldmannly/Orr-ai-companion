import { TrackerEvent, Alert, RiskLevel } from '../parser/event-types';
import { Config, AlertRuleConfig } from '../config';
import { isSensitiveFile, detectInjectionPatterns } from '../risk/classifier';
import { checkSupplyChain } from '../risk/typosquat';
import { insertAlert } from '../storage/db';

const SEVERITY_ORDER: RiskLevel[] = ['info', 'watch', 'warn', 'danger', 'critical'];

// ── Alert dedup: suppress duplicate alert_type per session within cooldown window ──
const DEDUP_COOLDOWN_MS = 30 * 60 * 1000; // 30 minutes
// Key: "sessionId::alertType", Value: last fire timestamp
const alertCooldowns = new Map<string, number>();

// Alert types that are known to be bursty (e.g. SSH commands in a deploy script)
export const BURSTY_ALERT_TYPES = new Set(['ssh_remote', 'suspicious_download']);

function isDuplicate(sessionId: string, alertType: string): boolean {
  const key = `${sessionId}::${alertType}`;
  const last = alertCooldowns.get(key);
  if (last && Date.now() - last < DEDUP_COOLDOWN_MS) return true;
  alertCooldowns.set(key, Date.now());
  return false;
}

// Exposed for testing
export function clearAlertCooldowns() { alertCooldowns.clear(); }

function ruleEnabled(config: Config, rule: string): boolean {
  const rc = (config.alertRules as Record<string, AlertRuleConfig>)?.[rule];
  return rc ? rc.enabled : true;
}

function meetsMinSeverity(config: Config, rule: string, severity: RiskLevel): boolean {
  const rc = (config.alertRules as Record<string, AlertRuleConfig>)?.[rule];
  const minSev = rc?.minSeverity || 'warn';
  return SEVERITY_ORDER.indexOf(severity) >= SEVERITY_ORDER.indexOf(minSev);
}

function shouldAlert(config: Config, rule: string, severity: RiskLevel): boolean {
  return ruleEnabled(config, rule) && meetsMinSeverity(config, rule, severity);
}

export function evaluateAlerts(event: TrackerEvent, config: Config): Alert[] {
  const alerts: Alert[] = [];

  // Dangerous commands
  if (event.command && shouldAlert(config, 'destructive_commands', 'danger')) {
    for (const pattern of config.dangerousCommands) {
      if (event.command.toLowerCase().includes(pattern.toLowerCase())) {
        const dangerExplanations: Record<string, string> = {
          'rm -rf': 'Can recursively delete entire directory trees without confirmation — data may be unrecoverable',
          'git push --force': 'Overwrites remote branch history, destroying work from other collaborators',
          'git push -f': 'Overwrites remote branch history, destroying work from other collaborators',
          'git reset --hard': 'Permanently discards all uncommitted changes with no undo',
          'drop table': 'Destroys database tables and all stored data permanently',
          'drop database': 'Destroys an entire database — catastrophic data loss',
          'format c:': 'Formats the system drive, destroying the OS and all data',
          'del /f /s /q': 'Force-deletes files recursively without confirmation or recycle bin',
          'remove-item -recurse -force': 'PowerShell recursive force-delete — data loss risk',
          'rmdir /s /q': 'Removes entire directory trees silently',
        };
        const explanation = dangerExplanations[pattern.toLowerCase()] || `Matches dangerous pattern "${pattern}" — could cause irreversible damage`;
        alerts.push(makeAlert(event, 'destructive_command', 'danger',
          `⚠️ Destructive command: ${event.command.substring(0, 80)} — ${explanation}`));
        break;
      }
    }
  }

  // Force push
  if (event.command && shouldAlert(config, 'force_push', 'danger') && /git\s+push\s+.*--force|git\s+push\s+-f\b/.test(event.command)) {
    alerts.push(makeAlert(event, 'force_push', 'danger',
      `⚠️ Force push detected — overwrites remote history, can destroy collaborators' work and break CI/CD`));
  }

  // Sensitive file access
  if (shouldAlert(config, 'sensitive_files', 'warn')) {
    for (const fp of event.file_paths) {
      if (isSensitiveFile(fp, config)) {
        const fileName = fp.split(/[/\\]/).pop() || fp;
        let explanation = 'Could expose credentials or secrets to the AI context';
        if (/\.env/i.test(fileName)) explanation = 'Environment files contain API keys and database passwords — exposure could compromise services';
        else if (/\.pem|\.key|id_rsa/i.test(fileName)) explanation = 'Cryptographic keys grant server/API access — any exposure means full compromise';
        else if (/credential|secret|password/i.test(fileName)) explanation = 'Contains authentication secrets that could enable unauthorized access';
        else if (/personal|private/i.test(fp)) explanation = 'Personal data that should not be processed by AI agents';
        alerts.push(makeAlert(event, 'sensitive_file', 'warn',
          `🔑 Sensitive file accessed: ${fileName} — ${explanation}`));
      }
    }
  }

  // Memory injection (always high priority)
  if (event.event_type === 'memory_write' && event.parameters) {
    const content = (event.parameters.file_text as string) || (event.parameters.insert_text as string) || (event.parameters.new_str as string) || '';
    if (shouldAlert(config, 'memory_injection', 'danger') && detectInjectionPatterns(content)) {
      alerts.push(makeAlert(event, 'memory_injection', 'danger',
        `🚨 Memory injection detected — content attempts to manipulate future AI behavior. This could compromise all future sessions in this workspace.`));
    } else if (shouldAlert(config, 'memory_operations', 'warn') && content.length > 0) {
      const memPath = (event.parameters.path as string) || 'unknown';
      const scope = memPath.includes('/memories/session/') ? 'session' : memPath.includes('/memories/repo/') ? 'repo' : 'user';
      const scopeRisk = scope === 'user' ? 'persists across ALL workspaces' : scope === 'repo' ? 'persists for this project' : 'lasts this session only';
      alerts.push(makeAlert(event, 'memory_write', 'warn',
        `🧠 Memory write to ${scope} scope (${scopeRisk}) — review content to ensure no hidden instructions`));
    }
  }

  // Memory delete
  if (event.event_type === 'memory_delete' && shouldAlert(config, 'memory_operations', 'warn')) {
    const memPath = (event.parameters?.path as string) || 'unknown';
    alerts.push(makeAlert(event, 'memory_delete', 'warn',
      `🗑️ Memory deleted: ${memPath} — could erase safety notes or important context you stored`));
  }

  // ── NEW: Deployment detection ──
  if (event.command && shouldAlert(config, 'deployment', 'danger')) {
    const deployPatterns: Array<{ pattern: RegExp; msg: string }> = [
      { pattern: /\bdeploy\b.*(prod|production|live|release)/i, msg: 'Production deployment command' },
      { pattern: /\b(npm|docker|nuget|cargo|gem|pip)\s+publish\b/i, msg: 'Package publish command' },
      { pattern: /\b(kubectl|helm)\s+(apply|install|upgrade|rollout)/i, msg: 'Kubernetes cluster change' },
      { pattern: /\b(docker\s+push|docker\s+compose\s+up.*--detach)/i, msg: 'Docker image push / production container' },
      { pattern: /\b(terraform\s+apply|pulumi\s+up|cdk\s+deploy|sam\s+deploy|serverless\s+deploy)/i, msg: 'Infrastructure-as-code deployment' },
      { pattern: /\bgit\s+push\b.*\b(main|master|release|production)\b/i, msg: 'Push to protected branch' },
      { pattern: /\b(aws\s+(s3\s+sync|s3\s+cp|lambda\s+update|ecs\s+update-service))/i, msg: 'AWS service update' },
      { pattern: /\b(gcloud\s+(app\s+deploy|run\s+deploy|functions\s+deploy))/i, msg: 'Google Cloud deployment' },
      { pattern: /\b(az\s+(webapp\s+deploy|functionapp\s+deploy|aks\s+))/i, msg: 'Azure deployment' },
      { pattern: /\b(fly\s+deploy|vercel\s+(--prod|deploy)|netlify\s+deploy\s+--prod|railway\s+up|heroku\s+.*push)/i, msg: 'Platform deployment' },
    ];
    for (const dp of deployPatterns) {
      if (dp.pattern.test(event.command)) {
        alerts.push(makeAlert(event, 'deployment', 'danger',
          `🚀 ${dp.msg}: ${event.command.substring(0, 80)} — AI agent is deploying code; verify this is intentional`));
        break;
      }
    }
  }

  // ── NEW: SSH / Remote access ──
  if (event.command && shouldAlert(config, 'ssh_remote', 'danger')) {
    const sshPatterns: Array<{ pattern: RegExp; msg: string }> = [
      { pattern: /\bssh\s+/i, msg: 'SSH connection to remote server' },
      { pattern: /\bscp\s+/i, msg: 'SCP file transfer' },
      { pattern: /\brsync\s+.*:/i, msg: 'Rsync to remote host' },
      { pattern: /\bsftp\s+/i, msg: 'SFTP file transfer' },
      { pattern: /\b(nc|ncat|netcat)\s+/i, msg: 'Netcat network connection' },
    ];
    for (const sp of sshPatterns) {
      if (sp.pattern.test(event.command)) {
        if (!isDuplicate(event.session_id, 'ssh_remote')) {
          alerts.push(makeAlert(event, 'ssh_remote', 'danger',
            `🔌 ${sp.msg}: ${event.command.substring(0, 80)} — remote access is outside local monitoring scope`));
        }
        break;
      }
    }
  }

  // ── NEW: Data exfiltration ──
  if (event.command && shouldAlert(config, 'data_exfiltration', 'danger')) {
    const exfilPatterns: Array<{ pattern: RegExp; msg: string }> = [
      { pattern: /\bcurl\s+.*(-X\s*POST|--data|--upload-file|-F\s)/i, msg: 'curl sending data externally' },
      { pattern: /\bcurl\s+.*\|\s*(bash|sh|python|node)/i, msg: 'curl piped to shell — remote code execution' },
      { pattern: /\bwget\s+.*-O\s*-\s*\|\s*(bash|sh)/i, msg: 'wget piped to shell — remote code execution' },
      { pattern: /\b(base64|xxd)\s+.*\|\s*(curl|wget|nc)/i, msg: 'Encoded data being sent externally' },
      { pattern: /\b(tar|zip)\s+.*\|\s*(curl|nc|ssh)/i, msg: 'Archive piped to network' },
    ];
    for (const ep of exfilPatterns) {
      if (ep.pattern.test(event.command)) {
        alerts.push(makeAlert(event, 'data_exfiltration', 'danger',
          `🚨 ${ep.msg}: ${event.command.substring(0, 80)} — potential data leak or remote code execution`));
        break;
      }
    }
  }

  // ── NEW: Suspicious downloads ──
  if (event.command && shouldAlert(config, 'suspicious_download', 'warn')) {
    const dlPatterns: Array<{ pattern: RegExp; msg: string }> = [
      { pattern: /\b(curl|wget|Invoke-WebRequest|iwr)\s+.*(\.sh|\.bash|\.ps1|\.bat|\.cmd|\.exe|\.msi|\.dmg|\.AppImage)\b/i, msg: 'Downloading executable/script' },
      { pattern: /\b(pip|pip3)\s+install\s+.*--index-url\s/i, msg: 'pip install from non-default index' },
      { pattern: /\bnpm\s+install\s+.*--registry\s/i, msg: 'npm install from non-default registry' },
      { pattern: /\b(curl|wget)\s+.*\b(pastebin|hastebin|ghostbin|rentry|transfer\.sh|0x0\.st)\b/i, msg: 'Download from paste/file-share service' },
    ];
    for (const dlp of dlPatterns) {
      if (dlp.pattern.test(event.command)) {
        if (!isDuplicate(event.session_id, 'suspicious_download')) {
          alerts.push(makeAlert(event, 'suspicious_download', 'warn',
            `📥 ${dlp.msg}: ${event.command.substring(0, 80)} — verify the source is trusted`));
        }
        break;
      }
    }
  }

  // Web fetch to unusual domain
  if (event.event_type === 'web_fetch' && event.parameters && shouldAlert(config, 'suspicious_fetch', 'warn')) {
    const urls = (event.parameters.urls as string[]) || [event.parameters.url as string].filter(Boolean);
    for (const url of urls) {
      if (url && /pastebin|hastebin|ghostbin|rentry/i.test(url)) {
        alerts.push(makeAlert(event, 'suspicious_fetch', 'warn',
          `🌐 Fetch to paste service: ${url.substring(0, 60)} — paste sites are commonly used for data exfiltration or injecting malicious instructions`));
      }
    }
  }

  // ── Supply chain: typosquatting & dependency confusion ──
  if (event.command && shouldAlert(config, 'supply_chain', 'danger')) {
    const supplySignals = checkSupplyChain(event.command);
    for (const sig of supplySignals) {
      if (sig.rule === 'typosquat') {
        // Typosquats are CRITICAL — near-certain supply chain attack
        alerts.push(makeAlert(event, 'typosquat', 'critical',
          `🎭 TYPOSQUAT DETECTED: ${sig.reason} — ${sig.danger.substring(0, 120)}`));
      } else {
        const severity = sig.level === 'danger' ? 'danger' : 'warn';
        alerts.push(makeAlert(event, sig.rule, severity as RiskLevel,
          `📦 Supply chain: ${sig.reason}`));
      }
    }
  }

  // ── CRITICAL: Known malicious patterns (confirmed threats) ──
  if (event.command) {
    const criticalPatterns: Array<{ pattern: RegExp; msg: string }> = [
      // Reverse shells
      { pattern: /\bbash\s+-i\s+>&\s*\/dev\/tcp\//i, msg: 'Reverse shell via /dev/tcp' },
      { pattern: /\b(nc|ncat|netcat)\s+.*-e\s*(\/bin\/)?(ba)?sh/i, msg: 'Netcat reverse shell' },
      { pattern: /\bpython[23]?\s+-c\s+.*socket.*connect/i, msg: 'Python reverse shell' },
      { pattern: /\bperl\s+-e\s+.*socket.*INET/i, msg: 'Perl reverse shell' },
      { pattern: /\bphp\s+-r\s+.*fsockopen/i, msg: 'PHP reverse shell' },
      { pattern: /\brm\s+.*\/tmp\/f\s*;\s*mkfifo\s/i, msg: 'Named pipe reverse shell' },
      // Crypto miners
      { pattern: /\b(xmrig|minerd|cpuminer|cgminer|bfgminer|ethminer|nbminer)\b/i, msg: 'Cryptocurrency miner detected' },
      { pattern: /\bstratum\+tcp:\/\//i, msg: 'Mining pool connection (stratum protocol)' },
      // Credential harvesting
      { pattern: /\bmimikatz\b/i, msg: 'Mimikatz credential harvester' },
      { pattern: /\b(lazagne|credentialfileview|nirsoft)\b/i, msg: 'Known credential harvesting tool' },
      { pattern: /\/etc\/shadow|SAM\s+SYSTEM|sekurlsa::logonpasswords/i, msg: 'Credential file exfiltration' },
      // Persistence mechanisms
      { pattern: /\bcrontab\s+-.*\|\s*(curl|wget|bash)/i, msg: 'Cron persistence with remote payload' },
      { pattern: /\b(systemctl|launchctl)\s+(enable|load)\s+.*\.(service|plist)\s*$/i, msg: 'Service persistence installation' },
      // Known C2 frameworks
      { pattern: /\b(meterpreter|cobalt\s*strike|sliver|empire|covenant|havoc|brute\s*ratel)\b/i, msg: 'Known C2 framework component' },
      // Encoded payload execution
      { pattern: /\bpowershell\s+.*-e(nc(odedcommand)?)\s+[A-Za-z0-9+\/=]{40,}/i, msg: 'PowerShell encoded command (obfuscated payload)' },
      { pattern: /\becho\s+[A-Za-z0-9+\/=]{50,}\s*\|\s*base64\s+-d\s*\|\s*(bash|sh|python)/i, msg: 'Base64-decoded payload execution' },
      // Data destruction
      { pattern: /\bdd\s+if=\/dev\/(zero|urandom)\s+of=\/dev\/[sh]d[a-z]/i, msg: 'Disk wipe command' },
      { pattern: /\b(shred|wipe)\s+.*\/(etc|boot|home|root)/i, msg: 'Destructive wipe of critical system paths' },
    ];
    for (const cp of criticalPatterns) {
      if (cp.pattern.test(event.command)) {
        alerts.push(makeAlert(event, 'critical_threat', 'critical',
          `☠️ CRITICAL THREAT: ${cp.msg} — "${event.command.substring(0, 100)}" — This is a known attack pattern. Machine may be compromised.`));
        break; // One critical is enough
      }
    }
  }

  return alerts;
}

export function persistAlerts(alerts: Alert[]) {
  for (const alert of alerts) {
    insertAlert(alert);
  }
}

function makeAlert(event: TrackerEvent, alertType: string, severity: RiskLevel, message: string): Alert {
  return {
    event_id: event.id || null,
    session_id: event.session_id,
    timestamp: event.timestamp,
    alert_type: alertType,
    severity,
    message,
    acknowledged: false,
  };
}
