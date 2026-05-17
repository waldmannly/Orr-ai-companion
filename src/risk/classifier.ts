import { TrackerEvent, RiskLevel, MemoryOperation } from '../parser/event-types';
import { Config } from '../config';
import { minimatch } from 'minimatch';
import { checkSupplyChain } from './typosquat';

export interface RiskSignal {
  rule: string;         // short identifier (e.g. 'force_push', 'sensitive_file')
  level: RiskLevel;     // what this signal contributes
  reason: string;       // human explanation of WHY it was flagged
  danger: string;       // what could go wrong / the actual risk
}

export interface RiskResult {
  level: RiskLevel;
  signals: RiskSignal[];
}

export function classifyRisk(event: TrackerEvent, config: Config): RiskLevel {
  return classifyRiskWithReasons(event, config).level;
}

export function classifyRiskWithReasons(event: TrackerEvent, config: Config): RiskResult {
  const signals: RiskSignal[] = [];

  // File writes are at least 'watch'
  if (event.event_type === 'file_write') {
    signals.push({ rule: 'file_write', level: 'watch', reason: 'AI agent is modifying an existing file', danger: 'Unintended code changes could introduce bugs, break functionality, or alter application behavior' });
  }
  if (event.event_type === 'file_create') {
    signals.push({ rule: 'file_create', level: 'watch', reason: 'AI agent is creating a new file', danger: 'New files could add unexpected dependencies, backdoors, or overwrite important data if name collides' });
  }
  if (event.event_type === 'file_delete') {
    signals.push({ rule: 'file_delete', level: 'watch', reason: 'AI agent is deleting a file', danger: 'File deletion is irreversible without version control — could lose critical code or data' });
  }

  // Terminal commands
  if (['terminal_command', 'terminal_send'].includes(event.event_type)) {
    signals.push({ rule: 'terminal_exec', level: 'watch', reason: 'AI agent is executing a terminal command', danger: 'Terminal commands run with full user privileges — can modify system state, install packages, or access network' });
  }

  // Git operations
  if (event.event_type === 'git_commit') {
    signals.push({ rule: 'git_commit', level: 'watch', reason: 'AI agent is committing changes to version control', danger: 'Commits persist changes permanently — review carefully before pushing to shared branches' });
  }
  if (event.event_type === 'git_push') {
    signals.push({ rule: 'git_push', level: 'watch', reason: 'AI agent is pushing code to a remote repository', danger: 'Pushed code is visible to collaborators and may trigger CI/CD pipelines or deployments' });
    if (event.command && /--force|-f\b/.test(event.command)) {
      signals.push({ rule: 'force_push', level: 'danger', reason: 'Force push overwrites remote history', danger: 'Destroys commit history for other collaborators — can cause data loss and broken branches for the entire team' });
    }
  }
  if (event.event_type === 'git_reset') {
    if (event.command && /--hard/.test(event.command)) {
      signals.push({ rule: 'hard_reset', level: 'danger', reason: 'Hard reset discards all uncommitted changes', danger: 'Permanently destroys working directory changes and staged files — unrecoverable without reflog expertise' });
    } else {
      signals.push({ rule: 'git_reset', level: 'warn', reason: 'Git reset is altering commit history', danger: 'Can lose staged changes or rewrite history — verify intended state before continuing' });
    }
  }

  // Memory operations
  if (event.event_type === 'memory_write') {
    signals.push({ rule: 'memory_write', level: 'warn', reason: 'AI agent is writing to persistent memory', danger: 'Memory persists across sessions — injected instructions here could influence all future AI behavior in this workspace' });
  }
  if (event.event_type === 'memory_delete') {
    signals.push({ rule: 'memory_delete', level: 'warn', reason: 'AI agent is deleting from persistent memory', danger: 'Deleted memory entries cannot be recovered — could erase safety instructions or important context' });
  }
  if (event.event_type === 'memory_read') {
    signals.push({ rule: 'memory_read', level: 'watch', reason: 'AI agent is reading persistent memory', danger: 'Reading memory is normal, but verify the agent isn\'t probing for sensitive stored content' });
  }

  // Sub-agent spawn
  if (event.event_type === 'subagent_spawn') {
    signals.push({ rule: 'subagent_spawn', level: 'watch', reason: 'AI agent is spawning a sub-agent with delegated authority', danger: 'Sub-agents operate semi-autonomously — harder to monitor and may bypass constraints set for the main agent' });
  }

  // Web fetch
  if (event.event_type === 'web_fetch') {
    signals.push({ rule: 'web_fetch', level: 'watch', reason: 'AI agent is fetching external web content', danger: 'External content could contain prompt injection attacks or leak workspace context through URL parameters' });
  }

  // ── Deployment detection ──
  if (event.command) {
    const cmd = event.command;
    const deployPatterns: Array<{ pattern: RegExp; reason: string; danger: string }> = [
      { pattern: /\bdeploy\b.*(prod|production|live|release)/i, reason: 'Command appears to deploy to production', danger: 'Production deployments can push untested code to live users — outages, data corruption, or security holes' },
      { pattern: /\b(npm|docker|nuget|cargo|gem|pip)\s+publish\b/i, reason: 'Package publish command detected', danger: 'Published packages are public and may be immutable — malicious code reaches all downstream consumers' },
      { pattern: /\b(kubectl|helm)\s+(apply|install|upgrade|rollout)/i, reason: 'Kubernetes deployment command detected', danger: 'Cluster changes affect running services — bad configs can cause cascading failures across infrastructure' },
      { pattern: /\b(docker\s+push|docker\s+compose\s+up.*--detach)/i, reason: 'Docker image push or production container start', danger: 'Pushing images or starting detached containers deploys code that may run unsupervised' },
      { pattern: /\b(terraform\s+apply|pulumi\s+up|cdk\s+deploy|sam\s+deploy|serverless\s+deploy)/i, reason: 'Infrastructure-as-code deployment detected', danger: 'IaC deployments modify cloud infrastructure — can create resources, change permissions, or destroy services' },
      { pattern: /\bgit\s+push\b.*\b(main|master|release|production)\b/i, reason: 'Push to protected branch (main/master/release)', danger: 'Pushing directly to protected branches may trigger CI/CD deployment pipelines automatically' },
      { pattern: /\b(aws\s+(s3\s+sync|s3\s+cp|lambda\s+update|ecs\s+update-service))/i, reason: 'AWS service deployment or update detected', danger: 'Directly modifying AWS resources can affect running production services and stored data' },
      { pattern: /\b(gcloud\s+(app\s+deploy|run\s+deploy|functions\s+deploy))/i, reason: 'Google Cloud deployment detected', danger: 'GCP deployments push code to cloud services — can break live systems or incur costs' },
      { pattern: /\b(az\s+(webapp\s+deploy|functionapp\s+deploy|aks\s+))/i, reason: 'Azure deployment detected', danger: 'Azure deployments modify live cloud services and infrastructure' },
      { pattern: /\b(fly\s+deploy|vercel\s+(--prod|deploy)|netlify\s+deploy\s+--prod|railway\s+up|heroku\s+.*push)/i, reason: 'Platform deployment (Fly/Vercel/Netlify/Railway/Heroku)', danger: 'Deploys code to a live hosting platform where it becomes immediately accessible to users' },
    ];
    for (const dp of deployPatterns) {
      if (dp.pattern.test(cmd)) {
        signals.push({ rule: 'deployment', level: 'danger', reason: dp.reason, danger: dp.danger });
        break;
      }
    }

    // ── SSH / Remote access detection ──
    const sshPatterns: Array<{ pattern: RegExp; reason: string; danger: string }> = [
      { pattern: /\bssh\s+/i, reason: 'SSH connection to a remote server', danger: 'SSH grants shell access to remote machines — commands run there are outside your local monitoring' },
      { pattern: /\bscp\s+/i, reason: 'SCP file transfer to/from a remote server', danger: 'Files being copied to/from remote machines could leak source code, secrets, or inject malicious files' },
      { pattern: /\brsync\s+.*:/i, reason: 'Rsync to a remote destination', danger: 'Rsync can transfer large amounts of data to remote servers — potential data exfiltration channel' },
      { pattern: /\bsftp\s+/i, reason: 'SFTP connection for remote file transfer', danger: 'SFTP enables file upload/download to remote servers outside your local environment' },
      { pattern: /\b(nc|ncat|netcat)\s+/i, reason: 'Netcat network connection detected', danger: 'Netcat can open arbitrary network connections — commonly used for reverse shells and data exfiltration' },
    ];
    for (const sp of sshPatterns) {
      if (sp.pattern.test(cmd)) {
        signals.push({ rule: 'ssh_remote', level: 'danger', reason: sp.reason, danger: sp.danger });
        break;
      }
    }

    // ── Data exfiltration detection ──
    const exfilPatterns: Array<{ pattern: RegExp; reason: string; danger: string }> = [
      { pattern: /\bcurl\s+.*(-X\s*POST|--data|--upload-file|-F\s)/i, reason: 'curl is sending data to an external server', danger: 'Outbound data transfer could leak source code, environment variables, or credentials to an attacker' },
      { pattern: /\bcurl\s+.*\|\s*(bash|sh|python|node)/i, reason: 'curl piped to shell execution', danger: 'Downloading and immediately executing remote code — could run anything with your full privileges' },
      { pattern: /\bwget\s+.*-O\s*-\s*\|\s*(bash|sh)/i, reason: 'wget piped to shell execution', danger: 'Downloading and executing arbitrary code from the internet without inspection' },
      { pattern: /\b(base64|xxd)\s+.*\|\s*(curl|wget|nc)/i, reason: 'Encoding data before sending it externally', danger: 'Base64 encoding before network transfer is a common exfiltration technique to bypass detection' },
      { pattern: /\b(tar|zip)\s+.*\|\s*(curl|nc|ssh)/i, reason: 'Archiving files and piping to network tool', danger: 'Compressing and streaming data out — efficient bulk exfiltration of source code or secrets' },
    ];
    for (const ep of exfilPatterns) {
      if (ep.pattern.test(cmd)) {
        signals.push({ rule: 'data_exfiltration', level: 'danger', reason: ep.reason, danger: ep.danger });
        break;
      }
    }

    // ── Suspicious downloads ──
    const downloadPatterns: Array<{ pattern: RegExp; reason: string; danger: string }> = [
      { pattern: /\b(curl|wget|Invoke-WebRequest|iwr)\s+.*(\.sh|\.bash|\.ps1|\.bat|\.cmd|\.exe|\.msi|\.dmg|\.AppImage)\b/i, reason: 'Downloading an executable or script from the internet', danger: 'Downloaded scripts/binaries could contain malware, backdoors, or ransomware that runs with your user privileges' },
      { pattern: /\b(pip|pip3)\s+install\s+.*--index-url\s/i, reason: 'pip install from a non-default package index', danger: 'Custom package indexes can serve typosquatted or malicious packages that steal credentials' },
      { pattern: /\bnpm\s+install\s+.*--registry\s/i, reason: 'npm install from a non-default registry', danger: 'Custom registries can serve malicious package versions — supply chain attack vector' },
      { pattern: /\b(curl|wget)\s+.*\braw\.githubusercontent\.com\b/i, reason: 'Downloading raw file from GitHub', danger: 'GitHub raw content is not vetted — could download malicious scripts or overwrite local files' },
      { pattern: /\b(curl|wget)\s+.*\b(pastebin|hastebin|ghostbin|rentry|transfer\.sh|0x0\.st)\b/i, reason: 'Downloading from a paste/file-sharing service', danger: 'Paste services are anonymous and ephemeral — commonly used to stage payloads for attacks' },
    ];
    for (const dlp of downloadPatterns) {
      if (dlp.pattern.test(cmd)) {
        signals.push({ rule: 'suspicious_download', level: 'warn', reason: dlp.reason, danger: dlp.danger });
        break;
      }
    }

    // ── General network access (lower severity) ──
    if (/\b(curl|wget|http|fetch|Invoke-WebRequest|iwr)\b/i.test(cmd) && !signals.some(s => s.rule === 'data_exfiltration' || s.rule === 'suspicious_download')) {
      signals.push({ rule: 'network_access', level: 'watch', reason: 'Command accesses the network', danger: 'Network commands can send or receive data — verify the target URL and data being transferred' });
    }
  }

  // Check dangerous commands
  if (event.command) {
    for (const pattern of config.dangerousCommands) {
      if (event.command.toLowerCase().includes(pattern.toLowerCase())) {
        const dangerMap: Record<string, string> = {
          'rm -rf': 'Recursive force-delete can wipe entire directory trees instantly without confirmation',
          'git push --force': 'Overwrites remote branch history, potentially destroying other developers\' work',
          'git push -f': 'Overwrites remote branch history, potentially destroying other developers\' work',
          'git reset --hard': 'Discards ALL uncommitted changes permanently — no undo without reflog',
          'drop table': 'Permanently destroys database tables and all data within them',
          'drop database': 'Destroys an entire database — catastrophic and usually irreversible',
          'format c:': 'Formats the system drive — destroys the entire operating system and all data',
          'del /f /s /q': 'Force-deletes files recursively and silently — no recycle bin, no confirmation',
          'remove-item -recurse -force': 'PowerShell equivalent of rm -rf — destroys directory trees without confirmation',
          'rmdir /s /q': 'Removes directories recursively and silently — data loss risk',
        };
        const danger = dangerMap[pattern.toLowerCase()] || `Command matches dangerous pattern "${pattern}" — could cause irreversible system changes`;
        signals.push({ rule: 'dangerous_command', level: 'danger', reason: `Command contains "${pattern}"`, danger });
        break;
      }
    }
  }

  // Check sensitive files
  for (const fp of event.file_paths) {
    if (isSensitiveFile(fp, config)) {
      const fileName = fp.split(/[/\\]/).pop() || fp;
      let danger = 'Sensitive files often contain credentials, keys, or personal data that should not be read or modified by AI agents';
      if (/\.env/i.test(fileName)) danger = 'Environment files contain API keys, database passwords, and secrets — exposure could compromise services';
      else if (/\.pem|\.key|id_rsa/i.test(fileName)) danger = 'Cryptographic keys grant access to servers, APIs, or encrypted data — exposure means full compromise';
      else if (/credential|secret|password/i.test(fileName)) danger = 'Credential files contain authentication secrets — any exposure could lead to unauthorized access';
      else if (/personal|private/i.test(fp)) danger = 'Personal/private directories may contain sensitive personal information not meant for AI processing';
      signals.push({ rule: 'sensitive_file', level: 'warn', reason: `Accessing sensitive file: ${fileName}`, danger });
    }
  }

  // Dependency mutation detection
  if (['terminal_command', 'terminal_send'].includes(event.event_type) && event.command) {
    if (/npm\s+(install|i|add|remove|uninstall|update)\b/.test(event.command) || /yarn\s+(add|remove|upgrade)\b/.test(event.command) || /pip\s+install\b/.test(event.command) || /cargo\s+(add|install)\b/.test(event.command)) {
      signals.push({ rule: 'dependency_mutation', level: 'warn', reason: 'AI agent is modifying project dependencies', danger: 'Dependency changes can introduce supply-chain vulnerabilities, license issues, or break existing functionality' });
    }
    // Typosquatting & supply chain checks
    const supplyChainSignals = checkSupplyChain(event.command);
    signals.push(...supplyChainSignals);
  }

  // Environment variable access
  if (['terminal_command', 'terminal_send'].includes(event.event_type) && event.command) {
    if (/\$\{?[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH)[A-Z_]*\}?/i.test(event.command) || /printenv|env\b|set\s/.test(event.command)) {
      signals.push({ rule: 'env_var_access', level: 'warn', reason: 'AI agent is accessing environment variables that may contain secrets', danger: 'Secrets could be logged, exfiltrated, or exposed in command output' });
    }
  }

  // Git branch context — main/master branch operations
  if (['git_push', 'git_commit', 'git_reset', 'git_checkout'].includes(event.event_type) && event.command) {
    if (/\b(main|master|production|release)\b/.test(event.command)) {
      signals.push({ rule: 'protected_branch', level: 'warn', reason: 'AI agent is operating on a protected/default branch', danger: 'Direct changes to main/production branches bypass code review and could break deployments' });
    }
  }

  // File permission changes
  if (['terminal_command', 'terminal_send'].includes(event.event_type) && event.command) {
    if (/chmod\s/.test(event.command) || /chown\s/.test(event.command) || /icacls\s/.test(event.command) || /attrib\s/.test(event.command)) {
      signals.push({ rule: 'file_permissions', level: 'warn', reason: 'AI agent is modifying file permissions', danger: 'Permission changes could make files executable, world-readable, or alter ownership' });
    }
  }

  // Retry pattern detection — repeated similar commands
  if (['terminal_command', 'terminal_send'].includes(event.event_type) && event.command) {
    if (/--retry|--retries|retry|attempts?|loop|while\s+true/.test(event.command)) {
      signals.push({ rule: 'retry_pattern', level: 'watch', reason: 'Command contains retry/loop pattern', danger: 'Infinite loops or excessive retries could cause resource exhaustion or rate-limit violations' });
    }
  }

  // Process/service management
  if (['terminal_command', 'terminal_send'].includes(event.event_type) && event.command) {
    if (/kill\s|pkill\s|taskkill\s|systemctl\s|service\s|net\s+(start|stop)\b/.test(event.command)) {
      signals.push({ rule: 'process_management', level: 'warn', reason: 'AI agent is managing system processes or services', danger: 'Stopping or killing processes could cause data loss or service disruption' });
    }

    // Clipboard operations
    if (/pbcopy|pbpaste|xclip|xsel|clip\.exe|Set-Clipboard|Get-Clipboard|wl-copy|wl-paste/i.test(event.command)) {
      signals.push({ rule: 'clipboard_access', level: 'warn', reason: 'AI agent is accessing the system clipboard', danger: 'Clipboard may contain passwords, tokens, or sensitive data — reading/writing it is a privacy risk' });
    }

    // Context window / token manipulation
    if (/context.?window|max.?tokens|token.?limit|--max-tokens|temperature\s*[:=]\s*[0-9]/i.test(event.command)) {
      signals.push({ rule: 'context_window_manipulation', level: 'watch', reason: 'AI agent is adjusting context window or token parameters', danger: 'Changing token limits or temperature affects AI reasoning quality and may hide important context' });
    }
  }

  // URL resolution — detect external network access patterns
  if (event.event_type === 'web_fetch' || (event.command && /https?:\/\//.test(event.command))) {
    const urlMatch = (event.command || event.summary || '').match(/https?:\/\/[^\s"')]+/i);
    if (urlMatch) {
      const url = urlMatch[0];
      try {
        const host = new URL(url).hostname;
        // Flag suspicious redirect/shortener domains
        if (/bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|rb\.gy|shorturl|redirect/i.test(host)) {
          signals.push({ rule: 'url_shortener', level: 'warn', reason: `URL shortener detected: ${host}`, danger: 'Shortened URLs hide the real destination — could lead to malicious sites or data exfiltration endpoints' });
        }
        // Flag raw IP addresses
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
          signals.push({ rule: 'raw_ip_access', level: 'warn', reason: `Direct IP access: ${host}`, danger: 'Accessing raw IP addresses bypasses DNS logging and may indicate covert communication' });
        }
        // Flag non-standard ports
        const portMatch = url.match(/:(\d+)/);
        if (portMatch && !['80', '443', '8080', '8443', '3000', '5000'].includes(portMatch[1])) {
          signals.push({ rule: 'nonstandard_port', level: 'watch', reason: `Non-standard port ${portMatch[1]} in URL`, danger: 'Non-standard ports may indicate backdoor services or custom exfiltration endpoints' });
        }
      } catch {}
    }
  }

  // Agent confidence / reasoning (detected from summary or raw_log)
  if (event.raw_log) {
    const raw = event.raw_log.toLowerCase();
    if (/confidence\s*[:=]\s*(low|0\.[0-3])/i.test(raw)) {
      signals.push({ rule: 'low_confidence', level: 'watch', reason: 'AI agent reported low confidence in its action', danger: 'Low-confidence actions are more likely to contain errors or hallucinations' });
    }
    if (/i('m| am)\s+(not sure|uncertain|guessing)/i.test(raw)) {
      signals.push({ rule: 'uncertain_reasoning', level: 'watch', reason: 'AI agent expressed uncertainty about its action', danger: 'Uncertain reasoning increases risk of incorrect file modifications or commands' });
    }
  }

  // Check memory content for injection patterns
  if (event.event_type === 'memory_write' && event.parameters) {
    const content = (event.parameters.file_text as string) || (event.parameters.insert_text as string) || (event.parameters.new_str as string) || '';
    const injectionDetail = detectInjectionDetail(content);
    if (injectionDetail) {
      signals.push({ rule: 'memory_injection', level: 'danger', reason: injectionDetail.reason, danger: injectionDetail.danger });
    }
  }

  // Determine overall level from highest signal
  let level: RiskLevel = 'info';
  for (const s of signals) {
    level = escalate(level, s.level);
  }

  return { level, signals };
}

// Template env files that contain no real secrets
const SAFE_ENV_PATTERNS = /\.(example|sample|template|defaults|test|development)$/i;

export function isSensitiveFile(filePath: string, config: Config): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  const basename = normalized.split('/').pop() || '';

  // Exclude known-safe template files (e.g. .env.example, .env.sample, .env.template)
  if (SAFE_ENV_PATTERNS.test(basename)) return false;

  for (const exact of config.sensitiveFiles.exactPaths) {
    if (normalized === exact.replace(/\\/g, '/')) return true;
  }
  for (const pattern of config.sensitiveFiles.patterns) {
    if (minimatch(normalized, pattern, { dot: true, nocase: true })) return true;
    if (minimatch(basename, pattern, { dot: true, nocase: true })) return true;
  }
  return false;
}

export function detectInjectionPatterns(content: string): boolean {
  return detectInjectionDetail(content) !== null;
}

interface InjectionDetail { reason: string; danger: string; }

function detectInjectionDetail(content: string): InjectionDetail | null {
  const checks: Array<{ pattern: RegExp; reason: string; danger: string }> = [
    { pattern: /ignore\s+(previous|prior|above)\s+(instructions|prompts|rules)/i,
      reason: 'Memory content attempts to override previous instructions',
      danger: 'Prompt injection — could make the AI ignore safety rules, user preferences, or security constraints in future sessions' },
    { pattern: /always\s+(include|add|send|call|execute)\s+.*(https?:\/\/)/i,
      reason: 'Memory content contains a persistent instruction to contact an external URL',
      danger: 'Data exfiltration setup — could silently send workspace data, code, or secrets to an attacker-controlled server' },
    { pattern: /never\s+mention/i,
      reason: 'Memory content instructs the AI to hide information from the user',
      danger: 'Concealment attack — the AI could be manipulated to hide malicious actions or errors from you' },
    { pattern: /do\s+not\s+(tell|inform|alert|warn)\s+(the\s+)?user/i,
      reason: 'Memory content explicitly tells the AI to withhold information from the user',
      danger: 'Active deception — designed to prevent you from knowing about dangerous actions the AI is taking' },
    { pattern: /system\s*:\s*/i,
      reason: 'Memory content contains a system prompt override attempt',
      danger: 'System prompt injection — could override the AI\'s core safety instructions and behavioral constraints' },
    { pattern: /\bexfiltrate\b/i,
      reason: 'Memory content contains the word "exfiltrate"',
      danger: 'Explicit data theft instruction — content is attempting to extract sensitive data from your workspace' },
    { pattern: /send\s+.*\b(token|key|secret|password|credential)\b.*\bto\b/i,
      reason: 'Memory content instructs sending credentials to an external destination',
      danger: 'Credential theft — directly attempts to extract authentication secrets from your environment' },
    { pattern: /override\s+.*\b(security|safety|rules)\b/i,
      reason: 'Memory content attempts to override security or safety rules',
      danger: 'Security bypass — could disable the AI\'s safety mechanisms, allowing destructive or unauthorized actions' },
  ];
  for (const check of checks) {
    if (check.pattern.test(content)) return { reason: check.reason, danger: check.danger };
  }
  return null;
}

export function extractMemoryOp(event: TrackerEvent): MemoryOperation | null {
  if (!['memory_read', 'memory_write', 'memory_delete'].includes(event.event_type)) return null;
  const args = event.parameters || {};
  const memPath = (args.path as string) || '';

  let scope: MemoryOperation['memory_scope'] = 'unknown';
  if (memPath.includes('/memories/session/')) scope = 'session';
  else if (memPath.includes('/memories/repo/')) scope = 'repo';
  else if (memPath.startsWith('/memories/') || memPath.includes('/memories/')) scope = 'user';

  let operation: MemoryOperation['operation'] = 'read';
  const cmd = args.command as string | undefined;
  if (cmd === 'create' || cmd === 'str_replace' || cmd === 'insert') operation = 'write';
  else if (cmd === 'delete') operation = 'delete';
  else operation = 'read';

  const content = (args.file_text as string) || (args.insert_text as string) || (args.new_str as string) || '';
  const summary = content.substring(0, 300) || `${operation} ${memPath}`;

  return {
    event_id: null,
    session_id: event.session_id,
    timestamp: event.timestamp,
    operation,
    memory_scope: scope,
    memory_path: memPath,
    content_summary: summary,
    risk_level: event.risk_level,
  };
}

function escalate(current: RiskLevel, candidate: RiskLevel): RiskLevel {
  const order: RiskLevel[] = ['info', 'watch', 'warn', 'danger'];
  return order.indexOf(candidate) > order.indexOf(current) ? candidate : current;
}
