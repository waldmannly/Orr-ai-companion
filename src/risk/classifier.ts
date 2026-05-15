import { TrackerEvent, RiskLevel, MemoryOperation } from '../parser/event-types';
import { Config } from '../config';
import { minimatch } from 'minimatch';

export function classifyRisk(event: TrackerEvent, config: Config): RiskLevel {
  // Start with info, escalate based on rules
  let level: RiskLevel = 'info';

  // File writes are at least 'watch'
  if (['file_write', 'file_create', 'file_delete'].includes(event.event_type)) {
    level = escalate(level, 'watch');
  }

  // Terminal commands are 'watch'
  if (['terminal_command', 'terminal_send'].includes(event.event_type)) {
    level = escalate(level, 'watch');
  }

  // Git operations
  if (event.event_type === 'git_commit') level = escalate(level, 'watch');
  if (event.event_type === 'git_push') {
    level = escalate(level, 'watch');
    if (event.command && /--force|-f\b/.test(event.command)) {
      level = escalate(level, 'danger');
    }
  }
  if (event.event_type === 'git_reset') {
    if (event.command && /--hard/.test(event.command)) {
      level = escalate(level, 'danger');
    } else {
      level = escalate(level, 'warn');
    }
  }

  // Memory operations
  if (event.event_type === 'memory_write') level = escalate(level, 'warn');
  if (event.event_type === 'memory_delete') level = escalate(level, 'warn');
  if (event.event_type === 'memory_read') level = escalate(level, 'watch');

  // Sub-agent spawn
  if (event.event_type === 'subagent_spawn') level = escalate(level, 'watch');

  // Web fetch
  if (event.event_type === 'web_fetch') level = escalate(level, 'watch');

  // Check dangerous commands
  if (event.command) {
    for (const pattern of config.dangerousCommands) {
      if (event.command.toLowerCase().includes(pattern.toLowerCase())) {
        level = escalate(level, 'danger');
        break;
      }
    }
  }

  // Check sensitive files
  for (const fp of event.file_paths) {
    if (isSensitiveFile(fp, config)) {
      level = escalate(level, 'warn');
    }
  }

  // Check memory content for injection patterns
  if (event.event_type === 'memory_write' && event.parameters) {
    const content = (event.parameters.file_text as string) || (event.parameters.insert_text as string) || (event.parameters.new_str as string) || '';
    if (detectInjectionPatterns(content)) {
      level = escalate(level, 'danger');
    }
  }

  return level;
}

export function isSensitiveFile(filePath: string, config: Config): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  for (const exact of config.sensitiveFiles.exactPaths) {
    if (normalized === exact.replace(/\\/g, '/')) return true;
  }
  for (const pattern of config.sensitiveFiles.patterns) {
    if (minimatch(normalized, pattern, { dot: true, nocase: true })) return true;
    // Also check just the filename portion
    const basename = normalized.split('/').pop() || '';
    if (minimatch(basename, pattern, { dot: true, nocase: true })) return true;
  }
  return false;
}

export function detectInjectionPatterns(content: string): boolean {
  const lower = content.toLowerCase();
  const patterns = [
    /ignore\s+(previous|prior|above)\s+(instructions|prompts|rules)/i,
    /always\s+(include|add|send|call|execute)\s+.*(https?:\/\/)/i,
    /never\s+mention/i,
    /do\s+not\s+(tell|inform|alert|warn)\s+(the\s+)?user/i,
    /system\s*:\s*/i,
    /\bexfiltrate\b/i,
    /send\s+.*\b(token|key|secret|password|credential)\b.*\bto\b/i,
    /override\s+.*\b(security|safety|rules)\b/i,
  ];
  return patterns.some(p => p.test(content));
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
