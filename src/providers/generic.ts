import * as fs from 'fs';
import * as path from 'path';
import { LogProvider, TranscriptFile } from './types';
import { TrackerEvent, EventType } from '../parser/event-types';
import { SessionParserState } from '../parser';

/**
 * Generic provider that watches a user-configured directory for JSONL files.
 * Tries to parse lines as tool calls using common field naming conventions
 * across different AI coding tools (Aider, Cursor, Windsurf, Agency, OpenClaw, etc.)
 *
 * Supports these heuristic patterns:
 * 1. { type: "tool_call", tool: "...", args: {...} }
 * 2. { role: "assistant", content: [{ type: "tool_use", name: "..." }] }  (Anthropic style)
 * 3. { type: "function_call", function: { name: "...", arguments: {...} } }  (OpenAI style)
 * 4. { action: "...", file: "...", command: "..." }  (generic action log)
 */

export class GenericProvider implements LogProvider {
  id: string;
  displayName: string;
  icon = '📄';
  private basePaths: string[];

  constructor(id: string, displayName: string, basePaths: string[], icon?: string) {
    this.id = id;
    this.displayName = displayName;
    this.basePaths = basePaths;
    if (icon) this.icon = icon;
  }

  getDefaultLogPaths(): string[] {
    return this.basePaths.filter(p => fs.existsSync(p));
  }

  discoverSessions(basePaths?: string[]): TranscriptFile[] {
    const paths = basePaths?.length ? basePaths : this.getDefaultLogPaths();
    const results: TranscriptFile[] = [];

    for (const base of paths) {
      if (!fs.existsSync(base)) continue;
      this.scanDir(base, base, results);
    }
    return results;
  }

  private scanDir(dir: string, base: string, results: TranscriptFile[], depth = 0) {
    if (depth > 4) return; // Don't recurse too deep
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isFile() && entry.name.endsWith('.jsonl')) {
          const relative = path.relative(base, dir);
          results.push({
            filePath: fullPath,
            sessionId: `${this.id}-${entry.name.replace('.jsonl', '')}`,
            workspace: relative || path.basename(base),
            projectName: relative ? path.basename(relative) : path.basename(base),
            providerId: this.id,
          });
        } else if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
          this.scanDir(fullPath, base, results, depth + 1);
        }
      }
    } catch { /* permission errors */ }
  }

  watchForNewSessions(basePath: string, onNew: (file: TranscriptFile) => void): fs.FSWatcher | null {
    if (!fs.existsSync(basePath)) return null;
    return fs.watch(basePath, { recursive: true }, (_eventType, filename) => {
      if (!filename || !filename.endsWith('.jsonl')) return;
      const fullPath = path.join(basePath, filename);
      if (!fs.existsSync(fullPath)) return;

      const parts = filename.split(path.sep);
      const projectName = parts.length > 1 ? parts[0] : path.basename(basePath);

      onNew({
        filePath: fullPath,
        sessionId: `${this.id}-${parts[parts.length - 1].replace('.jsonl', '')}`,
        workspace: projectName,
        projectName,
        providerId: this.id,
      });
    });
  }

  parseLine(line: string, sessionId: string, _workspace: string, _state?: SessionParserState): TrackerEvent | null {
    let raw: Record<string, unknown>;
    try {
      raw = JSON.parse(line);
    } catch {
      return null;
    }

    const timestamp = (raw.timestamp as string) || new Date().toISOString();

    // Strategy 1: Anthropic-style tool_use in content array
    if (raw.role === 'assistant' && Array.isArray(raw.content)) {
      for (const block of raw.content as Array<Record<string, unknown>>) {
        if (block.type === 'tool_use' && block.name) {
          return this.makeEvent(sessionId, timestamp, block.name as string, (block.input || {}) as Record<string, unknown>, line);
        }
      }
    }

    // Strategy 2: OpenAI-style function_call
    if (raw.type === 'function_call' && raw.function && typeof raw.function === 'object') {
      const fn = raw.function as Record<string, unknown>;
      const args = typeof fn.arguments === 'string' ? JSON.parse(fn.arguments) : (fn.arguments || {});
      return this.makeEvent(sessionId, timestamp, fn.name as string, args, line);
    }

    // Strategy 3: Direct tool_call / tool.execution_start
    if ((raw.type === 'tool_call' || raw.type === 'tool.execution_start') && (raw.tool || raw.toolName || (raw.data as Record<string, unknown>)?.toolName)) {
      const toolName = (raw.tool || raw.toolName || (raw.data as Record<string, unknown>)?.toolName) as string;
      const args = (raw.args || raw.arguments || raw.input || (raw.data as Record<string, unknown>)?.arguments || {}) as Record<string, unknown>;
      return this.makeEvent(sessionId, timestamp, toolName, args, line);
    }

    // Strategy 4: Generic action log
    if (raw.action && typeof raw.action === 'string') {
      return this.makeEvent(sessionId, timestamp, raw.action, raw as Record<string, unknown>, line);
    }

    // Strategy 5: User message
    if (raw.role === 'user' || raw.type === 'user' || raw.type === 'user.message') {
      const text = typeof raw.content === 'string' ? raw.content :
        (Array.isArray(raw.content) ? (raw.content[0] as Record<string, unknown>)?.text as string || '' : '');
      if (!text) return null;
      return {
        session_id: sessionId,
        timestamp,
        agent_id: 'user',
        parent_agent_id: null,
        event_type: 'user_message',
        tool_name: null,
        risk_level: 'info',
        summary: `User: "${text.substring(0, 200)}"`,
        file_paths: [],
        command: null,
        parameters: null,
        duration_ms: null,
        raw_log: line.substring(0, 50000),
        source_tool: this.id,
      };
    }

    return null;
  }

  private makeEvent(sessionId: string, timestamp: string, toolName: string, args: Record<string, unknown>, rawLine: string): TrackerEvent {
    let eventType: EventType = guessEventType(toolName, args);
    const filePaths: string[] = [];
    let command: string | null = null;

    // Extract file paths from common field names
    for (const key of ['file_path', 'filePath', 'path', 'file', 'filename']) {
      if (typeof args[key] === 'string') filePaths.push(args[key] as string);
    }

    // Extract command from common field names
    for (const key of ['command', 'cmd', 'shell_command']) {
      if (typeof args[key] === 'string') { command = args[key] as string; break; }
    }

    if (command) {
      if (/\bgit\s+push\b/.test(command)) eventType = 'git_push';
      else if (/\bgit\s+commit\b/.test(command)) eventType = 'git_commit';
      else if (/\bgit\s+reset\b/.test(command)) eventType = 'git_reset';
      else if (/\bgit\s+/.test(command)) eventType = 'git_operation';
    }

    const summary = command ? `${toolName}: ${command.substring(0, 80)}` :
      filePaths.length ? `${toolName}: ${filePaths[0].split(/[/\\]/).slice(-2).join('/')}` :
      `${toolName}: ${JSON.stringify(args).substring(0, 80)}`;

    return {
      session_id: sessionId,
      timestamp,
      agent_id: 'main',
      parent_agent_id: null,
      event_type: eventType,
      tool_name: toolName,
      risk_level: 'info',
      summary,
      file_paths: [...new Set(filePaths)],
      command,
      parameters: args,
      duration_ms: null,
      raw_log: rawLine.substring(0, 2000),
      source_tool: this.id,
    };
  }
}

/** Best-effort guess at event type from tool name */
function guessEventType(name: string, args: Record<string, unknown>): EventType {
  const n = name.toLowerCase();
  if (/read|view|cat|head|tail/.test(n)) return 'file_read';
  if (/write|create|touch|mkdir/.test(n)) return 'file_create';
  if (/edit|replace|patch|modify|update/.test(n)) return 'file_write';
  if (/delete|remove|rm|unlink/.test(n)) return 'file_delete';
  if (/terminal|shell|bash|exec|run|command/.test(n)) return 'terminal_command';
  if (/search|grep|find|glob|ripgrep|rg/.test(n)) return 'search';
  if (/fetch|web|http|curl|browse/.test(n)) return 'web_fetch';
  if (/memory|remember|forget/.test(n)) return 'memory_write';
  if (/agent|subagent|spawn|delegate/.test(n)) return 'subagent_spawn';
  if (/git/.test(n)) return 'git_operation';
  if (typeof args.command === 'string') return 'terminal_command';
  if (typeof args.file_path === 'string' || typeof args.filePath === 'string') return 'file_read';
  return 'tool_call';
}
