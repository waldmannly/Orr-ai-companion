import * as fs from 'fs';
import * as path from 'path';
import { LogProvider, TranscriptFile } from './types';
import { TrackerEvent, EventType } from '../parser/event-types';
import { SessionParserState } from '../parser';

/**
 * Claude Code JSONL format:
 *   type: 'user' | 'assistant' | 'system' | 'queue-operation' | 'attachment' | 'last-prompt'
 *   message.content: array of { type: 'text' | 'tool_use' | 'tool_result', ... }
 *   Tool names: Bash, Read, Edit, Write, Grep, Glob, Agent, TodoWrite, WebFetch, etc.
 */

const CLAUDE_TOOL_MAP: Record<string, EventType> = {
  Read: 'file_read',
  Edit: 'file_write',
  Write: 'file_create',
  Bash: 'terminal_command',
  Grep: 'search',
  Glob: 'search',
  Agent: 'subagent_spawn',
  TodoWrite: 'tool_call',
  TodoRead: 'tool_call',
  WebFetch: 'web_fetch',
  AskUserQuestion: 'tool_call',
  EnterPlanMode: 'tool_call',
  TaskOutput: 'tool_call',
  TaskStop: 'tool_call',
  MultiEdit: 'file_write',
  NotebookEdit: 'file_write',
  NotebookRead: 'file_read',
};

interface ClaudeContent {
  type: string;
  text?: string;
  name?: string;
  id?: string;
  input?: Record<string, unknown>;
  tool_use_id?: string;
  content?: unknown;
  is_error?: boolean;
  signature?: string;
}

interface ClaudeLine {
  type: string;
  parentUuid?: string;
  isSidechain?: boolean;
  promptId?: string;
  sessionId?: string;
  timestamp?: string;
  message?: {
    role?: string;
    content?: ClaudeContent[] | string;
  };
}

export class ClaudeCodeProvider implements LogProvider {
  id = 'claude-code';
  displayName = 'Claude Code';
  icon = '🟠';

  getDefaultLogPaths(): string[] {
    const home = process.env.USERPROFILE || process.env.HOME || '';
    const claudeDir = path.join(home, '.claude', 'projects');
    return fs.existsSync(claudeDir) ? [claudeDir] : [];
  }

  discoverSessions(basePaths?: string[]): TranscriptFile[] {
    const paths = basePaths?.length ? basePaths : this.getDefaultLogPaths();
    const results: TranscriptFile[] = [];

    for (const base of paths) {
      if (!fs.existsSync(base)) continue;
      // ~/.claude/projects/<project-hash>/<sessionId>.jsonl
      const projectDirs = fs.readdirSync(base, { withFileTypes: true });
      for (const pDir of projectDirs) {
        if (!pDir.isDirectory()) continue;
        const projectPath = path.join(base, pDir.name);
        const projectName = decodeClaudeProjectName(pDir.name);

        const files = fs.readdirSync(projectPath, { withFileTypes: true });
        for (const file of files) {
          if (!file.isFile() || !file.name.endsWith('.jsonl')) continue;
          results.push({
            filePath: path.join(projectPath, file.name),
            sessionId: `cc-${file.name.replace('.jsonl', '')}`,
            workspace: pDir.name,
            projectName,
            providerId: this.id,
          });
        }
      }
    }
    return results;
  }

  watchForNewSessions(basePath: string, onNew: (file: TranscriptFile) => void): fs.FSWatcher | null {
    if (!fs.existsSync(basePath)) return null;
    return fs.watch(basePath, { recursive: true }, (_eventType, filename) => {
      if (!filename || !filename.endsWith('.jsonl')) return;
      const fullPath = path.join(basePath, filename);
      if (!fs.existsSync(fullPath)) return;

      const parts = filename.split(path.sep);
      if (parts.length < 2) return;
      const projectHash = parts[0];
      const sessionFile = parts[parts.length - 1];

      onNew({
        filePath: fullPath,
        sessionId: `cc-${sessionFile.replace('.jsonl', '')}`,
        workspace: projectHash,
        projectName: decodeClaudeProjectName(projectHash),
        providerId: this.id,
      });
    });
  }

  parseLine(line: string, sessionId: string, _workspace: string, state?: SessionParserState): TrackerEvent | null {
    let raw: ClaudeLine;
    try {
      raw = JSON.parse(line);
    } catch {
      return null;
    }

    // Skip non-message types
    if (raw.type === 'queue-operation' || raw.type === 'attachment' || raw.type === 'last-prompt' || raw.type === 'system') {
      return null;
    }

    const timestamp = raw.timestamp || new Date().toISOString();

    // User message
    if (raw.type === 'user') {
      const text = extractClaudeText(raw.message?.content);
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
        source_tool: 'claude-code',
      };
    }

    // Assistant message — may contain tool_use blocks
    if (raw.type === 'assistant' && raw.message?.content && Array.isArray(raw.message.content)) {
      const events: TrackerEvent[] = [];

      for (const block of raw.message.content) {
        if (block.type === 'tool_use' && block.name) {
          const event = parseClaudeToolUse(block, sessionId, timestamp, line, state);
          if (event) events.push(event);
        }
      }

      // If no tool calls, it's just an assistant text message — skip (too noisy)
      if (events.length === 0) return null;

      // Return the first tool call event (most significant)
      // Additional tool calls in the same message are less common
      return events[0];
    }

    return null;
  }
}

function parseClaudeToolUse(block: ClaudeContent, sessionId: string, timestamp: string, rawLine: string, state?: SessionParserState): TrackerEvent | null {
  const toolName = block.name || 'unknown';
  const input = block.input || {};
  let eventType: EventType = CLAUDE_TOOL_MAP[toolName] || 'tool_call';

  // Extract file paths
  const filePaths: string[] = [];
  if (typeof input.file_path === 'string') filePaths.push(input.file_path);
  if (typeof input.path === 'string') filePaths.push(input.path);
  if (typeof input.pattern === 'string' && toolName === 'Glob') filePaths.push(input.pattern as string);

  // Extract command
  let command: string | null = null;
  if (toolName === 'Bash' && typeof input.command === 'string') {
    command = input.command;
    // Detect git operations
    if (/\bgit\s+push\b/.test(command)) eventType = 'git_push';
    else if (/\bgit\s+commit\b/.test(command)) eventType = 'git_commit';
    else if (/\bgit\s+reset\b/.test(command)) eventType = 'git_reset';
    else if (/\bgit\s+checkout\b/.test(command) || /\bgit\s+switch\b/.test(command)) eventType = 'git_checkout';
    else if (/\bgit\s+/.test(command)) eventType = 'git_operation';
  }

  // Build summary
  const summary = buildClaudeSummary(toolName, input, command);

  // Sub-agent tracking
  let agentId = 'main';
  let parentAgentId: string | null = null;
  if (toolName === 'Agent') {
    agentId = state?.isInsideSubagent() ? state.currentAgentId() : 'main';
    if (state && block.id) {
      const agentName = (input.name as string) || (input.prompt as string || '').substring(0, 20) || 'sub';
      state.pushSubagent(block.id, agentName);
    }
  } else if (state?.isInsideSubagent()) {
    agentId = state.currentAgentId();
    parentAgentId = state.currentAgentName();
  }

  return {
    session_id: sessionId,
    timestamp,
    agent_id: agentId,
    parent_agent_id: parentAgentId,
    event_type: eventType,
    tool_name: toolName,
    risk_level: 'info',
    summary,
    file_paths: [...new Set(filePaths)],
    command,
    parameters: input as Record<string, unknown>,
    duration_ms: null,
    raw_log: rawLine.substring(0, 2000),
    source_tool: 'claude-code',
  };
}

function buildClaudeSummary(toolName: string, input: Record<string, unknown>, command: string | null): string {
  switch (toolName) {
    case 'Read': {
      const fp = (input.file_path as string) || '';
      const short = fp.split(/[/\\]/).slice(-2).join('/');
      return `Read ${short}`;
    }
    case 'Edit': {
      const fp = (input.file_path as string) || '';
      const short = fp.split(/[/\\]/).slice(-2).join('/');
      return `Edit ${short}`;
    }
    case 'MultiEdit': {
      const fp = (input.file_path as string) || '';
      const short = fp.split(/[/\\]/).slice(-2).join('/');
      return `Multi-edit ${short}`;
    }
    case 'Write': {
      const fp = (input.file_path as string) || '';
      const short = fp.split(/[/\\]/).slice(-2).join('/');
      return `Create ${short}`;
    }
    case 'Bash': return `Terminal: ${(command || '').substring(0, 80)}`;
    case 'Grep': return `Grep: "${(input.pattern as string || '').substring(0, 60)}"`;
    case 'Glob': return `Glob: ${(input.pattern as string || '').substring(0, 60)}`;
    case 'Agent': return `Sub-agent: ${(input.prompt as string || '').substring(0, 80)}`;
    case 'WebFetch': return `Fetch: ${(input.url as string || '').substring(0, 60)}`;
    case 'TodoWrite': return `Update todo list`;
    case 'AskUserQuestion': return `Ask user: "${(input.question as string || '').substring(0, 60)}"`;
    default: return `${toolName}: ${JSON.stringify(input).substring(0, 80)}`;
  }
}

function extractClaudeText(content: ClaudeContent[] | string | undefined): string | null {
  if (!content) return null;
  if (typeof content === 'string') return content;
  for (const block of content) {
    if (block.type === 'text' && block.text) return block.text;
  }
  return null;
}

/** Decode Claude Code project directory name back to a readable project name.
 * Format: c--Users-jane-Desktop-code-projects-my-app → my-app */
function decodeClaudeProjectName(dirName: string): string {
  // Claude encodes paths like: c--Users-jane-Desktop-code-projects-my-app
  const parts = dirName.split('-');
  // Take the last meaningful segment as the project name
  // Filter out empty parts and common path components
  const skip = new Set(['c', '', 'users', 'user', 'home', 'desktop', 'files', 'documents', 'code', 'projects', 'repos', 'src']);
  const meaningful = parts.filter(p => !skip.has(p.toLowerCase()));
  if (meaningful.length > 0) {
    // Join the last few parts to form the project name
    return meaningful.slice(-3).join('-') || dirName;
  }
  return dirName;
}
