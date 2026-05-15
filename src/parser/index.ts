import { TrackerEvent, EventType, RawTranscriptLine } from './event-types';

/**
 * Tracks sub-agent context across JSONL lines for a single session.
 * When a runSubagent tool.execution_start is seen, we push its toolCallId
 * onto the stack with the agent name. When the matching
 * tool.execution_complete arrives (same toolCallId), we pop.
 */
export class SessionParserState {
  // Stack of active sub-agents: { toolCallId, agentName }
  private subagentStack: Array<{ toolCallId: string; agentName: string }> = [];

  pushSubagent(toolCallId: string, agentName: string) {
    this.subagentStack.push({ toolCallId, agentName });
  }

  popSubagent(toolCallId: string): boolean {
    const idx = this.subagentStack.findIndex(s => s.toolCallId === toolCallId);
    if (idx >= 0) {
      this.subagentStack.splice(idx, 1);
      return true;
    }
    return false;
  }

  isInsideSubagent(): boolean {
    return this.subagentStack.length > 0;
  }

  currentAgentId(): string {
    if (this.subagentStack.length === 0) return 'main';
    const top = this.subagentStack[this.subagentStack.length - 1];
    return `sub:${top.agentName}`;
  }

  currentAgentName(): string | null {
    if (this.subagentStack.length === 0) return null;
    return this.subagentStack[this.subagentStack.length - 1].agentName;
  }
}

// Tool name → EventType mapping
const TOOL_EVENT_MAP: Record<string, EventType> = {
  read_file: 'file_read',
  replace_string_in_file: 'file_write',
  multi_replace_string_in_file: 'file_write',
  create_file: 'file_create',
  create_directory: 'file_create',
  run_in_terminal: 'terminal_command',
  get_terminal_output: 'terminal_output',
  send_to_terminal: 'terminal_send',
  kill_terminal: 'terminal_kill',
  memory: 'tool_call', // further classified by classifyMemoryOp
  fetch_webpage: 'web_fetch',
  grep_search: 'search',
  semantic_search: 'search',
  file_search: 'search',
  list_dir: 'search',
  runSubagent: 'subagent_spawn',
  view_image: 'file_read',
  open_browser_page: 'web_fetch',
};

function classifyMemoryOp(args: Record<string, unknown>): EventType {
  const cmd = args.command as string | undefined;
  if (cmd === 'create' || cmd === 'str_replace' || cmd === 'insert') return 'memory_write';
  if (cmd === 'delete') return 'memory_delete';
  return 'memory_read';
}

function extractFilePaths(toolName: string, args: Record<string, unknown>): string[] {
  const paths: string[] = [];
  if (args.filePath && typeof args.filePath === 'string') paths.push(args.filePath);
  if (args.path && typeof args.path === 'string') paths.push(args.path);
  if (Array.isArray(args.replacements)) {
    for (const r of args.replacements) {
      if (r && typeof r === 'object' && typeof (r as Record<string, unknown>).filePath === 'string') {
        paths.push((r as Record<string, unknown>).filePath as string);
      }
    }
  }
  return [...new Set(paths)];
}

function extractCommand(toolName: string, args: Record<string, unknown>): string | null {
  if (toolName === 'run_in_terminal' || toolName === 'send_to_terminal') {
    return (args.command as string) || null;
  }
  return null;
}

function buildSummary(toolName: string, args: Record<string, unknown>, eventType: EventType): string {
  const fileP = (args.filePath || args.path || '') as string;
  const shortPath = fileP ? fileP.split(/[/\\]/).slice(-2).join('/') : '';

  switch (toolName) {
    case 'read_file': return `Read ${shortPath} (L${args.startLine || '?'}-${args.endLine || '?'})`;
    case 'replace_string_in_file': return `Edit ${shortPath}`;
    case 'multi_replace_string_in_file': {
      const count = Array.isArray(args.replacements) ? args.replacements.length : 0;
      return `Multi-edit (${count} changes)`;
    }
    case 'create_file': return `Create ${shortPath}`;
    case 'run_in_terminal': return `Terminal: ${((args.command as string) || '').substring(0, 80)}`;
    case 'get_terminal_output': return `Get terminal output`;
    case 'send_to_terminal': return `Send to terminal: ${((args.command as string) || '').substring(0, 60)}`;
    case 'kill_terminal': return `Kill terminal`;
    case 'memory': {
      const cmd = args.command as string || 'view';
      const memPath = (args.path as string) || '';
      const shortMem = memPath.split('/').slice(-2).join('/');
      return `Memory ${cmd}: ${shortMem}`;
    }
    case 'grep_search': return `Grep: "${(args.query as string || '').substring(0, 60)}"`;
    case 'semantic_search': return `Semantic search: "${(args.query as string || '').substring(0, 60)}"`;
    case 'file_search': return `File search: ${(args.query as string || '').substring(0, 60)}`;
    case 'list_dir': return `List dir: ${shortPath}`;
    case 'fetch_webpage': return `Fetch: ${(Array.isArray(args.urls) ? (args.urls[0] || '') : '').toString().substring(0, 60)}`;
    case 'runSubagent': {
      const name = (args.agentName as string) || 'unnamed';
      const desc = (args.description as string) || '';
      const model = (args.model as string) || '';
      return `Sub-agent [${name}]${model ? ` (${model})` : ''}: ${desc}`;
    }
    case 'open_browser_page': return `Open browser: ${((args.url as string) || '').substring(0, 60)}`;
    case 'manage_todo_list': return `Update todo list`;
    case 'task_complete': return `Task complete`;
    case 'vscode_askQuestions': return `Ask user questions`;
    case 'tool_search': return `Tool search: "${(args.query as string || '').substring(0, 40)}"`;
    default: return `${toolName}: ${JSON.stringify(args).substring(0, 80)}`;
  }
}

export function parseTranscriptLine(line: string, sessionId: string, workspace: string, state?: SessionParserState): TrackerEvent | null {
  let raw: RawTranscriptLine;
  try {
    raw = JSON.parse(line);
  } catch {
    return null;
  }

  const timestamp = raw.timestamp || new Date().toISOString();

  // Check for tool.execution_complete — used to close sub-agent scopes
  if (raw.type === 'tool.execution_complete' && state) {
    const toolCallId = raw.data.toolCallId as string | undefined;
    if (toolCallId) {
      state.popSubagent(toolCallId);
    }
    return null; // We don't create events for execution_complete
  }

  // Session start
  if (raw.type === 'session.start') {
    return {
      session_id: sessionId,
      timestamp,
      agent_id: 'system',
      parent_agent_id: null,
      event_type: 'session_start',
      tool_name: null,
      risk_level: 'info',
      summary: `Session started (Copilot ${(raw.data.copilotVersion as string) || '?'})`,
      file_paths: [],
      command: null,
      parameters: raw.data,
      duration_ms: null,
      raw_log: line,
      source_tool: 'vscode-copilot',
    };
  }

  // User message
  if (raw.type === 'user.message') {
    const text = ((raw.data as Record<string, unknown>).content as string || '').substring(0, 200);
    return {
      session_id: sessionId,
      timestamp,
      agent_id: 'user',
      parent_agent_id: null,
      event_type: 'user_message',
      tool_name: null,
      risk_level: 'info',
      summary: `User: "${text}"`,
      file_paths: [],
      command: null,
      parameters: null,
      duration_ms: null,
      raw_log: line.substring(0, 500),
      source_tool: 'vscode-copilot',
    };
  }

  // Tool execution start — the main event we care about
  if (raw.type === 'tool.execution_start') {
    const toolName = raw.data.toolName as string;
    const args = (raw.data.arguments || {}) as Record<string, unknown>;

    let eventType = TOOL_EVENT_MAP[toolName] || 'tool_call';
    if (toolName === 'memory') eventType = classifyMemoryOp(args);

    // Detect git operations from terminal commands
    const cmd = extractCommand(toolName, args);
    if (cmd && eventType === 'terminal_command') {
      if (/\bgit\s+push\b/.test(cmd)) eventType = 'git_push';
      else if (/\bgit\s+commit\b/.test(cmd)) eventType = 'git_commit';
      else if (/\bgit\s+reset\b/.test(cmd)) eventType = 'git_reset';
      else if (/\bgit\s+checkout\b/.test(cmd) || /\bgit\s+switch\b/.test(cmd)) eventType = 'git_checkout';
      else if (/\bgit\s+/.test(cmd)) eventType = 'git_operation';
    }

    const summary = buildSummary(toolName, args, eventType);
    const filePaths = extractFilePaths(toolName, args);

    // Determine agent identity using stateful sub-agent tracking
    let agentId = 'main';
    let parentAgentId: string | null = null;
    const toolCallId = raw.data.toolCallId as string | undefined;

    if (toolName === 'runSubagent') {
      // Main agent is spawning a sub-agent — push onto state stack
      agentId = state?.isInsideSubagent() ? state.currentAgentId() : 'main';
      if (state && toolCallId) {
        const agentName = (args.agentName as string) || 'unnamed';
        state.pushSubagent(toolCallId, agentName);
      }
    } else if (state?.isInsideSubagent()) {
      // Inside a sub-agent scope — mark with sub-agent identity
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
      risk_level: 'info', // will be set by risk classifier
      summary,
      file_paths: filePaths,
      command: cmd,
      parameters: args,
      duration_ms: null,
      raw_log: line.substring(0, 2000),
      source_tool: 'vscode-copilot',
    };
  }

  // Tool execution complete is handled above (for sub-agent scope tracking)
  // Turn start/end, assistant.message — we skip unless needed
  if (raw.type === 'assistant.turn_start') {
    return {
      session_id: sessionId,
      timestamp,
      agent_id: 'assistant',
      parent_agent_id: null,
      event_type: 'turn_start',
      tool_name: null,
      risk_level: 'info',
      summary: `Turn ${(raw.data.turnId as string) || '?'} started`,
      file_paths: [],
      command: null,
      parameters: raw.data,
      duration_ms: null,
      raw_log: line.substring(0, 500),
      source_tool: 'vscode-copilot',
    };
  }

  if (raw.type === 'assistant.turn_end') {
    return {
      session_id: sessionId,
      timestamp,
      agent_id: 'assistant',
      parent_agent_id: null,
      event_type: 'turn_end',
      tool_name: null,
      risk_level: 'info',
      summary: `Turn ended`,
      file_paths: [],
      command: null,
      parameters: raw.data,
      duration_ms: null,
      raw_log: line.substring(0, 500),
      source_tool: 'vscode-copilot',
    };
  }

  return null; // Skip unrecognized types
}
