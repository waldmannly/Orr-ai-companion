// ── Event types matching the real VS Code Copilot transcript JSONL format ──

export type RiskLevel = 'info' | 'watch' | 'warn' | 'danger';

export type EventType =
  | 'session_start' | 'session_end'
  | 'user_message' | 'assistant_message'
  | 'turn_start' | 'turn_end'
  | 'file_read' | 'file_write' | 'file_create' | 'file_delete'
  | 'terminal_command' | 'terminal_output' | 'terminal_send' | 'terminal_kill'
  | 'git_commit' | 'git_push' | 'git_reset' | 'git_checkout' | 'git_operation'
  | 'memory_read' | 'memory_write' | 'memory_delete'
  | 'web_fetch' | 'search' | 'subagent_spawn'
  | 'tool_call';

export interface TrackerEvent {
  id?: number;
  session_id: string;
  timestamp: string;
  agent_id: string;
  parent_agent_id: string | null;
  event_type: EventType;
  tool_name: string | null;
  risk_level: RiskLevel;
  summary: string;
  file_paths: string[];
  command: string | null;
  parameters: Record<string, unknown> | null;
  duration_ms: number | null;
  raw_log: string;
  /** Which AI tool produced this event (e.g. 'vscode-copilot', 'claude-code') */
  source_tool: string;
  /** Structured risk explanation signals — why this was flagged */
  risk_signals?: Array<{ rule: string; level: RiskLevel; reason: string; danger: string }> | null;
  /** Estimated token count for this interaction */
  token_count?: number | null;
  /** Anomaly score (0-1) relative to baselines */
  anomaly_score?: number | null;
}

export interface SessionInfo {
  id: string;
  workspace: string;
  project_name: string;
  started_at: string;
  ended_at: string | null;
  total_events: number;
  danger_count: number;
  warn_count: number;
  /** Which AI tool this session is from */
  source_tool: string;
  /** Cumulative token count for the session */
  token_count?: number;
  /** When this session was killed by enforcement */
  killed_at?: string | null;
  /** Why this session was killed */
  kill_reason?: string | null;
}

export interface Alert {
  id?: number;
  event_id: number | null;
  session_id: string;
  timestamp: string;
  alert_type: string;
  severity: RiskLevel;
  message: string;
  acknowledged: boolean;
}

export interface MemoryOperation {
  id?: number;
  event_id: number | null;
  session_id: string;
  timestamp: string;
  operation: 'read' | 'write' | 'delete';
  memory_scope: 'user' | 'session' | 'repo' | 'unknown';
  memory_path: string;
  content_summary: string;
  risk_level: RiskLevel;
}

// Raw JSONL line from VS Code transcript
export interface RawTranscriptLine {
  type: string;
  data: Record<string, unknown>;
  id: string;
  timestamp: string;
  parentId: string | null;
}
