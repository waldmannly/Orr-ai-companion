import * as fs from 'fs';
import * as path from 'path';
import { LogProvider, TranscriptFile } from './types';
import { TrackerEvent, EventType } from '../parser/event-types';
import { SessionParserState } from '../parser';

/**
 * Gemini CLI stores project markers in ~/.gemini/history/<project>/
 * Session conversations may be stored as JSONL when sessionRetention is enabled.
 * Format is evolving — this provider handles the known structures.
 *
 * Gemini CLI tool names: shell, read_file, edit_file, write_file, search, etc.
 */

const GEMINI_TOOL_MAP: Record<string, EventType> = {
  shell: 'terminal_command',
  read_file: 'file_read',
  read_many_files: 'file_read',
  edit_file: 'file_write',
  write_file: 'file_create',
  search_files: 'search',
  list_dir: 'search',
  find_files: 'search',
  web_search: 'web_fetch',
};

interface GeminiLine {
  type?: string;
  role?: string;
  parts?: Array<{
    functionCall?: { name: string; args: Record<string, unknown> };
    functionResponse?: { name: string; response: unknown };
    text?: string;
  }>;
  timestamp?: string;
  toolCall?: { name: string; args: Record<string, unknown> };
}

export class GeminiCliProvider implements LogProvider {
  id = 'gemini-cli';
  displayName = 'Gemini CLI';
  icon = '🔵';

  getDefaultLogPaths(): string[] {
    const home = process.env.USERPROFILE || process.env.HOME || '';
    const historyDir = path.join(home, '.gemini', 'history');
    return fs.existsSync(historyDir) ? [historyDir] : [];
  }

  discoverSessions(basePaths?: string[]): TranscriptFile[] {
    const paths = basePaths?.length ? basePaths : this.getDefaultLogPaths();
    const results: TranscriptFile[] = [];

    for (const base of paths) {
      if (!fs.existsSync(base)) continue;
      const projectDirs = fs.readdirSync(base, { withFileTypes: true });
      for (const pDir of projectDirs) {
        if (!pDir.isDirectory()) continue;
        const projectPath = path.join(base, pDir.name);

        // Look for JSONL session files
        try {
          const files = fs.readdirSync(projectPath, { withFileTypes: true });
          for (const file of files) {
            if (!file.isFile() || !file.name.endsWith('.jsonl')) continue;
            results.push({
              filePath: path.join(projectPath, file.name),
              sessionId: `gem-${pDir.name}-${file.name.replace('.jsonl', '')}`,
              workspace: pDir.name,
              projectName: pDir.name,
              providerId: this.id,
            });
          }
        } catch { /* permission errors */ }
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
      const projectName = parts[0] || 'unknown';
      const sessionFile = parts[parts.length - 1];

      onNew({
        filePath: fullPath,
        sessionId: `gem-${projectName}-${sessionFile.replace('.jsonl', '')}`,
        workspace: projectName,
        projectName,
        providerId: this.id,
      });
    });
  }

  parseLine(line: string, sessionId: string, _workspace: string, _state?: SessionParserState): TrackerEvent | null {
    let raw: GeminiLine;
    try {
      raw = JSON.parse(line);
    } catch {
      return null;
    }

    const timestamp = raw.timestamp || new Date().toISOString();

    // Gemini uses functionCall in parts
    if (raw.parts) {
      for (const part of raw.parts) {
        if (part.functionCall) {
          return this.parseToolCall(part.functionCall.name, part.functionCall.args || {}, sessionId, timestamp, line);
        }
        // User text
        if (part.text && raw.role === 'user') {
          return {
            session_id: sessionId,
            timestamp,
            agent_id: 'user',
            parent_agent_id: null,
            event_type: 'user_message',
            tool_name: null,
            risk_level: 'info',
            summary: `User: "${part.text.substring(0, 200)}"`,
            file_paths: [],
            command: null,
            parameters: null,
            duration_ms: null,
            raw_log: line.substring(0, 50000),
            source_tool: 'gemini-cli',
          };
        }
      }
    }

    // Alternative format: direct toolCall field
    if (raw.toolCall) {
      return this.parseToolCall(raw.toolCall.name, raw.toolCall.args || {}, sessionId, timestamp, line);
    }

    return null;
  }

  private parseToolCall(name: string, args: Record<string, unknown>, sessionId: string, timestamp: string, rawLine: string): TrackerEvent {
    let eventType: EventType = GEMINI_TOOL_MAP[name] || 'tool_call';
    const filePaths: string[] = [];
    let command: string | null = null;

    if (typeof args.file_path === 'string') filePaths.push(args.file_path);
    if (typeof args.path === 'string') filePaths.push(args.path);

    if (name === 'shell' && typeof args.command === 'string') {
      command = args.command;
      if (/\bgit\s+push\b/.test(command)) eventType = 'git_push';
      else if (/\bgit\s+commit\b/.test(command)) eventType = 'git_commit';
      else if (/\bgit\s+reset\b/.test(command)) eventType = 'git_reset';
      else if (/\bgit\s+/.test(command)) eventType = 'git_operation';
    }

    const summary = `${name}: ${command || JSON.stringify(args).substring(0, 80)}`;

    return {
      session_id: sessionId,
      timestamp,
      agent_id: 'main',
      parent_agent_id: null,
      event_type: eventType,
      tool_name: name,
      risk_level: 'info',
      summary,
      file_paths: [...new Set(filePaths)],
      command,
      parameters: args,
      duration_ms: null,
      raw_log: rawLine.substring(0, 2000),
      source_tool: 'gemini-cli',
    };
  }
}
