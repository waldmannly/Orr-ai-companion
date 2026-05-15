import * as fs from 'fs';
import { TrackerEvent } from '../parser/event-types';
import { SessionParserState } from '../parser';

/**
 * A transcript file discovered by a provider.
 */
export interface TranscriptFile {
  filePath: string;
  sessionId: string;
  workspace: string;
  projectName: string;
  /** Which provider discovered this file */
  providerId: string;
}

/**
 * Interface that every AI tool provider must implement.
 * Each provider knows how to discover, watch, and parse logs for one tool.
 */
export interface LogProvider {
  /** Unique identifier, e.g. 'vscode-copilot', 'claude-code' */
  id: string;
  /** Display name, e.g. 'VS Code Copilot', 'Claude Code' */
  displayName: string;
  /** Short icon/emoji for dashboard badges */
  icon: string;

  /** Return the default log directories for this tool on the current OS. */
  getDefaultLogPaths(): string[];

  /**
   * Discover existing session/transcript files under the given paths.
   * If paths is empty, uses getDefaultLogPaths().
   */
  discoverSessions(basePaths?: string[]): TranscriptFile[];

  /**
   * Watch for new transcript files appearing under the given path.
   * Returns null if watching is not supported (e.g. server-side tool).
   */
  watchForNewSessions(basePath: string, onNew: (file: TranscriptFile) => void): fs.FSWatcher | null;

  /**
   * Parse one line of a transcript file into a TrackerEvent.
   * Returns null for lines that should be skipped (turn metadata, etc.).
   */
  parseLine(line: string, sessionId: string, workspace: string, state?: SessionParserState): TrackerEvent | null;
}
