import * as fs from 'fs';
import * as path from 'path';
import { LogProvider, TranscriptFile } from './types';
import { TrackerEvent } from '../parser/event-types';
import { parseTranscriptLine, SessionParserState } from '../parser';

const COPILOT_CHAT_DIR = 'GitHub.copilot-chat';
const TRANSCRIPTS_DIR = 'transcripts';

export class VSCodeCopilotProvider implements LogProvider {
  id = 'vscode-copilot';
  displayName = 'VS Code Copilot';
  icon = '🟦';

  getDefaultLogPaths(): string[] {
    const home = process.env.USERPROFILE || process.env.HOME || '';
    const candidates = [
      path.join(home, 'AppData', 'Roaming', 'Code', 'User', 'workspaceStorage'),
      path.join(home, '.config', 'Code', 'User', 'workspaceStorage'),
      path.join(home, 'Library', 'Application Support', 'Code', 'User', 'workspaceStorage'),
    ];
    return candidates.filter(c => fs.existsSync(c));
  }

  discoverSessions(basePaths?: string[]): TranscriptFile[] {
    const paths = basePaths?.length ? basePaths : this.getDefaultLogPaths();
    const results: TranscriptFile[] = [];

    for (const base of paths) {
      if (!fs.existsSync(base)) continue;
      const entries = fs.readdirSync(base, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const transcriptDir = path.join(base, entry.name, COPILOT_CHAT_DIR, TRANSCRIPTS_DIR);
        if (!fs.existsSync(transcriptDir)) continue;

        const workspace = entry.name;
        const projectName = resolveProjectName(path.join(base, entry.name));

        const files = fs.readdirSync(transcriptDir, { withFileTypes: true });
        for (const file of files) {
          if (!file.isFile() || !file.name.endsWith('.jsonl')) continue;
          results.push({
            filePath: path.join(transcriptDir, file.name),
            sessionId: file.name.replace('.jsonl', ''),
            workspace,
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
      if (!filename || !filename.endsWith('.jsonl') || !filename.includes(TRANSCRIPTS_DIR)) return;
      const fullPath = path.join(basePath, filename);
      if (!fs.existsSync(fullPath)) return;

      const parts = filename.split(path.sep);
      const transcriptIdx = parts.indexOf(TRANSCRIPTS_DIR);
      if (transcriptIdx < 0) return;

      const workspace = parts[0] || '';
      const sessionId = parts[transcriptIdx + 1]?.replace('.jsonl', '') || '';
      const wsDir = path.join(basePath, workspace);

      onNew({
        filePath: fullPath,
        sessionId,
        workspace,
        projectName: resolveProjectName(wsDir),
        providerId: this.id,
      });
    });
  }

  parseLine(line: string, sessionId: string, workspace: string, state?: SessionParserState): TrackerEvent | null {
    return parseTranscriptLine(line, sessionId, workspace, state);
  }
}

function resolveProjectName(workspaceDir: string): string {
  const wsFile = path.join(workspaceDir, 'workspace.json');
  if (fs.existsSync(wsFile)) {
    try {
      const data = JSON.parse(fs.readFileSync(wsFile, 'utf-8'));
      if (data.folder) {
        const folder = decodeURIComponent(data.folder.replace(/^file:\/\/\//, ''));
        return path.basename(folder);
      }
    } catch { /* ignore */ }
  }
  return path.basename(workspaceDir);
}
