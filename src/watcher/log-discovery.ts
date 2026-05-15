import * as fs from 'fs';
import * as path from 'path';

export interface TranscriptFile {
  filePath: string;
  sessionId: string;
  workspace: string;
  projectName: string;
}

// VS Code stores transcript JSONL files under:
// <workspaceStorage>/<hash>/GitHub.copilot-chat/transcripts/<sessionId>.jsonl

const COPILOT_CHAT_DIR = 'GitHub.copilot-chat';
const TRANSCRIPTS_DIR = 'transcripts';

export function discoverTranscripts(watchPaths: string[]): TranscriptFile[] {
  const defaultBase = getDefaultWorkspaceStoragePath();
  const searchPaths = watchPaths.length > 0 ? watchPaths : (defaultBase ? [defaultBase] : []);

  const results: TranscriptFile[] = [];

  for (const base of searchPaths) {
    if (!fs.existsSync(base)) continue;

    // Each subdirectory is a workspace hash
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
        const sessionId = file.name.replace('.jsonl', '');
        results.push({
          filePath: path.join(transcriptDir, file.name),
          sessionId,
          workspace,
          projectName,
        });
      }
    }
  }

  return results;
}

export function getDefaultWorkspaceStoragePath(): string | null {
  const home = process.env.USERPROFILE || process.env.HOME || '';
  const candidates = [
    path.join(home, 'AppData', 'Roaming', 'Code', 'User', 'workspaceStorage'), // Windows
    path.join(home, '.config', 'Code', 'User', 'workspaceStorage'),             // Linux
    path.join(home, 'Library', 'Application Support', 'Code', 'User', 'workspaceStorage'), // macOS
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return null;
}

function resolveProjectName(workspaceDir: string): string {
  // Try to read workspace.json for the folder name
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

export function watchForNewTranscripts(basePath: string, onNew: (file: TranscriptFile) => void): fs.FSWatcher {
  return fs.watch(basePath, { recursive: true }, (eventType, filename) => {
    if (!filename || !filename.endsWith('.jsonl') || !filename.includes(TRANSCRIPTS_DIR)) return;
    const fullPath = path.join(basePath, filename);
    if (!fs.existsSync(fullPath)) return;

    // Extract parts
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
    });
  });
}
