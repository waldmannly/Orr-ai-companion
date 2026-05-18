import * as vscode from 'vscode';
import * as http from 'http';
import * as path from 'path';
import { ChildProcess, spawn } from 'child_process';

// ── Types ──

interface SessionStatus {
  sessionId: string | null;
  provider: string;
  grade: string;
  eventsLastMinute: number;
  dangerCount: number;
  tokenUsage: number;
}

interface FileActivityEntry {
  timestamp: string;
  event_type: string;
  risk_level: string;
  summary: string;
  session_id: string;
  provider: string;
}

interface SessionSummary {
  active: boolean;
  sessionId?: string;
  provider?: string;
  grade?: string;
  dangerCount?: number;
  tokenUsage?: number;
  health?: { grade: string; danger_ratio: number; warn_ratio: number };
  recentViolations?: Array<{ rule: string; severity: string; message: string }>;
}

// ── Globals ──

let statusBarItem: vscode.StatusBarItem;
let pollInterval: ReturnType<typeof setInterval> | undefined;
let serverProcess: ChildProcess | null = null;
let decorationsEnabled = true;
let lastStatus: SessionStatus = { sessionId: null, provider: 'none', grade: 'A', eventsLastMinute: 0, dangerCount: 0, tokenUsage: 0 };

// Decoration types
let dangerDecorationType: vscode.TextEditorDecorationType;
let warnDecorationType: vscode.TextEditorDecorationType;
let safeDecorationType: vscode.TextEditorDecorationType;
let gutterDecorationType: vscode.TextEditorDecorationType;

// Cache of file activity per path
const fileActivityCache = new Map<string, { entries: FileActivityEntry[]; fetched: number }>();

// ── Activation ──

export function activate(context: vscode.ExtensionContext) {
  const config = vscode.workspace.getConfiguration('orr');

  // Create decoration types
  dangerDecorationType = vscode.window.createTextEditorDecorationType({
    backgroundColor: new vscode.ThemeColor('orr.dangerBackground'),
    isWholeLine: true,
    overviewRulerColor: '#ff4444',
    overviewRulerLane: vscode.OverviewRulerLane.Right,
  });
  warnDecorationType = vscode.window.createTextEditorDecorationType({
    backgroundColor: new vscode.ThemeColor('orr.warnBackground'),
    isWholeLine: true,
    overviewRulerColor: '#ffaa00',
    overviewRulerLane: vscode.OverviewRulerLane.Right,
  });
  safeDecorationType = vscode.window.createTextEditorDecorationType({
    backgroundColor: new vscode.ThemeColor('orr.safeBackground'),
    isWholeLine: true,
  });
  gutterDecorationType = vscode.window.createTextEditorDecorationType({
    gutterIconPath: context.asAbsolutePath('icons/ai-gutter.svg'),
    gutterIconSize: '80%',
  });

  // Create status bar item
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 50);
  statusBarItem.command = 'orr.showSessionActivity';
  statusBarItem.tooltip = 'Orr — Click for session details';
  updateStatusBar({ sessionId: null, provider: 'none', grade: 'A', eventsLastMinute: 0, dangerCount: 0, tokenUsage: 0 });
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Auto-start server if configured
  if (config.get<boolean>('autoStart')) {
    tryAutoStartServer(context);
  }

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand('orr.showDashboard', () => openDashboard()),
    vscode.commands.registerCommand('orr.showSessionActivity', () => showSessionPanel(context)),
    vscode.commands.registerCommand('orr.showFileActivity', () => showFileActivityForCurrentFile(context)),
    vscode.commands.registerCommand('orr.pauseSession', () => pauseCurrentSession()),
    vscode.commands.registerCommand('orr.toggleDecorations', () => {
      decorationsEnabled = !decorationsEnabled;
      if (!decorationsEnabled) clearAllDecorations();
      else refreshDecorations();
      vscode.window.showInformationMessage(`Orr decorations ${decorationsEnabled ? 'enabled' : 'disabled'}`);
    }),
    vscode.commands.registerCommand('orr.jumpToAgent', () => {
      // Focus this VS Code window and show warning about risky action
      vscode.commands.executeCommand('workbench.action.focusActiveEditorGroup');
      vscode.commands.executeCommand('workbench.panel.chat.view.copilot.focus');
      vscode.window.showWarningMessage('⚠️ Orr detected a risky action! Review the agent output.');
    }),
  );

  // Start polling
  const interval = config.get<number>('pollingInterval') || 3000;
  pollInterval = setInterval(() => pollStatus(), interval);
  pollStatus(); // immediate first poll

  // Refresh decorations when editor changes
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(() => {
      if (decorationsEnabled) refreshDecorations();
    }),
    vscode.workspace.onDidSaveTextDocument(() => {
      // Invalidate cache on save
      const editor = vscode.window.activeTextEditor;
      if (editor) fileActivityCache.delete(normalPath(editor.document.uri.fsPath));
    }),
  );
}

export function deactivate() {
  if (pollInterval) clearInterval(pollInterval);
  if (serverProcess) {
    serverProcess.kill();
    serverProcess = null;
  }
}

// ── Server Auto-Start ──

async function tryAutoStartServer(context: vscode.ExtensionContext) {
  // Check if server is already running
  try {
    await apiGet('/api/ide/status');
    return; // Already running
  } catch {
    // Not running, start it
  }

  const trackerPath = findTrackerBinary();
  if (!trackerPath) {
    // Can't find the binary, just show status as disconnected
    return;
  }

  try {
    serverProcess = spawn('node', [trackerPath], {
      cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || process.cwd(),
      stdio: 'ignore',
      detached: true,
    });
    serverProcess.unref();

    // Wait a moment for startup
    await new Promise(r => setTimeout(r, 2000));
  } catch {
    // Server start failed silently
  }
}

function findTrackerBinary(): string | null {
  // Check common locations
  const candidates = [
    path.join(__dirname, '..', '..', '..', 'dist', 'index.js'),  // monorepo
    path.join(__dirname, '..', '..', 'dist', 'index.js'),         // sibling
  ];

  // Check if orr is globally installed
  try {
    const { execSync } = require('child_process');
    const globalPath = execSync('npm root -g', { encoding: 'utf-8' }).trim();
    candidates.push(path.join(globalPath, 'orr-ai-companion', 'dist', 'index.js'));
  } catch { /* ignore */ }

  for (const c of candidates) {
    try {
      require('fs').accessSync(c);
      return c;
    } catch { /* not found */ }
  }
  return null;
}

// ── Status Bar ──

async function pollStatus() {
  try {
    const status = await apiGet<SessionStatus>('/api/ide/status');
    lastStatus = status;
    updateStatusBar(status);
    if (decorationsEnabled) refreshDecorations();
  } catch {
    updateStatusBar(null);
  }
}

function updateStatusBar(status: SessionStatus | null) {
  if (!status || !status.sessionId) {
    statusBarItem.text = '$(circle-slash) Orr';
    statusBarItem.backgroundColor = undefined;
    statusBarItem.tooltip = 'Orr — No active session (server may be offline)';
    return;
  }

  const gradeIcons: Record<string, string> = {
    A: '$(pass-filled)', B: '$(pass)', C: '$(warning)',
    D: '$(warning)', F: '$(error)',
  };
  const gradeColors: Record<string, vscode.ThemeColor | undefined> = {
    A: undefined, B: undefined,
    C: new vscode.ThemeColor('statusBarItem.warningBackground'),
    D: new vscode.ThemeColor('statusBarItem.warningBackground'),
    F: new vscode.ThemeColor('statusBarItem.errorBackground'),
  };

  const icon = gradeIcons[status.grade] || '$(circle-filled)';
  statusBarItem.text = `${icon} ${status.grade} · ${status.provider}`;
  statusBarItem.backgroundColor = gradeColors[status.grade];
  statusBarItem.tooltip = [
    `Orr — Grade: ${status.grade}`,
    `Provider: ${status.provider}`,
    `Events/min: ${status.eventsLastMinute}`,
    `Danger events: ${status.dangerCount}`,
    `Tokens: ${status.tokenUsage.toLocaleString()}`,
    '',
    'Click for session details',
  ].join('\n');
}

// ── Inline Decorations ──

async function refreshDecorations() {
  const editor = vscode.window.activeTextEditor;
  if (!editor || !lastStatus.sessionId) return;

  const config = vscode.workspace.getConfiguration('orr');
  if (!config.get<boolean>('showDecorations')) return;

  const filePath = normalPath(editor.document.uri.fsPath);

  // Check cache (refresh every 10s)
  const cached = fileActivityCache.get(filePath);
  const now = Date.now();
  let entries: FileActivityEntry[];

  if (cached && now - cached.fetched < 10000) {
    entries = cached.entries;
  } else {
    try {
      entries = await apiGet<FileActivityEntry[]>(`/api/ide/file-activity?path=${encodeURIComponent(filePath)}&limit=20`);
      fileActivityCache.set(filePath, { entries, fetched: now });
    } catch {
      return;
    }
  }

  if (!entries.length) {
    editor.setDecorations(dangerDecorationType, []);
    editor.setDecorations(warnDecorationType, []);
    editor.setDecorations(safeDecorationType, []);
    editor.setDecorations(gutterDecorationType, []);
    return;
  }

  // Find the highest risk level for this file
  const maxRisk = entries.reduce((max, e) => {
    const order = ['info', 'watch', 'warn', 'danger'];
    return order.indexOf(e.risk_level) > order.indexOf(max) ? e.risk_level : max;
  }, 'info');

  // Show a single-line decoration at the top of the file with a summary
  const recent = entries[0];
  const timeAgo = formatTimeAgo(recent.timestamp);
  const hoverMsg = new vscode.MarkdownString();
  hoverMsg.isTrusted = true;
  hoverMsg.appendMarkdown(`### 🤖 AI Activity on This File\n\n`);
  for (const e of entries.slice(0, 5)) {
    const riskIcon = e.risk_level === 'danger' ? '🔴' : e.risk_level === 'warn' ? '🟡' : '🟢';
    hoverMsg.appendMarkdown(`${riskIcon} **${e.event_type}** — ${e.summary || 'No details'} *(${formatTimeAgo(e.timestamp)})*\n\n`);
  }
  if (entries.length > 5) {
    hoverMsg.appendMarkdown(`*... and ${entries.length - 5} more events*\n\n`);
  }
  hoverMsg.appendMarkdown(`[Open Full Activity](command:orr.showFileActivity)`);

  const topLineRange = new vscode.Range(0, 0, 0, 0);
  const decoration: vscode.DecorationOptions = {
    range: topLineRange,
    hoverMessage: hoverMsg,
    renderOptions: {
      after: {
        contentText: ` ⟨ AI: ${entries.length} events, last ${timeAgo} — ${recent.provider} ⟩`,
        color: maxRisk === 'danger' ? '#ff6b6b' : maxRisk === 'warn' ? '#ffa94d' : '#69db7c',
        fontStyle: 'italic',
        fontSize: '0.85em',
      },
    },
  };

  // Apply based on risk level
  if (maxRisk === 'danger') {
    editor.setDecorations(dangerDecorationType, [decoration]);
    editor.setDecorations(warnDecorationType, []);
    editor.setDecorations(safeDecorationType, []);
  } else if (maxRisk === 'warn') {
    editor.setDecorations(dangerDecorationType, []);
    editor.setDecorations(warnDecorationType, [decoration]);
    editor.setDecorations(safeDecorationType, []);
  } else {
    editor.setDecorations(dangerDecorationType, []);
    editor.setDecorations(warnDecorationType, []);
    editor.setDecorations(safeDecorationType, [decoration]);
  }

  // Gutter icons if enabled
  if (config.get<boolean>('showGutterIcons') && entries.some(e => e.event_type === 'file_write' || e.event_type === 'file_create')) {
    editor.setDecorations(gutterDecorationType, [{ range: topLineRange }]);
  } else {
    editor.setDecorations(gutterDecorationType, []);
  }
}

function clearAllDecorations() {
  for (const editor of vscode.window.visibleTextEditors) {
    editor.setDecorations(dangerDecorationType, []);
    editor.setDecorations(warnDecorationType, []);
    editor.setDecorations(safeDecorationType, []);
    editor.setDecorations(gutterDecorationType, []);
  }
}

// ── Webview Panels ──

function openDashboard() {
  const config = vscode.workspace.getConfiguration('orr');
  const url = config.get<string>('serverUrl') || 'http://127.0.0.1:3847';
  vscode.env.openExternal(vscode.Uri.parse(url));
}

async function showSessionPanel(context: vscode.ExtensionContext) {
  const panel = vscode.window.createWebviewPanel(
    'orrSession', 'Orr — Session', vscode.ViewColumn.Beside,
    { enableScripts: true, retainContextWhenHidden: false },
  );

  try {
    const summary = await apiGet<SessionSummary>('/api/ide/session-summary');
    panel.webview.html = buildSessionHtml(summary);
  } catch {
    panel.webview.html = buildErrorHtml('Cannot connect to Orr server. Is it running?');
  }

  // Auto-refresh every 5s
  const refresher = setInterval(async () => {
    try {
      const summary = await apiGet<SessionSummary>('/api/ide/session-summary');
      panel.webview.html = buildSessionHtml(summary);
    } catch { /* ignore */ }
  }, 5000);

  panel.onDidDispose(() => clearInterval(refresher));
}

async function showFileActivityForCurrentFile(context: vscode.ExtensionContext) {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage('No file is currently open');
    return;
  }

  const filePath = normalPath(editor.document.uri.fsPath);
  const panel = vscode.window.createWebviewPanel(
    'orrFile', `Orr — ${path.basename(filePath)}`, vscode.ViewColumn.Beside,
    { enableScripts: true },
  );

  try {
    const entries = await apiGet<FileActivityEntry[]>(`/api/ide/file-activity?path=${encodeURIComponent(filePath)}&limit=100`);
    panel.webview.html = buildFileActivityHtml(filePath, entries);
  } catch {
    panel.webview.html = buildErrorHtml('Cannot connect to Orr server.');
  }
}

async function pauseCurrentSession() {
  if (!lastStatus.sessionId) {
    vscode.window.showWarningMessage('No active session to pause');
    return;
  }

  try {
    await apiPost(`/api/response/pause/${lastStatus.sessionId}`, { reason: 'Paused from VS Code' });
    vscode.window.showInformationMessage(`Session paused: ${lastStatus.sessionId.slice(0, 8)}...`);
  } catch {
    vscode.window.showErrorMessage('Failed to pause session. Is auto-response enabled?');
  }
}

// ── HTML Builders ──

function buildSessionHtml(summary: SessionSummary): string {
  if (!summary.active) {
    return wrapHtml('No Active Session', '<div class="empty">No AI agent session is currently active.</div>');
  }

  const gradeColor = summary.grade === 'A' ? '#69db7c' : summary.grade === 'B' ? '#69db7c'
    : summary.grade === 'C' ? '#ffa94d' : summary.grade === 'D' ? '#ffa94d' : '#ff6b6b';

  let violations = '';
  if (summary.recentViolations?.length) {
    violations = '<h3>⚠️ Recent Guardrail Violations</h3><div class="violations">';
    for (const v of summary.recentViolations) {
      const sColor = v.severity === 'danger' ? '#ff6b6b' : v.severity === 'warn' ? '#ffa94d' : '#aaa';
      violations += `<div class="violation"><span style="color:${sColor};font-weight:600;">[${v.severity}]</span> ${escHtml(v.rule)} — ${escHtml(v.message)}</div>`;
    }
    violations += '</div>';
  }

  return wrapHtml('Current Session', `
    <div class="grade-circle" style="border-color:${gradeColor};color:${gradeColor};">${summary.grade}</div>
    <div class="stats">
      <div class="stat"><span class="stat-label">Provider</span><span class="stat-value">${escHtml(summary.provider || '')}</span></div>
      <div class="stat"><span class="stat-label">Session</span><span class="stat-value">${escHtml((summary.sessionId || '').slice(0, 12))}…</span></div>
      <div class="stat"><span class="stat-label">Danger Events</span><span class="stat-value" style="color:#ff6b6b;">${summary.dangerCount || 0}</span></div>
      <div class="stat"><span class="stat-label">Token Usage</span><span class="stat-value">${(summary.tokenUsage || 0).toLocaleString()}</span></div>
    </div>
    ${violations}
    <button onclick="document.querySelector('.loading').style.display='block';" style="margin-top:16px;padding:8px 16px;background:#339af0;color:#fff;border:none;border-radius:6px;cursor:pointer;">Open Full Dashboard</button>
  `);
}

function buildFileActivityHtml(filePath: string, entries: FileActivityEntry[]): string {
  if (!entries.length) {
    return wrapHtml('File Activity', `<div class="empty">No AI activity recorded for <code>${escHtml(path.basename(filePath))}</code></div>`);
  }

  let rows = '';
  for (const e of entries) {
    const riskColor = e.risk_level === 'danger' ? '#ff6b6b' : e.risk_level === 'warn' ? '#ffa94d' : '#69db7c';
    rows += `<tr>
      <td style="color:${riskColor};">${escHtml(e.risk_level)}</td>
      <td>${escHtml(e.event_type)}</td>
      <td>${escHtml(e.summary || '')}</td>
      <td>${escHtml(e.provider)}</td>
      <td>${formatTimeAgo(e.timestamp)}</td>
    </tr>`;
  }

  return wrapHtml(`AI Activity — ${path.basename(filePath)}`, `
    <p style="color:#aaa;margin-bottom:12px;">${entries.length} events recorded for this file</p>
    <table>
      <thead><tr><th>Risk</th><th>Type</th><th>Summary</th><th>Provider</th><th>When</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `);
}

function buildErrorHtml(message: string): string {
  return wrapHtml('Connection Error', `
    <div class="empty" style="color:#ff6b6b;">
      <p>${escHtml(message)}</p>
      <p style="margin-top:12px;color:#aaa;">Make sure the tracker is running: <code>npm start</code> in the tracker directory.</p>
    </div>
  `);
}

function wrapHtml(title: string, body: string): string {
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #1a1b26; color: #c0caf5; padding: 16px; margin: 0; }
  h2 { margin: 0 0 16px; font-size: 1.2rem; }
  h3 { margin: 16px 0 8px; font-size: 1rem; }
  .grade-circle { width: 64px; height: 64px; border-radius: 50%; border: 3px solid; display: flex; align-items: center; justify-content: center; font-size: 2rem; font-weight: 700; margin: 0 auto 16px; }
  .stats { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  .stat { background: #24283b; border-radius: 8px; padding: 10px; }
  .stat-label { display: block; font-size: 0.75rem; color: #565f89; margin-bottom: 4px; }
  .stat-value { font-size: 1.1rem; font-weight: 600; }
  .empty { text-align: center; padding: 32px; color: #565f89; }
  .violations { margin-top: 4px; }
  .violation { padding: 6px 0; border-bottom: 1px solid #24283b; font-size: 0.85rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #24283b; }
  th { color: #565f89; font-weight: 500; }
  code { background: #24283b; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; }
  .loading { display: none; text-align: center; padding: 8px; color: #565f89; }
</style>
</head><body><h2>${escHtml(title)}</h2>${body}<div class="loading">Loading...</div></body></html>`;
}

// ── HTTP Helpers ──

function getServerUrl(): string {
  return vscode.workspace.getConfiguration('orr').get<string>('serverUrl') || 'http://127.0.0.1:3847';
}

function apiGet<T>(path: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, getServerUrl());
    http.get(url, { timeout: 3000 }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error('Invalid JSON')); }
      });
    }).on('error', reject);
  });
}

function apiPost(path: string, body: Record<string, unknown>): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, getServerUrl());
    const postData = JSON.stringify(body);
    const req = http.request(url, {
      method: 'POST', timeout: 3000,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(postData) },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error('Invalid JSON')); }
      });
    });
    req.on('error', reject);
    req.write(postData);
    req.end();
  });
}

// ── Utility ──

function normalPath(p: string): string {
  return p.replace(/\\/g, '/');
}

function formatTimeAgo(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime();
  if (diff < 60000) return `${Math.round(diff / 1000)}s ago`;
  if (diff < 3600000) return `${Math.round(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.round(diff / 3600000)}h ago`;
  return `${Math.round(diff / 86400000)}d ago`;
}

function escHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
