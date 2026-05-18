# Blocking Design — How to Actually Stop Agents

> Status: **Design proposal** — not yet implemented

Currently Orr is a passive log tailer. It reads agent transcripts *after* actions execute. This doc outlines what it would take to actually prevent dangerous actions and give users instant access to intervene.

---

## The Problem

```
Agent decides to run `rm -rf /` → Agent executes it → Log is written → Orr reads log → Alert fires
                                   ^^^^^^^^^^^^^^^^^^^^
                                   Too late. Damage done.
```

We need to move our interception point *before* execution.

---

## Strategy 1: Process Suspension (Most Practical, Works Today)

**Concept:** When Orr detects a dangerous action in the log stream, immediately suspend (freeze) the agent's OS process. The action that triggered the alert already ran, but all *subsequent* actions are frozen until the user decides.

**How it works:**
1. Orr detects violation in log stream (same as today)
2. Orr finds the agent's PID (see "Process Discovery" below)
3. Orr sends `SIGSTOP` (Unix) or `NtSuspendProcess` (Windows) to freeze the agent
4. Desktop notification fires: "⚠️ RISKY ACTION — Agent frozen. Resume or Kill?"
5. User clicks Resume → `SIGCONT` / `NtResumeProcess`
6. User clicks Kill → `SIGKILL` / `TerminateProcess`

**Process Discovery:**
- **VS Code Copilot:** Find the VS Code process that owns the workspace. The Copilot extension runs in the VS Code renderer process. Suspending VS Code freezes everything (too aggressive) — better to use the extension approach (Strategy 3).
- **Claude Code:** It's a Node.js process in a terminal. Find it via: `ps aux | grep claude` or track the PID when we see the session start in the log.
- **Gemini CLI:** Same as Claude — it's a process in a terminal.

**Limitations:**
- The triggering action already executed (1 bad action gets through)
- Suspending VS Code is too heavy-handed for Copilot
- Works great for terminal-based agents (Claude Code, Gemini CLI)

**Implementation effort:** ~2-3 days. Mostly PID tracking + platform-specific suspend/resume.

---

## Strategy 2: Terminal PTY Proxy (True Pre-Execution Blocking)

**Concept:** Instead of running `claude` directly, users run `orr wrap claude`. Orr spawns the agent inside a PTY proxy that intercepts all tool calls before they execute.

**How it works:**
```
User runs:  orr wrap claude
Orr spawns: PTY proxy → claude process

Agent wants to run `rm -rf /`:
  claude writes tool call to PTY → Orr intercepts → pattern matches "rm -rf" →
  Orr holds the output → shows intervention UI → user denies → Orr sends
  error response back to agent ("permission denied")
```

**For Claude Code specifically:**
Claude Code writes tool calls as structured JSON before executing them. The PTY proxy can:
1. Buffer the JSON tool call
2. Check against guardrail rules
3. If safe → pass through
4. If dangerous → respond with a synthetic error ("Tool execution denied by policy")

**For Gemini CLI:** Same approach — structured tool calls in the stream.

**Limitations:**
- Doesn't work for VS Code Copilot (different architecture)
- User must remember to use `orr wrap` instead of running agents directly
- Slight latency on every tool call (guardrail check)

**Implementation effort:** ~1-2 weeks. PTY proxy, stream parsing, synthetic error injection.

---

## Strategy 3: VS Code Extension Enhancement (For Copilot)

**Concept:** Orr already has a `vscode-extension/` directory. Enhance it to hook into VS Code's command execution pipeline.

**How it works:**
1. Extension registers `onWillExecuteCommand` handlers
2. Before Copilot executes a terminal command or file write, the extension checks Orr's guardrail rules
3. If dangerous → extension shows a modal: "Copilot wants to run `rm -rf /`. Allow?"
4. User approves → execution proceeds
5. User denies → extension cancels the command, Copilot sees a failure

**VS Code API hooks available:**
- `workspace.onWillCreateFiles` / `onWillDeleteFiles` / `onWillRenameFiles` — intercept file operations
- `window.onDidOpenTerminal` + terminal `sendText` wrapping — intercept terminal commands
- `tasks.onDidStartTask` — intercept task execution

**Limitations:**
- Only works for VS Code Copilot (not Claude Code/Gemini CLI)
- VS Code API may not expose all Copilot internals
- Extension must run in same VS Code instance

**Implementation effort:** ~1 week. Extension API hooks, rule evaluation, modal UI.

---

## Strategy 4: MCP Gatekeeper (Future-Proof)

**Concept:** If agents use MCP (Model Context Protocol) servers for tool access, Orr can sit as a transparent MCP proxy that gates tool calls.

**How it works:**
```
Agent → Orr MCP Proxy → Real MCP Server
                ↓
        Guardrail check
        If blocked → return error to agent
        If allowed → forward to real server
```

**This is the cleanest architecture** but requires:
- Agents to use MCP (increasingly common)
- Configuration to route through Orr's proxy
- Support for the MCP transport protocol

**Implementation effort:** ~1-2 weeks once MCP is standard.

---

## "Jump to Session" Button — Immediate Manual Intervention

Regardless of which blocking strategy we implement, users need a way to **immediately jump to the running agent** to stop it manually. This is the fastest thing we can ship.

### What It Does

When a risky action fires:
1. Desktop notification appears with a **"Jump to Agent"** button
2. Clicking it instantly focuses the window/terminal where the agent is running
3. User can hit Ctrl+C, close the terminal, or stop the agent themselves

### Implementation

**For VS Code Copilot sessions:**
```typescript
// In the VS Code extension:
vscode.commands.registerCommand('orr.jumpToSession', (sessionId) => {
  // Focus the VS Code window for this workspace
  vscode.commands.executeCommand('workbench.action.focusActiveEditorGroup');
  // Open the Copilot chat panel
  vscode.commands.executeCommand('workbench.panel.chat.view.copilot.focus');
  // Show inline warning
  vscode.window.showWarningMessage('⚠️ Risky action detected! Review the agent output.');
});
```

**For terminal agents (Claude Code, Gemini CLI):**
```typescript
// Find the terminal window and bring it to foreground
import { exec } from 'child_process';

function jumpToTerminalAgent(sessionId: string, pid?: number) {
  if (process.platform === 'win32') {
    // Windows: Use PowerShell to activate the window containing the process
    exec(`powershell -c "(Get-Process -Id ${pid}).MainWindowHandle | ForEach-Object { [Win32]::SetForegroundWindow($_) }"`);
  } else if (process.platform === 'darwin') {
    // macOS: Activate Terminal.app or iTerm
    exec(`osascript -e 'tell application "Terminal" to activate'`);
  } else {
    // Linux: Use wmctrl or xdotool
    exec(`wmctrl -ia $(xdotool search --pid ${pid} | head -1)`);
  }
}
```

**In the Dashboard (always available):**
- Add a "🔴 LIVE — Jump to Agent" button on the session timeline header
- For VS Code sessions: opens `vscode://` URI that focuses the workspace
- For terminal sessions: shows the terminal command + PID so user can find it

### Dashboard Notification Enhancement

Current flow:
```
Alert fires → Toast appears → User reads it → ??? 
```

New flow:
```
Alert fires → Notification with "Jump" button → User clicks → 
  Agent's window/terminal focused → User hits Ctrl+C
```

The desktop notification (already implemented) would gain an action button:
```typescript
const notification = new Notification('⚠️ Risky Action Detected', {
  body: 'Claude Code is running: rm -rf node_modules/',
  requireInteraction: true,  // Don't auto-dismiss
  actions: [
    { action: 'jump', title: '🚨 Jump to Agent' },
    { action: 'dismiss', title: 'Dismiss' }
  ]
});

notification.onclick = () => {
  jumpToTerminalAgent(sessionId, pid);
};
```

---

## Recommended Implementation Order

| Phase | What | Effort | Impact |
|-------|------|--------|--------|
| **1** | "Jump to Agent" button (notifications + dashboard) | 2-3 days | Immediate — users can manually stop agents in <2 seconds |
| **2** | Process suspension for terminal agents | 2-3 days | Freezes Claude/Gemini after first bad action |
| **3** | VS Code extension hooks for Copilot | 1 week | True pre-execution blocking for Copilot |
| **4** | `orr wrap` PTY proxy for terminal agents | 1-2 weeks | True pre-execution blocking for Claude/Gemini |
| **5** | MCP gatekeeper proxy | 1-2 weeks | Future-proof blocking for any MCP agent |

---

## What We Need to Track (New Data)

To enable any of these, Orr needs to know:
- **PID** of the running agent process (for suspend/kill)
- **Window handle** or terminal ID (for jump-to-session)
- **Workspace path** (for VS Code URI deep links — already have this)
- **Agent transport type** (terminal vs extension vs MCP)

These can be discovered during session start and stored alongside the session record.

---

## Summary

The "Jump to Agent" button is the quickest win — ship it as Phase 1 and it immediately makes the alerting system actionable. Users go from "I got a notification but the agent already finished" to "I got a notification, clicked Jump, and hit Ctrl+C in 2 seconds."

True blocking requires either:
- A proxy layer (PTY proxy or MCP gatekeeper) for pre-execution interception
- OS-level process control (suspend/resume) for post-first-action freezing
- VS Code extension hooks for Copilot-specific interception

All approaches are feasible. The code infrastructure (intervention panel, command queue, approve/deny flow) is already built — it just needs a real enforcement backend behind it.
