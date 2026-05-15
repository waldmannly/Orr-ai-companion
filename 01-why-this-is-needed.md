# AI Companion Tracker — Why This Is Needed

## The Problem

AI coding agents running in "YOLO mode" and autopilot previews represent a fundamental shift in how software gets built. The developer is no longer the one typing every command — an autonomous agent is reading files, writing code, spawning subprocesses, making git commits, and accessing system resources on the developer's behalf.

This creates a **visibility gap**:

- **You can't watch everything.** Agents run fast, often in parallel, spawning sub-agents. By the time you scroll back through terminal output, dozens of actions have already happened.
- **You can't easily tell safe from dangerous.** A `rm -rf` buried in a chain of 40 tool calls looks the same as a harmless `mkdir` unless you're actively watching.
- **Memory systems are opaque.** Agent memory (persistent notes, repo-scoped context, session state) is written and read without clear summaries. A poisoned memory entry from a prompt injection attack silently influences every future conversation.
- **Sensitive files may be accessed without your knowledge.** Personal information, credentials, private keys, and other sensitive data can be read by agents as part of normal file exploration — and you'd never know.

## The Threat Model

### 1. Prompt Injection via Tool Outputs
An agent fetches a webpage, reads a README, or processes untrusted input. That content contains hidden instructions that alter the agent's behavior — exfiltrating data, modifying files, or poisoning memory for future sessions.

### 2. Memory Poisoning
An attacker (or a confused agent) writes misleading facts into persistent memory. These entries survive across conversations and workspaces, subtly corrupting future agent behavior. Without a clear audit trail of what was written and when, this is nearly impossible to detect.

### 3. Destructive Commands
Agents may run `git push --force`, `DROP TABLE`, `rm -rf`, or other irreversible operations. In autopilot mode these execute without confirmation unless the agent's own safety checks catch them — and those checks aren't perfect.

### 4. Sensitive Data Exposure
Agents exploring a codebase may read `.env` files, private keys, personal documents, or files containing PII. Even if the agent doesn't exfiltrate this data, it passes through the model's context window, creating a data handling concern.

### 5. Scope Creep & Unintended Changes
An agent asked to "fix the login bug" might refactor three other files, add dependencies, and change configuration — all technically "helpful" but outside what you authorized.

## How This Tool Helps

The AI Companion Tracker provides **passive, non-blocking observability** into everything AI agents do:

| Capability | What It Gives You |
|---|---|
| **Action Log** | A timestamped, structured record of every file read, file write, terminal command, git operation, and tool call |
| **Security Alerts** | Real-time flagging of destructive commands, sensitive file access, and suspicious patterns |
| **Memory Audit** | A human-readable summary of what's being stored in and read from agent memory, across all scopes |
| **Sensitive File Watchlist** | User-defined list of files/patterns that trigger alerts when accessed |
| **Multi-Agent Visibility** | Track parallel agents and sub-agents as separate threads with parent-child relationships |
| **Web Dashboard** | Drill into projects, sessions, agents, and individual actions with filters, search, and charts |
| **Post-Session Review** | After an autopilot run, review everything that happened in a digestible timeline |

## Who This Is For

- **Solo developers using YOLO/autopilot mode** who want confidence that the agent isn't doing anything unexpected.
- **Teams adopting AI agents** that need audit trails and security review of agent activity.
- **Security-conscious users** who want to detect prompt injection, memory poisoning, and data exposure.
- **Anyone who's ever scrolled through agent output and thought "wait, what did it just do?"**

## Design Principles

1. **Zero friction.** The tracker must never slow down the agent or require the developer to change their workflow.
2. **Passive observation.** It watches and records — it does not block, prompt, or modify agent behavior.
3. **Security-first alerting.** Dangerous patterns are flagged automatically, not buried in logs.
4. **Human-readable summaries.** Raw logs are available, but the default view is a clear, scannable summary.
5. **Lightweight.** Minimal resource footprint. No heavy databases. Runs alongside the agent without impact.
