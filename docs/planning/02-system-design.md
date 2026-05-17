# AI Companion Tracker — System Design

## Architecture Overview

The system is designed around one core constraint: **never block or slow down the AI agent**. Every design decision flows from this.

```
┌─────────────────────────────────────────────────────────┐
│                    VS Code / Editor                      │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │  Agent 1  │  │  Agent 2  │  │ Sub-Agent │              │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘              │
│        │               │               │                   │
│        ▼               ▼               ▼                   │
│  ┌──────────────────────────────────────────────┐         │
│  │         Debug Log / Session Log Stream         │         │
│  └──────────────────┬───────────────────────────┘         │
└─────────────────────┼───────────────────────────────────┘
                      │
                      ▼  (tail / file watch)
         ┌────────────────────────────┐
         │    Log Ingestion Service    │
         │  (lightweight local process)│
         └────────────┬───────────────┘
                      │
              ┌───────┴───────┐
              ▼               ▼
    ┌──────────────┐  ┌──────────────┐
    │  SQLite DB    │  │  Alert Engine │
    │  (structured  │  │  (rules +     │
    │   events)     │  │   patterns)   │
    └──────┬───────┘  └──────┬───────┘
           │                  │
           ▼                  ▼
    ┌──────────────────────────────┐
    │       Web Dashboard           │
    │   (local, lightweight UI)     │
    └──────────────────────────────┘
```

## Core Design: Passive Log Tailing

The tracker does **not** hook into the agent, modify its behavior, or sit in its execution path. Instead:

1. **VS Code's Copilot extension already writes debug logs** for every agent session to a known location (`workspaceStorage/.../debug-logs/`).
2. The tracker **tails these log files** in real-time using file system watchers.
3. Parsed events are written to a **local SQLite database** for querying, filtering, and dashboard rendering.

This means:
- **Zero overhead on the agent.** The agent doesn't know the tracker exists.
- **No extension APIs required.** We read files that already exist.
- **Works with any agent mode** — YOLO, autopilot, manual, sub-agents, all of it.

## Key Components

### 1. Log Watcher

A lightweight Node.js process that:
- Watches the VS Code debug log directories for new session files
- Tails active session logs in real-time using `fs.watch` + polling fallback
- Detects new sessions, agent spawns, and session completions

**Performance target:** < 5MB memory, < 1% CPU during active monitoring.

### 2. Log Parser

Parses the raw debug log stream into structured events:

```
┌─────────────────────────────────────────┐
│              Raw Log Line                │
└──────────────────┬──────────────────────┘
                   ▼
         ┌─────────────────┐
         │   Line Classifier │
         │   (regex + JSON)  │
         └────────┬──────────┘
                  ▼
    ┌─────────────────────────┐
    │    Structured Event      │
    │  {                       │
    │    timestamp,            │
    │    session_id,           │
    │    agent_id,             │
    │    event_type,           │
    │    tool_name,            │
    │    parameters,           │
    │    file_paths,           │
    │    command,              │
    │    risk_level,           │
    │    ...                   │
    │  }                       │
    └─────────────────────────┘
```

Event types captured:
- `file_read` — agent reads a file
- `file_write` — agent creates or edits a file
- `file_delete` — agent deletes a file
- `terminal_command` — agent runs a shell command
- `git_operation` — commit, push, reset, checkout, etc.
- `memory_read` — agent reads from memory store
- `memory_write` — agent writes to memory store
- `memory_delete` — agent deletes memory entries
- `web_fetch` — agent fetches a URL
- `tool_call` — any tool invocation (parent category)
- `subagent_spawn` — a new sub-agent is created
- `search` — file search, grep, semantic search

### 3. Risk Classifier

Every event passes through a risk classification engine that assigns a risk level:

| Level | Meaning | Examples |
|---|---|---|
| **info** | Normal, expected activity | File reads, searches, benign tool calls |
| **watch** | Worth noting but not alarming | File writes, git commits, memory reads |
| **warn** | Potentially concerning | Accessing `.env` files, writing to memory, running install commands |
| **danger** | Destructive or security-relevant | `rm -rf`, `git push --force`, `DROP TABLE`, accessing sensitive files, memory writes with suspicious content |

Risk classification uses:
- **Static rules** — pattern matching on commands, file paths, tool names
- **User-defined sensitive file list** — any file matching user-specified patterns triggers elevated risk
- **Memory operation analysis** — memory writes are parsed and summarized; content is checked for suspicious patterns (e.g., instructions that look like prompt injections)

### 4. SQLite Storage

All structured events go into a local SQLite database. SQLite was chosen because:
- Zero configuration, single file
- Fast enough for this workload (thousands of events per session, not millions)
- Supports the queries needed for dashboards (time ranges, filters, aggregations)
- Portable — easy to back up or move

**Schema overview:**

```sql
sessions (
    id TEXT PRIMARY KEY,
    workspace TEXT,
    project_name TEXT,
    started_at DATETIME,
    ended_at DATETIME,
    total_events INTEGER,
    danger_count INTEGER,
    warn_count INTEGER
)

events (
    id INTEGER PRIMARY KEY,
    session_id TEXT,
    timestamp DATETIME,
    agent_id TEXT,
    parent_agent_id TEXT,
    event_type TEXT,
    tool_name TEXT,
    risk_level TEXT,
    summary TEXT,
    file_paths TEXT,       -- JSON array
    command TEXT,
    parameters TEXT,       -- JSON blob
    raw_log TEXT
)

memory_operations (
    id INTEGER PRIMARY KEY,
    event_id INTEGER,
    session_id TEXT,
    timestamp DATETIME,
    operation TEXT,         -- read / write / delete
    memory_scope TEXT,      -- user / session / repo
    memory_path TEXT,
    content_summary TEXT,
    risk_level TEXT
)

sensitive_file_access (
    id INTEGER PRIMARY KEY,
    event_id INTEGER,
    session_id TEXT,
    timestamp DATETIME,
    file_path TEXT,
    access_type TEXT,       -- read / write / delete
    matched_rule TEXT
)

alerts (
    id INTEGER PRIMARY KEY,
    event_id INTEGER,
    session_id TEXT,
    timestamp DATETIME,
    alert_type TEXT,
    severity TEXT,
    message TEXT,
    acknowledged INTEGER DEFAULT 0
)
```

### 5. Alert Engine

Runs in-process with the log watcher. Evaluates each event against:

1. **Built-in rules** (destructive commands, force pushes, sensitive file patterns)
2. **User-defined rules** (custom file watchlist, custom command blocklist)
3. **Memory poisoning heuristics** (memory writes containing instruction-like content, unusual memory access patterns)

Alerts are stored in the database and surfaced in the dashboard. Optionally, desktop notifications can be sent for `danger`-level alerts.

### 6. Web Dashboard

A lightweight local web server (Express or similar) serving a single-page app:

- **Runs on `localhost` only** — no external access
- **No authentication required** — it's local-only and read-only
- **Minimal dependencies** — vanilla JS or lightweight framework (Preact/Alpine)
- **Phone-sized viewport** — designed to feel like a companion app, not a sprawling analytics platform

## Data Flow Summary

```
Agent does work
       │
       ▼
Debug logs written to disk (already happens)
       │
       ▼
Log Watcher detects new content (fs.watch, ~100ms latency)
       │
       ▼
Parser extracts structured events
       │
       ▼
Risk Classifier assigns risk levels
       │
       ▼
Alert Engine checks rules, generates alerts
       │
       ▼
SQLite stores everything
       │
       ▼
Dashboard queries SQLite, renders UI
```

**End-to-end latency from agent action to dashboard visibility: < 500ms.**

## What This Design Avoids

- **No agent modification.** The agent code is untouched. No middleware, no hooks, no plugins.
- **No network calls.** Everything is local. No telemetry, no cloud, no external APIs.
- **No blocking I/O in the agent path.** The tracker is a completely separate process.
- **No heavy infrastructure.** No Docker, no Postgres, no Redis. One Node process and one SQLite file.
