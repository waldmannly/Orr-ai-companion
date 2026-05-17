# AI Companion Tracker — Implementation Plan

## Tech Stack

| Component | Technology | Rationale |
|---|---|---|
| Log Watcher & Parser | Node.js (TypeScript) | Fast file I/O, native `fs.watch`, runs everywhere |
| Storage | SQLite via `better-sqlite3` | Zero-config, synchronous writes (fast for single-writer), no server process |
| Alert Engine | In-process (TypeScript) | Runs alongside watcher, no IPC overhead |
| Web Dashboard | Express + Preact | Minimal footprint, fast renders, phone-sized SPA |
| Charts | Chart.js or lightweight alternative | Small bundle, covers bar/line/timeline needs |
| Desktop Notifications | `node-notifier` | Cross-platform, optional |

## Project Structure

```
al-companion-tracker/
├── src/
│   ├── watcher/
│   │   ├── index.ts              # Entry point — starts watching
│   │   ├── log-discovery.ts      # Finds debug log directories
│   │   ├── log-tailer.ts         # Tails active log files
│   │   └── session-tracker.ts    # Tracks session lifecycle
│   ├── parser/
│   │   ├── index.ts              # Main parser pipeline
│   │   ├── line-classifier.ts    # Classifies raw log lines into event types
│   │   ├── tool-call-parser.ts   # Extracts tool call details
│   │   ├── memory-parser.ts      # Extracts memory operation details
│   │   └── event-types.ts        # TypeScript types for all events
│   ├── risk/
│   │   ├── classifier.ts         # Risk level assignment
│   │   ├── rules.ts              # Built-in risk rules
│   │   ├── sensitive-files.ts    # User-defined sensitive file patterns
│   │   └── memory-analysis.ts    # Memory poisoning heuristics
│   ├── storage/
│   │   ├── db.ts                 # SQLite connection and migrations
│   │   ├── events.ts             # Event CRUD
│   │   ├── sessions.ts           # Session CRUD
│   │   ├── alerts.ts             # Alert CRUD
│   │   └── queries.ts            # Dashboard query helpers
│   ├── alerts/
│   │   ├── engine.ts             # Alert evaluation engine
│   │   ├── notifier.ts           # Desktop notification bridge
│   │   └── rules.ts              # Alert rule definitions
│   ├── dashboard/
│   │   ├── server.ts             # Express server (localhost only)
│   │   ├── api/                  # REST API routes
│   │   │   ├── sessions.ts
│   │   │   ├── events.ts
│   │   │   ├── alerts.ts
│   │   │   ├── memory.ts
│   │   │   └── stats.ts
│   │   └── public/               # Frontend SPA
│   │       ├── index.html
│   │       ├── app.js
│   │       ├── components/
│   │       │   ├── SessionList.js
│   │       │   ├── EventTimeline.js
│   │       │   ├── AlertPanel.js
│   │       │   ├── MemoryAudit.js
│   │       │   ├── SecurityOverview.js
│   │       │   └── ProjectDrilldown.js
│   │       └── styles/
│   │           └── main.css
│   └── config/
│       ├── index.ts              # Config loader
│       └── defaults.ts           # Default settings
├── config.json                   # User configuration
├── package.json
├── tsconfig.json
└── README.md
```

## Data Collected

### Event Fields

Every event captured from the debug logs includes:

| Field | Type | Description |
|---|---|---|
| `timestamp` | ISO 8601 | When the action occurred |
| `session_id` | string | Which Copilot Chat session |
| `agent_id` | string | Which agent (main or sub-agent name) |
| `parent_agent_id` | string | null | Parent agent if this is a sub-agent |
| `event_type` | enum | Category of action (see below) |
| `tool_name` | string | null | Specific tool invoked (e.g., `read_file`, `run_in_terminal`) |
| `risk_level` | enum | `info` / `watch` / `warn` / `danger` |
| `summary` | string | Human-readable one-line summary |
| `file_paths` | string[] | Files involved in this action |
| `command` | string | null | Terminal command if applicable |
| `parameters` | JSON | Full tool call parameters (sanitized) |
| `duration_ms` | number | null | How long the action took |
| `raw_log` | string | Original log line(s) for forensics |

### Event Types Tracked

| Event Type | What's Captured |
|---|---|
| `file_read` | Path, line range, file size |
| `file_write` | Path, old content hash, new content hash, diff size |
| `file_create` | Path, content size |
| `file_delete` | Path |
| `terminal_command` | Command string, working directory, exit code, output summary |
| `terminal_async` | Long-running process start/stop, process ID |
| `git_commit` | Commit message, files changed, hash |
| `git_push` | Remote, branch, force flag |
| `git_reset` | Mode (soft/hard/mixed), target ref |
| `git_checkout` | Branch/ref, files affected |
| `memory_read` | Memory scope, path, content preview |
| `memory_write` | Memory scope, path, content written, content summary |
| `memory_delete` | Memory scope, path |
| `web_fetch` | URL, query, response size |
| `search` | Query, search type (grep/semantic/file), result count |
| `subagent_spawn` | Agent name, prompt summary, model |
| `subagent_complete` | Agent name, result summary, duration |
| `tool_call` | Generic fallback for any tool invocation |

### Memory Operations — Special Handling

Memory operations get extra processing:

1. **Content is captured and summarized.** What was written to memory is stored in plain text so you can review it.
2. **Scope is tracked.** User memory (persists forever), session memory (current conversation), repo memory (workspace-scoped) — each is labeled.
3. **Instruction detection.** Memory content is scanned for patterns that look like injected instructions (e.g., "always do X", "never mention Y", "ignore previous instructions"). These generate `warn` or `danger` alerts.
4. **Diff on updates.** When memory is modified (via `str_replace`), both the old and new values are captured.

### Sensitive File Detection

Users define sensitive file patterns in `config.json`:

```json
{
  "sensitiveFiles": {
    "patterns": [
      "**/.env*",
      "**/*.pem",
      "**/*.key",
      "**/id_rsa*",
      "**/credentials*",
      "**/secrets*",
      "**/personal/**",
      "**/private/**"
    ],
    "exactPaths": [
      "C:/Users/yourname/Documents/personal-info.txt"
    ]
  }
}
```

Any file read, write, or search result touching these patterns generates an alert.

## Dashboard Views

### 1. Home — Overview

A quick-glance view showing:

- **Active sessions** (if any agent is running right now)
- **Today's stats** — total events, files changed, commands run, alerts triggered
- **Risk summary** — donut chart of event risk levels
- **Recent alerts** — last 5 alerts, sorted by severity

### 2. Sessions

List of all tracked sessions with:

- Project/workspace name
- Start time, duration
- Event count, alert count
- Risk heat indicator (green/yellow/orange/red based on highest alert severity)

Click into a session to see its full timeline.

### 3. Session Timeline

The core drill-down view. A vertical timeline showing every event in a session:

```
┌────────────────────────────────────────────────────┐
│  10:23:01  📂 read_file  src/index.ts (L1-50)      │ info
│  10:23:02  🔍 grep_search  "handleAuth"             │ info
│  10:23:03  📂 read_file  src/auth.ts (L1-120)       │ info
│  10:23:04  ✏️  file_write  src/auth.ts               │ watch
│  10:23:05  📂 read_file  .env                        │ ⚠️ WARN
│  10:23:06  🖥️  terminal  npm test                    │ watch
│  10:23:08  🖥️  terminal  git add -A                  │ watch
│  10:23:09  🖥️  terminal  git commit -m "fix auth"    │ watch
│  10:23:10  🧠 memory_write  /memories/repo/auth.md   │ ⚠️ WARN
│            └─ "Auth uses JWT tokens with 1h expiry"  │
│  10:23:11  🖥️  terminal  git push --force             │ 🔴 DANGER
└────────────────────────────────────────────────────┘
```

Each event is expandable to show full details (parameters, raw log, file diffs).

Filters:
- By event type
- By risk level
- By agent (for multi-agent sessions)
- By file path
- Text search across summaries and commands

### 4. Memory Audit

Dedicated view for all memory operations:

- **Memory Timeline** — chronological list of all reads/writes/deletes
- **Current State Summary** — what's currently in each memory scope, in plain language
- **Suspicious Entries** — any memory content flagged by the instruction-detection heuristic
- **Cross-Session Tracking** — see how memory evolves across multiple sessions (did a session 3 days ago write something that's still influencing behavior?)

### 5. Security Dashboard

Focused on risk and alerts:

- **Alert feed** — all alerts, filterable by severity, type, session
- **Sensitive file access log** — every time a watched file was touched
- **Destructive command log** — every `danger`-level terminal command
- **Trend chart** — alert frequency over time (are things getting riskier?)
- **Unacknowledged alerts** — items you haven't reviewed yet

### 6. Project Drilldown

Group sessions by workspace/project:

- Which projects have the most agent activity
- Which projects have the most alerts
- File change frequency per project
- Agent usage patterns

## User Configuration

`config.json` at the project root:

```json
{
  "watchPaths": [
    "C:/Users/yourname/AppData/Roaming/Code/User/workspaceStorage"
  ],
  "sensitiveFiles": {
    "patterns": ["**/.env*", "**/*.pem", "**/*.key"],
    "exactPaths": []
  },
  "dangerousCommands": [
    "rm -rf",
    "git push --force",
    "git reset --hard",
    "DROP TABLE",
    "DROP DATABASE",
    "format C:",
    "del /f /s /q"
  ],
  "alerts": {
    "desktopNotifications": true,
    "minSeverity": "warn"
  },
  "dashboard": {
    "port": 3847,
    "host": "127.0.0.1"
  },
  "retention": {
    "maxAgeDays": 90,
    "maxDbSizeMB": 500
  }
}
```

## Implementation Phases

### Phase 1: Core Pipeline (MVP)

**Goal:** Tail logs → parse events → store in SQLite → basic CLI output.

- [ ] Set up project scaffolding (TypeScript, build config)
- [ ] Implement log discovery (find debug log directories)
- [ ] Implement log tailer (watch + tail active session logs)
- [ ] Build line classifier (regex-based event type detection)
- [ ] Build tool call parser (extract parameters from structured log entries)
- [ ] Create SQLite schema and migrations
- [ ] Wire up: watcher → parser → storage
- [ ] Basic CLI that prints events as they happen (for testing)

### Phase 2: Risk & Alerts

**Goal:** Classify risk, detect sensitive access, generate alerts.

- [ ] Implement risk classifier with built-in rules
- [ ] Add user-configurable sensitive file watchlist
- [ ] Add dangerous command detection
- [ ] Implement memory operation parser and analyzer
- [ ] Build alert engine with rule evaluation
- [ ] Add desktop notification support
- [ ] Memory poisoning heuristics (instruction-like content detection)

### Phase 3: Web Dashboard

**Goal:** Localhost web UI with all views.

- [ ] Express server with localhost binding
- [ ] REST API routes for sessions, events, alerts, memory, stats
- [ ] Home overview page
- [ ] Session list page
- [ ] Session timeline (the core view)
- [ ] Alert panel
- [ ] Memory audit view
- [ ] Security dashboard
- [ ] Project drilldown

### Phase 4: Polish & UX

**Goal:** Make it feel like a real companion app.

- [ ] Phone-sized viewport design (app-like, not spreadsheet-like)
- [ ] Real-time updates via SSE or WebSocket
- [ ] Smooth animations on timeline
- [ ] Search and filtering across all views
- [ ] Alert acknowledgment workflow
- [ ] Data retention and cleanup
- [ ] One-command startup (`npx al-companion-tracker` or similar)

## How a User Gains Understanding

The tracker transforms raw, unstructured agent activity into layered understanding:

**Layer 1 — Glance (Home page, 2 seconds)**
"Everything looks normal" or "3 danger alerts in the last hour — go look."

**Layer 2 — Scan (Session list, 10 seconds)**
"The agent worked on 3 projects today. The auth-service session has warnings."

**Layer 3 — Review (Session timeline, 1-2 minutes)**
"The agent read my .env file, made 12 file changes, and force-pushed to main. Let me check those changes."

**Layer 4 — Investigate (Event details + memory audit, 5+ minutes)**
"The agent wrote a suspicious instruction to user memory 3 days ago that's been affecting behavior. This looks like it came from a fetched webpage."

Each layer is opt-in. You only drill deeper when something at the surface looks off. The dashboard is designed so that **no news is good news** — if the home page is green, you can trust that the agent behaved.
