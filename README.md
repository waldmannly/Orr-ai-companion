# 🛡 AL Companion Tracker

**AI Agent Activity Monitor** — Track, audit, and visualize what AI coding agents are doing on your machine in real time.

AI agents run dozens of tool calls per session — reading files, writing code, executing commands, accessing the network. AL Companion Tracker watches all of it silently, flags risky actions, and gives you a dashboard to understand exactly what happened.

---

## Why This Exists

AI coding agents are unsupervised contractors with broad access to your system. They read your secrets, modify configs, run shell commands, and touch production branches — all in a few-minute session with zero audit trail.

When something breaks, you have no way to trace what happened. AL Companion Tracker fixes that.

---

## Features

### Real-Time Monitoring
- **Auto-discovers AI agent sessions** from VS Code Copilot, Claude Code, and Gemini CLI
- **Parses every tool call** — file reads/writes, terminal commands, web fetches, memory operations
- **Live event stream** via SSE — see activity as it happens
- **Zero configuration required** — works out of the box

### Risk Detection & Alerts
- **Classifies every event** by risk level: info, watch, warn, danger
- **10+ built-in alert rules**: destructive commands, sensitive file access, deployment actions, SSH/remote access, data exfiltration, force pushes, memory injection, suspicious downloads
- **Alert burst detection** — escalates when multiple warnings fire in rapid succession
- **Configurable per-rule thresholds** — enable/disable rules, set minimum severity

### Dashboard (22 Pages)
- **Home** — session overview, alert counts, daily activity charts
- **Sessions** — browse all sessions, search, filter by project
- **Timeline** — event-by-event replay with risk highlighting
- **Security** — alert review, bulk acknowledge, severity filters
- **Memory** — track AI memory reads/writes/deletes across scopes
- **Projects** — per-project stats and session grouping
- **Trust** — provider trust scores based on historical behavior
- **Guardrails** — rule violations, blocked actions, guardrail config
- **Audit/Compliance** — hash chain verification, evidence reports, signed session exports
- **Prompts** — full prompt history, search, crash recovery context
- **Command Queue** — blocked commands awaiting approval/denial
- **Export** — CSV/JSON export, incident reports, weekly summaries
- **Agents** — sub-agent delegation trees, authority scopes, violation tracking
- **Correlation** — cross-session analysis, interleaved timelines
- **Analysis** — memory content analysis, injection scoring
- **Plugins** — community plugin system for custom detection rules
- **Team** — multi-user management, shared rules, API key auth
- **Response** — automated response actions for detected patterns
- **Replay** — session replay with event scrubbing
- **Tasks** — linked session tracking by project + branch
- **Policy** — enterprise policy engine (individual → team → enterprise tiers)
- **Settings** — all configuration in one place

### Guardrails & Intervention
- **Block dangerous commands** before they execute
- **Approval queue** for high-risk actions
- **Auto-deny timeout** for unreviewed interventions
- **Token budget limits** per session and per day

### Enterprise Policy Engine
- **Three-tier policy model**: individual → team → enterprise
- **Strictest-wins merge strategy** — org policies override local settings
- **Field-level locking** — enterprise can lock specific guardrail settings
- **Policy violation tracking** and metrics

### Additional Capabilities
- **CLI tool** for headless operation and scripting
- **Slack and webhook notifications** for alerts
- **Community rule packs** — shareable detection rule sets
- **Custom provider support** — add any JSONL-based agent log format
- **Data retention** — automatic pruning of old events (default: 90 days)
- **SQLite storage** with WAL mode — fast, portable, zero-dependency
- **Compliance hash chain** — tamper-evident event log

---

## Quick Start

### Prerequisites

- **Node.js 18+** (tested with Node 20–24)
- **npm** (comes with Node.js)

### Install & Run

```bash
# Clone the repo
git clone https://github.com/your-username/al-companion-tracker.git
cd al-companion-tracker

# Install dependencies
npm install

# Build
npm run build

# Start the tracker
npm start
```

The tracker will:
1. Auto-discover AI agent transcript files on your machine
2. Start parsing events into a local SQLite database
3. Launch the dashboard at **http://127.0.0.1:3847**

Open the dashboard URL in your browser. That's it.

### Supported AI Agents

| Agent | Auto-Detected | Log Format |
|-------|:---:|---|
| VS Code Copilot | ✅ | VS Code workspace storage transcripts |
| Claude Code (CLI) | ✅ | `~/.claude/projects/` JSONL |
| Gemini CLI | ✅ | `~/.gemini/` JSONL |
| Custom agents | ➕ | Any JSONL — configure in `config.json` |

---

## CLI Usage

```bash
# Start tracker (watcher + dashboard)
al-tracker start

# Check current session status
al-tracker status

# Replay last 10 minutes of activity
al-tracker replay 10

# Export last 7 days as CSV
al-tracker export --format=csv --output=events.csv

# List recent sessions
al-tracker sessions

# View or update config
al-tracker config
al-tracker config dashboard.port=4000

# Manage detection rule packs
al-tracker rules list
al-tracker rules add ./my-rules.pack.json

# Auto-start on login
al-tracker autostart enable
al-tracker autostart status
```

---

## Configuration

All configuration lives in `config.json` in the project root. The tracker works with zero configuration — every setting has sensible defaults.

### Example `config.json`

```json
{
  "dashboard": {
    "port": 3847,
    "host": "127.0.0.1"
  },
  "alertRules": {
    "destructive_commands": { "enabled": true, "minSeverity": "danger" },
    "sensitive_files": { "enabled": true, "minSeverity": "warn" },
    "memory_injection": { "enabled": true, "minSeverity": "warn" },
    "deployment": { "enabled": true, "minSeverity": "danger" },
    "ssh_remote": { "enabled": true, "minSeverity": "danger" },
    "data_exfiltration": { "enabled": true, "minSeverity": "warn" },
    "force_push": { "enabled": true, "minSeverity": "warn" }
  },
  "notifications": {
    "slack": { "enabled": false, "url": "", "minSeverity": "warn" },
    "webhook": { "enabled": false, "url": "", "minSeverity": "danger" },
    "desktop": { "enabled": true, "minSeverity": "danger" }
  },
  "sensitiveFiles": {
    "patterns": ["**/.env*", "**/*.pem", "**/*.key", "**/credentials*"],
    "exactPaths": []
  },
  "retention": {
    "maxAgeDays": 90,
    "maxDbSizeMB": 500
  },
  "tokenBudget": {
    "maxPerSession": 0,
    "maxPerDay": 0,
    "action": "warn"
  }
}
```

### Alert Rules

| Rule | Default | What It Detects |
|------|:---:|---|
| `destructive_commands` | danger | `rm -rf`, `git reset --hard`, `DROP TABLE`, etc. |
| `sensitive_files` | warn | Access to `.env`, `.pem`, `.key`, credentials |
| `memory_injection` | warn | Prompt injection patterns in AI memory writes |
| `deployment` | danger | `npm publish`, `kubectl apply`, `terraform apply`, deploy scripts |
| `ssh_remote` | danger | SSH, SCP, rsync, netcat commands |
| `data_exfiltration` | warn | `curl POST` with data, piping to network, encoded data transfer |
| `force_push` | warn | `git push --force` / `git push -f` |
| `suspicious_download` | warn | Downloading executables, packages from non-default registries |
| `memory_operations` | off | All AI memory writes (noisy — enable for high-security environments) |
| `network_access` | off | All network access (very noisy) |
| `file_operations` | off | All file read/write operations |
| `git_operations` | off | All git operations |
| `subagent_spawn` | off | Sub-agent spawning |

### Custom Providers

Add any JSONL-based agent log format:

```json
{
  "customProviders": [
    {
      "id": "my-agent",
      "name": "My Custom Agent",
      "paths": ["~/.my-agent/logs"]
    }
  ]
}
```

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│  AI Agents (Copilot, Claude, Gemini, custom)     │
│  Write transcript logs to disk                   │
└──────────────┬───────────────────────────────────┘
               │ file watch
┌──────────────▼───────────────────────────────────┐
│  Watcher / Log Tailer                            │
│  • Discovers transcript files                    │
│  • Tails from last-known offset (persistent)     │
│  • Parses events via provider-specific parsers   │
│  • Deduplicates at DB level                      │
└──────────────┬───────────────────────────────────┘
               │
┌──────────────▼───────────────────────────────────┐
│  Processing Pipeline                             │
│  • Risk classification (info/watch/warn/danger)  │
│  • Alert evaluation (10+ rule categories)        │
│  • Guardrail enforcement                         │
│  • Trust score updates                           │
│  • Compliance hash chain                         │
│  • Plugin & rule pack evaluation                 │
│  • Auto-response actions                         │
└──────────────┬───────────────────────────────────┘
               │
┌──────────────▼───────────────────────────────────┐
│  SQLite Database (WAL mode)                      │
│  • Events, sessions, alerts, memory ops          │
│  • Prompts, commands, baselines                  │
│  • Team users, shared rules, activity log        │
│  • Tailer offsets for restart resilience          │
└──────────────┬───────────────────────────────────┘
               │
┌──────────────▼───────────────────────────────────┐
│  Dashboard (Express + Single-Page HTML)          │
│  • 22 pages, SSE live updates                    │
│  • REST API for all data                         │
│  • Localhost-only (127.0.0.1:3847)               │
└──────────────────────────────────────────────────┘
```

---

## Development

```bash
# Build
npm run build

# Run unit tests (723 tests)
npm run test:unit

# Run unit tests with coverage report
npm run test:coverage

# Run UI/API tests (329 tests, requires running server)
npm start &          # start the server first
npm test             # then run UI tests

# Dev mode (build + start)
npm run dev
```

### Project Structure

```
src/
├── index.ts              # Entry point + CLI dispatch
├── cli.ts                # CLI subcommands
├── config/               # Configuration loading + merging
├── storage/db.ts         # SQLite schema, migrations, CRUD
├── watcher/              # File watcher + log tailer
├── parser/               # Event type definitions + line parsing
├── providers/            # Agent-specific log parsers
│   ├── vscode-copilot.ts
│   ├── claude-code.ts
│   ├── gemini-cli.ts
│   └── generic.ts
├── dashboard/
│   ├── server.ts         # Express API (70+ endpoints)
│   └── public/index.html # Single-page dashboard app
├── alerts/engine.ts      # Alert rule evaluation
├── risk/classifier.ts    # Risk classification with signals
├── guardrails/           # Guardrail enforcement + intervention queue
├── trust/                # Provider trust scoring
├── compliance/           # Hash chain + evidence reports
├── prompts/              # Prompt history + crash recovery
├── commands/             # Blocked command queue
├── agents/               # Sub-agent authority tracking
├── correlation/          # Cross-session analysis
├── analysis/             # Memory analysis + injection scoring
├── plugins/              # Community plugin system
├── team/                 # Multi-user management
├── response/             # Automated response actions
├── policy/               # Enterprise policy engine
├── rules/packs.ts        # Community rule pack loader
├── notifications/        # Slack, webhook, desktop notifications
└── export/               # CSV/JSON export + reports
```

---

## Security Notes

- **Localhost only** — the dashboard binds to `127.0.0.1`, never exposed to the network
- **All data stays local** — SQLite database in `./data/`, no cloud services, no telemetry
- **No secrets stored** — the tracker reads agent logs but doesn't store API keys or tokens
- **Team API keys** are stored as bcrypt hashes, never in plaintext

---

