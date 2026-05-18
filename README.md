# 🛡 Orr — AI Companion

**AI Agent Activity Monitor** — Track, audit, and visualize what AI coding agents are doing on your machine in real time.

AI agents run dozens of tool calls per session — reading files, writing code, executing commands, accessing the network. Orr watches all of it silently, flags risky actions, and gives you a dashboard to understand exactly what happened.

> 📖 **New here?** Check out the **[Usage Guide](docs/USAGE.md)** for a full walkthrough of every feature and tips for getting the most out of the tracker.

---

## Why This Exists

AI coding agents are unsupervised contractors with broad access to your system. They read your secrets, modify configs, run shell commands, and touch production branches — all in a few-minute session with zero audit trail.

When something breaks, you have no way to trace what happened. Orr fixes that.

---

## Features at a Glance

| Category | Highlights |
|----------|-----------|
| **Monitoring** | Auto-discovers Copilot, Claude Code, Gemini CLI sessions; live SSE event stream; zero-config |
| **Risk & Alerts** | 5 severity tiers (info → critical); 14+ alert rules; supply chain / typosquatting detection; alert dedup with configurable toggle |
| **Threats** | Dedicated threat view for confirmed malicious activity — reverse shells, crypto miners, credential harvesters, C2, disk wipes |
| **Guardrails** | Block dangerous commands; approval queue; auto-deny timeout; session kill on critical; token budgets; network allowlist |
| **Trust Scores** | Per-provider grades (A–F) based on historical behavior |
| **Dashboard** | 23-page SPA with live updates, phone-sized desktop layout |
| **Policy Engine** | Three-tier (individual → team → enterprise); strictest-wins merge; field-level locking |
| **Compliance** | Tamper-evident hash chain; signed exports; SOC2/ISO evidence generation |
| **Supply Chain** | Typosquatting detection across npm, pip, cargo, gem, go, composer, dotnet; dependency confusion; scope confusion |
| **Integrations** | Slack, Microsoft Teams, webhooks, desktop notifications, VS Code extension |
| **CLI** | Full headless operation: start, status, replay, export, sessions, config, rules, compact, autostart |

See the **[full feature list →](docs/USAGE.md)**

---

## Quick Start

### Prerequisites

- **Node.js 18+** (tested with Node 20–24)
- **npm** (comes with Node.js)

### Install & Run

```bash
git clone https://github.com/your-username/orr-ai-companion.git
cd orr-ai-companion
npm install
npm run build
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

## Configuration

All configuration lives in `config.json` in the project root. The tracker works with zero configuration — every setting has sensible defaults. Copy the example to get started:

```bash
cp config.example.json config.json
```

```json
{
  "dashboard": { "port": 3847, "host": "127.0.0.1" },
  "alertRules": {
    "destructive_commands": { "enabled": true, "minSeverity": "danger" },
    "sensitive_files": { "enabled": true, "minSeverity": "warn" },
    "supply_chain": { "enabled": true, "minSeverity": "warn" }
  },
  "notifications": {
    "slack": { "enabled": false, "url": "", "minSeverity": "warn" },
    "desktop": { "enabled": true, "minSeverity": "danger" }
  },
  "retention": { "maxAgeDays": 90, "maxDbSizeMB": 500 }
}
```

See **[docs/USAGE.md](docs/USAGE.md)** for the full configuration reference with all 14+ alert rules, guardrails, token budgets, and notification options.

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│  AI Agents (Copilot, Claude, Gemini, custom)     │
│  Write transcript logs to disk                   │
└──────────────┬───────────────────────────────────┘
               │ file watch (passive tail)
┌──────────────▼───────────────────────────────────┐
│  Watcher / Log Tailer                            │
│  • Discovers transcript files automatically      │
│  • Tails from last-known offset (persistent)     │
│  • Provider-specific parsers (Copilot/Claude/    │
│    Gemini/generic JSONL)                         │
└──────────────┬───────────────────────────────────┘
               │
┌──────────────▼───────────────────────────────────┐
│  Processing Pipeline                             │
│  • Risk classification (5 levels)                │
│  • Alert evaluation (14+ rule categories)        │
│  • Supply chain / typosquatting detection        │
│  • Guardrail enforcement + session kill          │
│  • Trust score updates                           │
│  • Compliance hash chain                         │
│  • Plugin & rule pack evaluation                 │
└──────────────┬───────────────────────────────────┘
               │
┌──────────────▼───────────────────────────────────┐
│  SQLite Database (WAL mode)                      │
│  • Events, sessions, alerts, memory ops          │
│  • Prompts, commands, baselines, policies        │
│  • Tailer offsets for restart resilience          │
│  • Auto-compaction (VACUUM)                      │
└──────────────┬───────────────────────────────────┘
               │
┌──────────────▼───────────────────────────────────┐
│  Dashboard (Express + Single-Page HTML)          │
│  • 23 pages, SSE live updates                    │
│  • 70+ REST API endpoints                        │
│  • Localhost-only (127.0.0.1:3847)               │
└──────────────────────────────────────────────────┘
```

---

## Development

```bash
npm run build              # Compile TypeScript
npm test                   # 838 unit tests (no server needed)
npm run test:ui            # 329 UI/API tests (requires running server)
npm run test:coverage      # Unit tests with c8 coverage report
npm run dev                # Build + start in one step
```

---

## Security Notes

- **Localhost only** — the dashboard binds to `127.0.0.1`, never exposed to the network
- **All data stays local** — SQLite database in `./data/`, no cloud, no telemetry
- **No secrets stored** — reads agent logs but doesn't store API keys or tokens
- **Team API keys** are stored as SHA-256 hashes, never in plaintext
- **Passive architecture** — tails logs AFTER agents write them; never intercepts or modifies agent behavior

---

## Documentation

| Doc | Description |
|-----|-------------|
| **[docs/USAGE.md](docs/USAGE.md)** | Full feature guide, tips, and configuration reference |
| **[docs/VISION.md](docs/VISION.md)** | Product vision and adoption strategy |
| **[docs/ROADMAP.md](docs/ROADMAP.md)** | Development roadmap |
| **[docs/DATA-ANALYSIS.md](docs/DATA-ANALYSIS.md)** | Data analysis capabilities |

---

