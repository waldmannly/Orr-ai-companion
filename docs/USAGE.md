# Usage Guide

Everything Orr does, how to use it, and tips for getting the most out of it.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Dashboard Pages](#dashboard-pages)
- [Risk Levels](#risk-levels)
- [Alert Rules](#alert-rules)
- [Supply Chain & Typosquatting Detection](#supply-chain--typosquatting-detection)
- [Critical Threats](#critical-threats)
- [Guardrails](#guardrails)
- [Trust Scores](#trust-scores)
- [Alert Dedup](#alert-dedup)
- [Token Budgets](#token-budgets)
- [Policy Engine](#policy-engine)
- [Notifications](#notifications)
- [CLI Commands](#cli-commands)
- [Export & Reports](#export--reports)
- [Compliance & Audit](#compliance--audit)
- [Community Rule Packs](#community-rule-packs)
- [Custom Providers](#custom-providers)
- [VS Code Extension](#vs-code-extension)
- [Configuration Reference](#configuration-reference)
- [Tips & Best Practices](#tips--best-practices)

---

## Getting Started

```bash
npm install
npm run build
npm start
```

Open **http://127.0.0.1:3847** in your browser. The tracker auto-discovers sessions from:
- **VS Code Copilot** — workspace storage transcripts
- **Claude Code** — `~/.claude/projects/` JSONL files
- **Gemini CLI** — `~/.gemini/` JSONL files

No configuration needed. It just works.

---

## Dashboard Pages

The dashboard is a 23-page single-page app with live SSE updates. Navigate via the left sidebar.

| Page | Icon | What It Shows |
|------|------|--------------|
| **Home** | 🏠 | Session counts, alert summary, daily activity chart, recent events |
| **Sessions** | 📋 | All sessions with search, filter by project/provider/date |
| **Timeline** | ⏱️ | Event-by-event replay with risk color coding |
| **Security** | 🔒 | Alert review, bulk acknowledge, severity filters, link to Threats |
| **Threats** | ☠️ | Critical-only view — confirmed malicious activity (purple/red theme) |
| **Memory** | 🧠 | AI memory reads/writes/deletes across user/project/global scopes |
| **Projects** | 📁 | Per-project stats, session grouping, risk breakdown |
| **Trust** | ⭐ | Provider trust scores (A–F), historical trend, comparison |
| **Guardrails** | 🚧 | Rule violations, flagged actions, guardrail configuration |
| **Audit** | 📜 | Hash chain verification, evidence reports, signed exports |
| **Prompts** | 💬 | Full prompt history, search, crash recovery context |
| **Queue** | ⏸️ | Flagged commands logged for your review |
| **Export** | 📤 | CSV/JSON export, incident reports, weekly summaries |
| **Agents** | 🤖 | Sub-agent delegation trees, authority scopes, violations |
| **Correlation** | 🔗 | Cross-session analysis, interleaved timelines |
| **Analysis** | 🔬 | Memory content analysis, injection scoring |
| **Plugins** | 🧩 | Community plugin system, installed rule packs |
| **Team** | 👥 | Multi-user management, shared rules, API key auth |
| **Response** | ⚡ | Automated response actions for detected patterns |
| **Replay** | ▶️ | Session replay with event scrubbing/playback |
| **Tasks** | ✅ | Session tracking by project + git branch |
| **Policy** | 🏛️ | Enterprise policy editor (individual/team/enterprise tiers) |
| **Settings** | ⚙️ | All configuration in one place |

---

## Risk Levels

Every event is classified into one of 5 severity tiers:

| Level | Color | Meaning |
|-------|-------|---------|
| `info` | Gray | Normal operation — file reads, routine commands |
| `watch` | Blue | Worth noting — unusual but not alarming |
| `warn` | Yellow | Suspicious — accessing sensitive files, unusual downloads |
| `danger` | Red | Dangerous — destructive commands, SSH access, data exfil |
| `critical` | Purple | Confirmed malicious — reverse shells, crypto miners, typosquats |

The classifier uses **signal-based scoring** with escalation rules. Multiple weak signals can escalate a single event.

---

## Alert Rules

14+ built-in alert rules, all configurable:

| Rule | Default Severity | Detects |
|------|:---:|---|
| `destructive_commands` | danger | `rm -rf`, `git reset --hard`, `DROP TABLE`, format commands |
| `sensitive_files` | warn | `.env`, `.pem`, `.key`, `credentials`, `secrets`, `id_rsa` |
| `memory_injection` | warn | Prompt injection patterns in AI memory writes |
| `deployment` | danger | `npm publish`, `kubectl apply`, `terraform apply`, `docker push` |
| `ssh_remote` | danger | SSH, SCP, rsync, netcat, remote connections |
| `data_exfiltration` | warn | `curl -d`, piping to network, base64-encoded transfers |
| `suspicious_download` | warn | Downloading executables, sketchy URLs, non-default registries |
| `suspicious_fetch` | warn | Agent fetching from unusual/untrusted URLs |
| `supply_chain` | warn | Typosquatting, dependency confusion, scope confusion |
| `force_push` | warn | `git push --force`, `git push -f` |
| `memory_operations` | off | All AI memory writes (enable for high-security) |
| `network_access` | off | All network access (very noisy) |
| `file_operations` | off | All file read/write ops |
| `git_operations` | off | All git commands |
| `subagent_spawn` | off | When agents spawn sub-agents |

### Alert Burst Detection

When multiple alerts fire in rapid succession on the same session, the tracker escalates the overall session severity and can trigger guardrail actions. Bursty alert types (SSH, downloads) are excluded from burst counting to avoid false escalation.

---

## Supply Chain & Typosquatting Detection

Catches malicious package installs across **7 ecosystems**:

| Ecosystem | Commands Detected |
|-----------|------------------|
| npm / yarn / pnpm / bun | `npm install`, `yarn add`, `pnpm add`, `bun add` |
| Python | `pip install`, `pip3 install` |
| Rust | `cargo add`, `cargo install` |
| Ruby | `gem install`, `bundle add` |
| Go | `go get`, `go install` |
| PHP | `composer require` |
| .NET | `dotnet add package` |

### What It Catches

- **Levenshtein typosquats** — `lod-ash` instead of `lodash` (1-2 char difference)
- **Transposition attacks** — `exrpess` instead of `express`
- **Prefix/suffix attacks** — `lodash-utils`, `react-native-helper`
- **Separator confusion** — `lodash_core` vs `lodash-core`
- **Scope confusion** — `@evil/lodash` (wrong npm scope)
- **Dependency confusion** — `internal-*` names targeting private registries
- **Suspicious install flags** — `--ignore-scripts`, `--force`, `--no-verify`

Maintains curated lists of 200+ popular packages across ecosystems. Any install of a near-miss fires a **critical** alert.

---

## Critical Threats

The **Threats** page (☠️) shows only confirmed malicious activity. These fire at `critical` level and trigger immediate session kill (stops monitoring):

| Threat | Examples |
|--------|----------|
| **Reverse shells** | `bash -i >& /dev/tcp/`, `nc -e /bin/sh`, `python -c 'import socket'` |
| **Crypto miners** | `xmrig`, `cryptonight`, `stratum+tcp://` |
| **Credential harvesters** | `mimikatz`, credential dumping commands |
| **C2 frameworks** | `meterpreter`, `cobalt strike`, `empire` |
| **Encoded payloads** | `base64 -d | sh`, `eval(atob(`, `python -c exec(` |
| **Disk wipes** | `dd if=/dev/zero`, `mkfs.ext4 /dev/sd` |
| **Typosquats** | Any package matching a known popular package within 1-2 edits |

When a critical threat fires:
1. Desktop notification (forced)
2. Session monitoring stopped immediately (agent still running — stop it manually)
3. Alert appears on Threats page with pulsing nav badge
4. SSE pushes update to all connected dashboards

---

## Guardrails

Real-time detection and alerting for dangerous agent actions. Guardrails fire the instant a risky action is observed in the log stream and immediately notify you via desktop notification, SSE push, and dashboard alerts.

> **Note:** Orr is a passive log tailer — it reads agent transcripts *after* actions are written. Guardrails detect and flag violations instantly, but cannot prevent execution. The agent continues running unless you manually stop it. Future versions may introduce middleware-based interception for true pre-execution blocking.

| Feature | Description |
|---------|-------------|
| **Command detection** | Dangerous commands flagged instantly with desktop + dashboard alerts |
| **Review queue** | Flagged actions logged for your review with full context |
| **Auto-escalation** | Unreviewed flagged commands auto-escalate after timeout |
| **Session kill** | Stops monitoring the session and marks it killed (agent process is not terminated) |
| **Token budgets** | Alert/kill-monitor when sessions exceed token limits |
| **Network allowlist** | Flag outbound network calls to non-allowed domains |
| **Daily limits** | Cap total AI token spend per day |

### Session Kill on Critical

When enabled, any `critical`-level alert immediately stops monitoring that session. The session is marked as killed in the database and no further events are processed. **Important:** this does not terminate the agent process itself — you must manually stop the agent (close the terminal, stop VS Code, etc.).

```json
{ "guardrails": { "sessionKill": { "enabled": true } } }
```

---

## Trust Scores

Every AI provider gets a trust grade (A–F) based on historical session behavior:

- **A** — Clean sessions, stays in scope, no surprises
- **B** — Minor warnings, generally safe
- **C** — Accessed sensitive files, ran unusual commands
- **D** — Multiple danger alerts, hit guardrails
- **F** — Critical threats, session kills, repeated violations

Trust scores update after every session. View trends on the Trust page to compare providers over time.

---

## Alert Dedup

To prevent alert spam (e.g., an SSH deploy script generating 50 identical alerts), the tracker deduplicates by default:

- **30-minute cooldown** per session per alert type
- After one SSH alert fires, subsequent SSH events in the same session are suppressed for 30 min
- Applies to `ssh_remote` and `suspicious_download` by default

### Disable Dedup

If you're monitoring agents that should **never** use SSH (local-only development), you want every alert:

```json
{
  "alertRules": {
    "ssh_remote": { "enabled": true, "minSeverity": "danger", "dedup": false }
  }
}
```

With `"dedup": false`, every single SSH command fires an alert. Useful for catching bad agents that are supposed to stay local.

---

## Token Budgets

Prevent runaway sessions from burning through your AI credits:

```json
{
  "tokenBudget": {
    "maxPerSession": 100000,
    "maxPerDay": 500000,
    "action": "warn"
  }
}
```

| Setting | Effect |
|---------|--------|
| `maxPerSession` | Max tokens per single session (0 = unlimited) |
| `maxPerDay` | Max tokens across all sessions in 24h (0 = unlimited) |
| `action` | `"warn"` = alert only, `"kill"` = terminate session |

---

## Policy Engine

Three-tier policy system for teams and enterprises:

```
Individual (local config.json)
    ↓ merged with
Team (shared team policy)
    ↓ merged with
Enterprise (org-wide policy)
```

**Strictest-wins merge** — if enterprise says "no SSH", it doesn't matter what local config allows. Enterprise always wins.

**Field-level locking** — enterprise can lock specific fields so they can't be overridden at team or individual level.

---

## Notifications

Get alerted outside the dashboard:

| Channel | Config Key | Notes |
|---------|-----------|-------|
| **Desktop** | `notifications.desktop` | Native OS notifications |
| **Slack** | `notifications.slack` | Webhook URL, posts to channel |
| **Microsoft Teams** | `notifications.teams` | Incoming webhook URL |
| **Custom webhook** | `notifications.webhook` | POST JSON to any URL |

Each channel has its own `minSeverity` — e.g., desktop at `danger`, Slack at `warn`.

---

## CLI Commands

Full headless operation without the dashboard:

```bash
orr start                  # Start watcher + dashboard
orr status                 # Current session status
orr sessions               # List recent sessions
orr replay 10              # Replay last 10 minutes
orr export --format=csv    # Export events to CSV
orr export --format=json   # Export events to JSON
orr config                 # View current config
orr config key=value       # Update config value
orr rules list             # List installed rule packs
orr rules add ./pack.json  # Install a rule pack
orr compact                # Run database compaction (VACUUM)
orr autostart enable       # Auto-start on login
orr autostart status       # Check autostart status
```

---

## Export & Reports

Generate reports for compliance, incident response, or weekly review:

| Format | Use Case |
|--------|----------|
| **CSV** | Spreadsheet analysis, bulk processing |
| **JSON** | Integration with other tools, programmatic access |
| **Incident report** | Formatted summary of a specific alert/session |
| **Weekly summary** | Digest of AI activity over the past 7 days |
| **Signed export** | Tamper-evident session export with hash chain |

All exports available via the Export page or CLI.

---

## Compliance & Audit

For regulated environments (SOC2, ISO 27001, HIPAA):

- **Tamper-evident hash chain** — each event links to the previous via SHA-256
- **Hash chain verification** — detect if any event was modified/deleted
- **Signed session exports** — cryptographic proof of what happened
- **Evidence reports** — formatted for compliance audits
- **Immutable logging** — events are append-only, never modified

The Audit page shows chain status and lets you verify integrity on demand.

---

## Community Rule Packs

Shareable detection rule sets for specific threat categories:

```bash
# Install a community rule pack
orr rules add @community/supply-chain
orr rules add @community/aws-credential-leaks
orr rules add @community/ci-sabotage

# List installed packs
orr rules list
```

Rule packs are JSON files that define custom detection patterns. Create your own and share with your team.

---

## Custom Providers

Add any JSONL-based agent that writes logs:

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

The tracker will watch those paths and parse JSONL lines using the generic parser. Events are attributed to your custom provider in the dashboard.

---

## VS Code Extension

The `vscode-extension/` directory contains a companion VS Code extension that provides:

- Status bar indicator showing current session health
- Quick access to the dashboard
- In-editor notifications for alerts

Install from the extension directory or VS Code marketplace.

---

## Configuration Reference

All settings in `config.json` with defaults:

```json
{
  "watchPaths": [],
  "sensitiveFiles": {
    "patterns": ["**/.env*", "**/*.pem", "**/*.key", "**/id_rsa*",
                 "**/credentials*", "**/secrets*"],
    "exactPaths": ["/etc/shadow"]
  },
  "dangerousCommands": ["rm -rf", "git push --force", "git push -f",
                        "git reset --hard", "DROP TABLE"],
  "alertRules": {
    "destructive_commands": { "enabled": true, "minSeverity": "danger" },
    "sensitive_files": { "enabled": true, "minSeverity": "warn" },
    "memory_operations": { "enabled": false, "minSeverity": "warn" },
    "memory_injection": { "enabled": true, "minSeverity": "warn" },
    "deployment": { "enabled": true, "minSeverity": "danger" },
    "ssh_remote": { "enabled": true, "minSeverity": "danger", "dedup": true },
    "data_exfiltration": { "enabled": true, "minSeverity": "warn" },
    "suspicious_download": { "enabled": true, "minSeverity": "warn", "dedup": true },
    "suspicious_fetch": { "enabled": true, "minSeverity": "warn" },
    "supply_chain": { "enabled": true, "minSeverity": "warn" },
    "network_access": { "enabled": false, "minSeverity": "watch" },
    "force_push": { "enabled": true, "minSeverity": "warn" },
    "file_operations": { "enabled": false, "minSeverity": "watch" },
    "git_operations": { "enabled": false, "minSeverity": "watch" },
    "subagent_spawn": { "enabled": false, "minSeverity": "watch" }
  },
  "notifications": {
    "slack": { "enabled": false, "url": "", "minSeverity": "warn" },
    "webhook": { "enabled": false, "url": "", "minSeverity": "danger" },
    "teams": { "enabled": false, "url": "", "minSeverity": "warn" },
    "desktop": { "enabled": true, "minSeverity": "danger" }
  },
  "dashboard": { "port": 3847, "host": "127.0.0.1" },
  "retention": { "maxAgeDays": 90, "maxDbSizeMB": 500 },
  "tokenBudget": { "maxPerSession": 0, "maxPerDay": 0, "action": "warn" },
  "guardrails": {
    "sessionKill": { "enabled": false },
    "dailyTokenLimit": 0,
    "networkAllowlist": []
  },
  "customProviders": []
}
```

### Per-Rule Options

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | boolean | Turn the rule on/off |
| `minSeverity` | string | Minimum level to trigger: `watch`, `warn`, `danger` |
| `dedup` | boolean | (Optional) `false` to disable 30-min cooldown suppression |

---

## Tips & Best Practices

### For Solo Developers

1. **Just run it.** Zero config gets you 90% of the value. Install, start, forget.
2. **Check the dashboard after sketchy sessions.** If an agent did something weird, the timeline shows exactly what happened.
3. **Enable desktop notifications at `danger`.** You'll get a popup the moment something bad happens.
4. **Set token budgets** if you're worried about runaway sessions burning credits.
5. **Use the Trust page** to compare providers — you'll learn which AI agent behaves best on your codebase.

### For Teams

1. **Enable policy engine** — set org-wide guardrails that can't be overridden locally.
2. **Use Slack/Teams notifications** so the whole team knows when agents act up.
3. **Export weekly summaries** for your engineering manager or compliance officer.
4. **Share rule packs** — when one dev discovers a new pattern, everyone benefits.
5. **Lock critical guardrails at enterprise tier** — individual devs can't weaken security.

### For High-Security / Compliance

1. **Enable `memory_operations` rule** — track every AI memory write.
2. **Enable hash chain verification** — prove logs haven't been tampered with.
3. **Generate signed exports** for audit evidence.
4. **Set `sessionKill: true`** — stop monitoring on critical threats (then manually kill the agent).
5. **Use network allowlist** — flag all outbound except known-good domains.
6. **Disable dedup on SSH** — in a local-only environment, every remote connection attempt matters.

### For Catching Bad Agents

If you're evaluating a new AI agent or running one that should only work locally:

```json
{
  "alertRules": {
    "ssh_remote": { "enabled": true, "minSeverity": "warn", "dedup": false },
    "network_access": { "enabled": true, "minSeverity": "watch" },
    "suspicious_download": { "enabled": true, "minSeverity": "warn", "dedup": false }
  },
  "guardrails": { "sessionKill": { "enabled": true } },
  "notifications": { "desktop": { "enabled": true, "minSeverity": "warn" } }
}
```

This gives you maximum visibility: every network call logged, every SSH attempt alerted with no suppression, and auto-kill on critical threats.

---

## API Endpoints

The dashboard exposes 70+ REST API endpoints at `http://127.0.0.1:3847/api/`. Key ones:

| Endpoint | Method | Returns |
|----------|--------|---------|
| `/api/sessions` | GET | All sessions (paginated) |
| `/api/sessions/:id` | GET | Single session detail |
| `/api/events` | GET | Events with filters |
| `/api/alerts` | GET | All alerts |
| `/api/threats` | GET | Critical-only alerts |
| `/api/trust` | GET | Provider trust scores |
| `/api/config` | GET/PUT | Read/update configuration |
| `/api/export` | GET | Export data (CSV/JSON) |
| `/api/compliance/verify` | GET | Hash chain verification |
| `/api/compact` | POST | Trigger database compaction |

SSE stream at `/api/events/stream` for real-time updates.

---

## Database

- **Engine:** SQLite with WAL mode (fast concurrent reads)
- **Location:** `./data/tracker.db`
- **Compaction:** Auto-VACUUM on startup + manual via `orr compact` or `POST /api/compact`
- **Retention:** Auto-prunes events older than `retention.maxAgeDays` (default: 90)
- **Size limit:** Warns when DB exceeds `retention.maxDbSizeMB` (default: 500 MB)
- **Portable:** Single file, copy it anywhere, works on any OS

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Dashboard won't open | Check port 3847 isn't in use: `lsof -i :3847` or `netstat -an | findstr 3847` |
| No sessions detected | Ensure AI agents have been used — transcripts must exist on disk |
| Too many alerts | Raise `minSeverity` on noisy rules, or disable them |
| Missing events | Check `watchPaths` in config — the tracker may not know about custom log locations |
| DB too large | Run `orr compact` or lower `retention.maxAgeDays` |
