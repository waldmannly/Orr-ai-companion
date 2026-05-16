# AL Companion Tracker — Roadmap & High-Impact Features

## Current State (v1)

The tracker already provides:

- **Real-time event pipeline** — captures AI tool calls, file ops, commands, git actions, and memory operations without slowing the AI down (async log tailing + SQLite WAL)
- **60+ risk detection rules** — deployment, SSH, exfiltration, injection, dangerous commands, sensitive files, suspicious downloads
- **7-page dashboard** — Home (stats/charts), Sessions, Timeline, Security (alerts), Memory, Projects, Settings
- **3 providers** — VS Code Copilot, Claude Code, Gemini CLI (auto-detected)
- **Structured risk signals** — every flagged event explains *what* was detected, *why* it's suspicious, and *what the danger is*
- **14 configurable alert rules** — each with enable/disable + severity threshold
- **SSE live updates** — dashboard updates in real-time as events flow in

---

## Missing Features & High-Impact Additions

### 🔴 Priority 1 — High Impact, High Value

#### 1. Webhook & Notification Integrations
**Why**: Alerts are currently trapped in the web UI. You won't see danger-level events unless the dashboard is open.

**What to build**:
- Slack webhook integration (post danger alerts to a channel)
- Generic webhook POST (for SIEM, Discord, Teams, custom pipelines)
- Desktop notifications (system toast on danger events)
- Optional email digest (daily summary of threats)

**Config**:
```json
{
  "notifications": {
    "slack": { "enabled": true, "webhookUrl": "...", "minSeverity": "warn" },
    "webhook": { "enabled": false, "url": "...", "minSeverity": "danger" },
    "desktop": { "enabled": true, "minSeverity": "danger" }
  }
}
```

---

#### 2. Behavioral Baselines & Anomaly Detection
**Why**: Static rules only catch known-bad patterns. The really dangerous stuff is *unusual* behavior — a model that suddenly starts accessing files it never touches, or running commands at 3am, or hitting 10x its normal tool-call rate.

**What to build**:
- Per-session and per-project baselines (avg events/min, common tools, common file paths)
- Spike detection: alert when current session deviates >3σ from baseline
- New-pattern detection: "this agent has never accessed .env files before"
- Time-of-day anomalies: activity outside normal hours
- Gradual drift: detect when an agent's behavior slowly shifts over days

**Dashboard additions**:
- Baseline comparison chart on Home page
- "Unusual for this project" badge on timeline events
- Anomaly history page showing detected drifts

---

#### 3. Memory Threat Intelligence
**Why**: Memory poisoning is a real attack vector. The tracker already logs memory ops, but doesn't deeply analyze *content*.

**What to build**:
- Instruction injection scoring (detect hidden instructions in memory content beyond simple regex)
- Memory lineage tracking: who wrote it, who read it, has it been modified?
- Cross-session memory diff: show what changed between sessions
- "Memory health" dashboard panel showing all active memory files + risk scores
- Alert when memory written by one session is consumed by a different session (potential lateral movement)

---

#### 4. Export & Reporting
**Why**: You can't share findings, create incident reports, or do offline analysis.

**What to build**:
- Export timeline as JSON/CSV (filtered by session, date, risk level)
- PDF incident report generation (for a specific alert or time window)
- Daily/weekly summary reports (auto-generated markdown)
- Shareable session replay links (read-only snapshot)

---

### 🟡 Priority 2 — Medium Impact

#### 5. Sub-Agent Authority Modeling
**Why**: When agents spawn sub-agents (Copilot spawning terminal commands, Claude Code launching child processes), there's no visibility into whether the child exceeded scope.

**What to build**:
- Model trust hierarchy (parent → child delegation)
- Define expected scope per sub-agent (allowed files, allowed tools)
- Alert when sub-agent accesses something outside its parent's context
- Visual delegation tree in timeline view

---

#### 6. Advanced Query & Filtering
**Why**: Finding specific events in a long timeline is painful. No date range picker, no regex, no compound filters.

**What to build**:
- Date range picker on Timeline and Security pages
- Regex search across summaries and commands
- Compound filters (e.g., "risk_level = danger AND tool_name LIKE '%terminal%'")
- Saved filter presets
- Full-text search across all event data

---

#### 7. Multi-Agent Correlation
**Why**: When multiple AI agents work on the same project, it's hard to see how their actions relate.

**What to build**:
- Cross-session view for the same project
- Conflict detection: two agents editing the same file
- Resource contention alerts
- Combined timeline showing all agents' actions interleaved

---

#### 8. Cost & Token Tracking
**Why**: AI agents burn tokens invisibly. Understanding cost per session/project helps with budgeting and detecting runaway agents.

**What to build**:
- Parse token usage from provider logs (Copilot reports tokens in telemetry)
- Per-session and per-project token totals
- Cost estimates based on model pricing
- Alert on unusually high token consumption (could indicate loops)

---

### 🟢 Priority 3 — Nice to Have

#### 9. Session Replay
**Why**: Reviewing what happened in a session as a "replay" (step-by-step with timing) is way more intuitive than scrolling a table.

**What to build**:
- Playback mode: step through events chronologically with real timing
- Speed controls (1x, 2x, 5x, skip to next alert)
- File diff inline viewer showing what changed at each step

---

#### 10. Team Dashboard
**Why**: In team settings, you want aggregate visibility — not just your own agents.

**What to build**:
- Auth layer (API key or OAuth)
- Multi-user event ingestion
- Team-wide risk overview
- Per-developer activity summaries
- Shared alert rules and thresholds

---

#### 11. Plugin System
**Why**: Different teams have different needs. Custom detection rules, custom providers, custom UI panels.

**What to build**:
- Plugin API for custom risk rules (JS functions that receive events)
- Plugin API for custom providers (watch arbitrary log files)
- Plugin API for custom dashboard widgets
- Plugin manifest format and loader

---

#### 12. Automated Response Actions
**Why**: Some threats should trigger immediate action, not just an alert.

**What to build**:
- Kill terminal on danger-level command detection
- Block file write to sensitive paths
- Pause agent execution (if provider supports it)
- Auto-git-stash before destructive operations
- Quarantine mode: log-only, no actual blocking (for auditing before enforcement)

⚠️ *Note: This is the most controversial feature. Default should be alert-only, never block without explicit opt-in.*

---

## What Else Should We Know & Show?

### Information Gaps (things we should surface but don't yet)

| What | Why it matters |
|------|----------------|
| **Agent reasoning** | Why did it choose that command? Did it consider alternatives? |
| **Confidence scores** | Was the AI uncertain? Uncertain actions are riskier. |
| **Context window usage** | How much context was the agent working with? Small context = more mistakes. |
| **Retry patterns** | Did the agent retry something multiple times? Could indicate confusion or brute-forcing. |
| **External network calls** | Which URLs did tool calls actually hit? (fetch, curl, npm install sources) |
| **File permission changes** | chmod, chown, ACL changes are high-signal |
| **Environment variable access** | Which env vars were read? (API keys, secrets) |
| **Clipboard operations** | Did the agent copy sensitive data to clipboard? |
| **Git branch context** | Is the agent working on main/production or a safe branch? |
| **Dependency mutations** | Did it add/remove/change package dependencies? (supply chain risk) |

### Metrics We Should Calculate & Display

- **Risk velocity**: how fast is risk accumulating in this session?
- **Trust score**: per-agent cumulative trust based on history (decays on incidents)
- **Coverage gaps**: which projects have no tracker coverage?
- **Alert fatigue index**: ratio of acknowledged vs unacknowledged alerts (too many = tune rules)
- **Mean time to danger**: avg time from session start to first danger event
- **Session health grade**: A-F letter grade per session based on risk signals

---

## Implementation Priority Order

For maximum impact with minimum effort:

1. **Desktop notifications** (small scope, immediate value)
2. **Webhook integrations** (Slack/generic, one afternoon of work)
3. **Date range filtering** (UI-only change, huge usability win)
4. **Export to JSON/CSV** (simple API endpoint + download button)
5. **Behavioral baselines** (background stats collection + deviation alerts)
6. **Memory lineage** (extend existing memory_operations table)
7. **Token/cost tracking** (parse from existing provider logs)
8. **Anomaly detection** (build on baselines once they exist)
