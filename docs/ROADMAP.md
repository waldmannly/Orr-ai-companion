# AL Companion Tracker — Roadmap

## What's Built (v1)

| Feature | Detail |
|---------|--------|
| Real-time pipeline | Async log tailing → parse → classify → store → broadcast via SSE |
| 67+ detection rules | Deployment, SSH, exfil, injection, deps, env vars, permissions, processes, retries, protected branches |
| 7-page dashboard | Home, Sessions, Timeline, Security, Memory, Projects, Settings |
| 3 providers | VS Code Copilot, Claude Code, Gemini CLI (auto-detected) |
| Structured risk signals | Every flag explains what, why, and the danger |
| 14 configurable alert rules | Enable/disable + severity per rule |
| Webhooks & notifications | Slack, generic webhook, desktop toasts — per-severity filtering |
| Behavioral baselines | Per-project rolling averages, spike detection via anomaly scoring |
| Memory lineage | Full write/read history per file, cross-session health dashboard |
| Token tracking | Per-session & per-project token counts with cost awareness |
| Advanced filtering | Date range, risk level, event type, text search, limit/offset |
| Session health grades | A–F grading, risk velocity, events/min, replay mode |
| Global metrics | Alert fatigue index, time-to-danger, project coverage |

---

## Up Next

### High Impact

| # | Feature | Status | Effort |
|---|---------|--------|--------|
| 1 | **Export & Reporting** — JSON/CSV export, incident reports, weekly summaries | ✅ Done | Medium |
| 2 | **Sub-Agent Authority** — trust hierarchy, scope enforcement, delegation tree | ✅ Done | Large |
| 3 | **Multi-Agent Correlation** — cross-session view, conflict detection, interleaved timeline | ✅ Done | Large |
| 4 | **Memory Content Analysis** — injection scoring beyond regex, cross-session diffs | ✅ Done | Medium |

### Medium Impact

| # | Feature | Status | Effort |
|---|---------|--------|--------|
| 5 | **Team Dashboard** — auth layer, multi-user ingestion, shared rules | ✅ Done | Large |
| 6 | **Plugin System** — custom rules, providers, and widgets via JS API | ✅ Done | Large |
| 7 | **Automated Response** — kill terminal, block writes, pause agent (opt-in only) | ✅ Done | Medium |

---

## Detection Coverage

Already tracking:

- Dependency mutations (npm/yarn/pip/cargo add/remove)
- Environment variable access ($SECRET, printenv, %ENV%)
- Protected branch pushes (main, master, production, release)
- File permission changes (chmod, chown, icacls)
- Retry/loop patterns (while true, --retry)
- Process management (kill, systemctl, taskkill, pkill)
- Network exfil, SSH, curl/wget to unknown hosts
- Git force-push, reset --hard, rebase on shared branches
- Sensitive file access (.env, id_rsa, /etc/shadow)
- Memory injection patterns
- Clipboard operations (pbcopy, xclip, Set-Clipboard, etc.)
- Context window / token manipulation
- External URL resolution (shorteners, raw IPs, non-standard ports)
- Agent confidence / uncertainty detection

Want to add:

- ~~Agent reasoning / confidence (needs provider support)~~ ✅ Done
- ~~Context window usage correlation~~ ✅ Done
- ~~Clipboard operations~~ ✅ Done
- ~~External URL resolution (where do fetches actually go?)~~ ✅ Done

---

## Priority Order (for next sprint)

1. Export to JSON/CSV (simple endpoint + download button)
2. PDF incident report (template + puppeteer or similar)
3. Memory content diff between sessions
4. Sub-agent scope modeling
5. Plugin API v1 (custom detection rules)
