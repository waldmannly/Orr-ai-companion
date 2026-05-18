# Orr — Roadmap

## What's Built (v1)

| Feature | Detail |
|---------|--------|
| Real-time pipeline | Async log tailing → parse → classify → store → broadcast via SSE |
| 67+ detection rules | Deployment, SSH, exfil, injection, deps, env vars, permissions, processes, retries, protected branches, clipboard, URL resolution, agent confidence |
| 23-page dashboard | Home, Sessions, Timeline, Security, Threats, Memory, Projects, Trust, Guardrails, Audit, Prompts, Queue, Export, Agents, Correlate, Analysis, Plugins, Team, Response, Replay, Tasks, Policy, Settings |
| 4 providers | VS Code Copilot, Claude Code, Gemini CLI, Custom (auto-detected) |
| Structured risk signals | Every flag explains what, why, and the danger |
| 14 configurable alert rules | Enable/disable + severity per rule |
| Webhooks & notifications | Slack, generic webhook, desktop toasts — per-severity filtering |
| Behavioral baselines | Per-project rolling averages, spike detection via anomaly scoring |
| Memory lineage | Full write/read history per file, cross-session health dashboard |
| Token tracking | Per-session & per-project token counts, budget enforcement (warn/kill) |
| Advanced filtering | Date range, risk level, event type, text search, limit/offset |
| Session health grades | A–F grading, risk velocity, events/min, replay mode |
| Global metrics | Alert fatigue index, time-to-danger, project coverage |
| VS Code extension | Status bar widget, inline decorations, gutter icons, command palette, auto-start server |
| Rich CLI | `orr status/replay/export/sessions/config/rules/autostart` |
| Export & Reporting | JSON/CSV bulk export, incident reports, weekly summaries |
| Sub-Agent Authority | Trust hierarchy, scope enforcement, delegation tree, authority violations |
| Multi-Agent Correlation | Cross-session views, file conflict detection, interleaved timeline |
| Memory Content Analysis | Injection scoring (0-100, 20+ patterns), cross-session diffs |
| Team Dashboard | API key auth (SHA-256 hashed), multi-user roles, shared rules |
| Plugin System | Custom rules/widgets via .plugin.json manifests, SQL-backed widgets |
| Automated Response | Kill terminal, block writes, pause agent (opt-in, all reversible) |
| Session Linking | Auto-group by project+branch, task groups, PR activity summaries |
| Quick Replay | "What just happened?" — last 5/10 min view with files, secrets, commands |
| Auto-Start | Windows startup, macOS launchd, Linux systemd user service |

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
