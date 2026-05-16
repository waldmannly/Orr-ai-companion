import { Config, loadConfig } from '../config';
import { LogTailer } from './log-tailer';
import { SessionParserState } from '../parser';
import { classifyRiskWithReasons, extractMemoryOp } from '../risk/classifier';
import { evaluateAlerts, persistAlerts } from '../alerts/engine';
import { initDb, upsertSession, insertEvent, insertMemoryOp, getSession, markSessionEnded, enforceRetention, insertAlert, getRecentSessionAlertBurst, upsertBaseline, getBaseline, insertGuardrailViolation, setSessionBranch, getTailerOffset, setTailerOffset } from '../storage/db';
import { SessionInfo } from '../parser/event-types';
import { LogProvider, TranscriptFile, getActiveProviders, createCustomProvider } from '../providers';
import { broadcastSSE } from '../dashboard/server';
import { dispatchAlertNotifications } from '../notifications';
import { evaluateGuardrails } from '../guardrails';
import { createIntervention } from '../guardrails/intervention';
import { updateTrustScore } from '../trust';
import { appendToChain, initHashChain } from '../compliance';
import { evaluatePackRules, loadPacksFromDirectory } from '../rules/packs';
import { insertPrompt, getSessionPromptCount } from '../prompts';
import { queueBlockedCommand } from '../commands';
import { upsertAgentNode, incrementAgentDanger, checkAgentAuthority } from '../agents';
import { evaluateAutoResponse } from '../response';
import { evaluatePluginRules } from '../plugins';
import { execSync } from 'child_process';

export class Watcher {
  private config: Config;
  private tailer: LogTailer;
  private sessionCounters = new Map<string, { total: number; danger: number; warn: number; tokens: number }>();
  private parserStates = new Map<string, SessionParserState>();
  private providers: LogProvider[] = [];
  /** Map sessionId → provider so we know which parser to use */
  private sessionProvider = new Map<string, LogProvider>();
  /** Track last event time per session for session-end detection */
  private sessionLastActivity = new Map<string, number>();
  private sessionEndTimer: ReturnType<typeof setInterval> | null = null;
  /** Dedup: track recent event fingerprints per session to skip duplicates */
  private recentHashes = new Map<string, Set<string>>();

  constructor(config?: Config) {
    this.config = config || loadConfig();
    this.tailer = new LogTailer();
  }

  start() {
    console.log('[watcher] Initializing database...');
    initDb();

    // Wire up offset persistence so restarts don't reprocess files
    this.tailer.setOffsetPersistence(getTailerOffset, setTailerOffset);

    // Initialize compliance hash chain
    initHashChain();

    // Load community rule packs if configured
    if (this.config.rulePacksDir) {
      const packs = loadPacksFromDirectory(this.config.rulePacksDir);
      if (packs.length > 0) console.log(`[watcher] Loaded ${packs.length} external rule pack(s)`);
    }

    // Enforce retention policy on startup
    if (this.config.retention.maxAgeDays > 0) {
      console.log(`[watcher] Enforcing retention: pruning events older than ${this.config.retention.maxAgeDays} days`);
      enforceRetention(this.config.retention.maxAgeDays);
    }

    // Build provider list: built-in auto-detected + custom from config
    const customProviders = (this.config.customProviders || [])
      .map(c => createCustomProvider(c.id, c.name, c.paths, c.icon));
    this.providers = getActiveProviders(customProviders);

    console.log(`[watcher] Active providers: ${this.providers.map(p => `${p.icon} ${p.displayName}`).join(', ') || 'none'}`);

    // Wire up the processing pipeline
    this.tailer.on('line', (line: string, file: TranscriptFile) => {
      this.processLine(line, file);
    });

    // Discover and watch for each provider
    let totalFiles = 0;
    for (const provider of this.providers) {
      const logPaths = provider.getDefaultLogPaths();
      const sessions = provider.discoverSessions(logPaths);
      totalFiles += sessions.length;
      console.log(`[watcher] ${provider.displayName}: found ${sessions.length} sessions in ${logPaths.length} path(s)`);

      for (const t of sessions) {
        this.tailTranscript(t, provider);
      }

      // Watch for new sessions
      for (const basePath of logPaths) {
        provider.watchForNewSessions(basePath, (file) => {
          console.log(`[watcher] ${provider.icon} New session: ${file.projectName} (${file.sessionId})`);
          this.tailTranscript(file, provider);
        });
      }
    }

    console.log(`[watcher] Now tailing ${this.tailer.tailedFileCount} files (${totalFiles} discovered)`);

    // Session end detection: mark sessions as ended after 5min inactivity
    this.sessionEndTimer = setInterval(() => {
      const cutoff = Date.now() - 5 * 60 * 1000;
      for (const [sessionId, lastTime] of this.sessionLastActivity) {
        if (lastTime < cutoff) {
          const counters = this.sessionCounters.get(sessionId);
          if (counters && counters.total > 0) {
            markSessionEnded(sessionId, new Date(lastTime).toISOString());
            this.sessionLastActivity.delete(sessionId);
            broadcastSSE('session-ended', { sessionId });
            // Update trust score for the provider when session ends
            const provider = this.sessionProvider.get(sessionId);
            if (provider) {
              updateTrustScore({
                provider: provider.id,
                sessionId,
                dangerCount: counters.danger,
                warnCount: counters.warn,
                totalEvents: counters.total,
              });
            }
          }
        }
      }
    }, 60000);
  }

  private tailTranscript(file: TranscriptFile, provider: LogProvider) {
    // Track which provider owns this session
    this.sessionProvider.set(file.sessionId, provider);

    // Ensure session exists
    const existing = getSession(file.sessionId);
    if (!existing) {
      upsertSession({
        id: file.sessionId,
        workspace: file.workspace,
        project_name: file.projectName,
        started_at: new Date().toISOString(),
        ended_at: null,
        total_events: 0,
        danger_count: 0,
        warn_count: 0,
        source_tool: provider.id,
      });
      // Detect git branch for session linking
      this.detectBranch(file);
    }

    if (!this.sessionCounters.has(file.sessionId)) {
      this.sessionCounters.set(file.sessionId, { total: 0, danger: 0, warn: 0, tokens: 0 });
    }

    if (!this.parserStates.has(file.sessionId)) {
      this.parserStates.set(file.sessionId, new SessionParserState());
    }

    this.tailer.startTailing(file);
  }

  private detectBranch(file: TranscriptFile) {
    try {
      const workspace = file.workspace || process.cwd();
      const branch = execSync('git rev-parse --abbrev-ref HEAD', {
        cwd: workspace, encoding: 'utf-8', timeout: 3000, stdio: ['pipe', 'pipe', 'pipe']
      }).trim();
      if (branch && branch !== 'HEAD') {
        setSessionBranch(file.sessionId, branch);
      }
    } catch {
      // Not a git repo or git not available — skip
    }
  }

  private processLine(line: string, file: TranscriptFile) {
    const provider = this.sessionProvider.get(file.sessionId);
    if (!provider) return;

    const parserState = this.parserStates.get(file.sessionId);
    const event = provider.parseLine(line, file.sessionId, file.workspace, parserState);
    if (!event) return;

    // Ensure source_tool is set
    event.source_tool = event.source_tool || provider.id;

    // Skip turn_start/turn_end for storage (too noisy)
    if (event.event_type === 'turn_start' || event.event_type === 'turn_end') return;

    // Deduplicate: skip if we've seen an identical event recently in this session
    const fingerprint = `${event.timestamp}|${event.event_type}|${event.summary}`;
    if (!this.recentHashes.has(file.sessionId)) {
      this.recentHashes.set(file.sessionId, new Set());
    }
    const hashes = this.recentHashes.get(file.sessionId)!;
    if (hashes.has(fingerprint)) return; // duplicate
    hashes.add(fingerprint);
    if (hashes.size > 1000) hashes.clear(); // reset to avoid unbounded growth

    // Classify risk with structured reasons
    const riskResult = classifyRiskWithReasons(event, this.config);
    event.risk_level = riskResult.level;
    event.risk_signals = riskResult.signals.length > 0 ? riskResult.signals : null;

    // Estimate token count from message/command length
    if (event.event_type === 'user_message' || event.event_type === 'assistant_message') {
      const textLen = (event.summary || '').length + (event.raw_log || '').length;
      event.token_count = Math.max(1, Math.round(textLen / 4)); // rough approximation
    }

    // Token budget enforcement
    if (event.token_count) {
      const counters = this.sessionCounters.get(file.sessionId);
      if (counters) counters.tokens += event.token_count;
      const budget = this.config.tokenBudget;
      if (budget && counters) {
        if (budget.maxPerSession > 0 && counters.tokens > budget.maxPerSession) {
          const msg = `Token budget exceeded: ${counters.tokens.toLocaleString()} / ${budget.maxPerSession.toLocaleString()} per session`;
          if (budget.action === 'kill') {
            broadcastSSE('budget-exceeded', { session_id: file.sessionId, tokens: counters.tokens, limit: budget.maxPerSession, action: 'kill' });
            insertAlert({ event_id: null, session_id: file.sessionId, timestamp: event.timestamp, alert_type: 'token_budget', severity: 'danger', message: msg, acknowledged: false });
          } else {
            broadcastSSE('budget-warning', { session_id: file.sessionId, tokens: counters.tokens, limit: budget.maxPerSession });
            if (counters.tokens - event.token_count <= budget.maxPerSession) {
              // First time exceeding — alert once
              insertAlert({ event_id: null, session_id: file.sessionId, timestamp: event.timestamp, alert_type: 'token_budget', severity: 'warn', message: msg, acknowledged: false });
            }
          }
        }
      }
    }

    // Store event
    const eventId = insertEvent(event);
    event.id = eventId;

    // Capture full prompt text for user messages
    if (event.event_type === 'user_message') {
      const fullText = this.extractFullPrompt(event);
      if (fullText) {
        const seq = getSessionPromptCount(file.sessionId) + 1;
        const provider = this.sessionProvider.get(file.sessionId);
        insertPrompt({
          event_id: eventId,
          session_id: file.sessionId,
          timestamp: event.timestamp,
          content: fullText,
          provider: provider?.id || event.source_tool || '',
          project_name: file.projectName || '',
          token_count: Math.max(1, Math.round(fullText.length / 4)),
          seq,
        });
      }
    }

    // Append to compliance hash chain
    appendToChain(event);

    // Evaluate community rule packs for additional signals
    const packSignals = evaluatePackRules(event);
    if (packSignals.length > 0) {
      // Merge pack signals with existing risk signals
      if (!event.risk_signals) event.risk_signals = [];
      event.risk_signals.push(...packSignals);
      // Elevate risk level if pack rules found higher severity
      for (const sig of packSignals) {
        if (sig.level === 'danger' && event.risk_level !== 'danger') {
          event.risk_level = 'danger';
        } else if (sig.level === 'warn' && event.risk_level === 'info') {
          event.risk_level = 'warn';
        }
      }
    }

    // Evaluate guardrails
    const violations = evaluateGuardrails(event, this.config.guardrails, file.sessionId);
    if (violations.length > 0) {
      for (const v of violations) {
        insertGuardrailViolation({
          event_id: eventId,
          session_id: file.sessionId,
          timestamp: event.timestamp,
          rule: v.rule,
          severity: v.severity,
          message: v.message,
          blocked: v.blocked,
        });
        broadcastSSE('guardrail', { rule: v.rule, severity: v.severity, message: v.message, blocked: v.blocked, session_id: file.sessionId });

        // Create intervention for blocked actions — dashboard can approve/deny
        if (v.blocked) {
          const provider = this.sessionProvider.get(file.sessionId);
          const actionType = event.event_type === 'terminal_command' ? 'command'
            : event.event_type === 'web_fetch' ? 'network'
            : (event.file_paths?.length > 0) ? 'file'
            : 'other';
          const actionTarget = event.command
            || (event.file_paths?.length > 0 ? event.file_paths.join(', ') : '')
            || event.summary || '';
          const intervention = createIntervention({
            sessionId: file.sessionId,
            rule: v.rule,
            severity: v.severity,
            message: v.message,
            actionType,
            actionTarget,
            provider: provider?.id || 'unknown',
          });
          broadcastSSE('intervention-pending', intervention);

          // Persist blocked command to DB (survives crashes, supports edit+relaunch)
          const queued = queueBlockedCommand({
            session_id: file.sessionId,
            event_id: eventId,
            provider: provider?.id || 'unknown',
            project_name: file.projectName || 'unknown',
            action_type: actionType,
            original_command: actionTarget,
            rule: v.rule,
            severity: v.severity,
            message: v.message,
          });
          broadcastSSE('command-blocked', queued);
        }
      }
      // Elevate risk level if guardrail fires
      if (violations.some(v => v.severity === 'danger') && event.risk_level !== 'danger') {
        event.risk_level = 'danger';
      }
    }

    // Baseline tracking: update per-project metrics
    const projectName = file.projectName || 'unknown';
    upsertBaseline(projectName, 'events_per_session', 1, 1);
    if (event.risk_level === 'danger') upsertBaseline(projectName, 'danger_per_session', 1, 1);
    if (event.token_count) upsertBaseline(projectName, 'tokens_per_event', event.token_count, 1);

    // Anomaly detection: compare event rate to baseline
    const baselineRate = getBaseline(projectName, 'events_per_session');
    if (baselineRate && baselineRate.sample_count >= 10) {
      const counters = this.sessionCounters.get(file.sessionId);
      if (counters && counters.total > baselineRate.value * 3) {
        event.anomaly_score = Math.min(1, (counters.total / baselineRate.value - 1) / 5);
      }
    }

    // Track session activity for end detection
    this.sessionLastActivity.set(file.sessionId, Date.now());

    // Broadcast to SSE clients
    broadcastSSE('event', { id: eventId, session_id: event.session_id, event_type: event.event_type,
      risk_level: event.risk_level, summary: event.summary, timestamp: event.timestamp, agent_id: event.agent_id });

    // Extract and store memory operations
    const memOp = extractMemoryOp(event);
    if (memOp) {
      memOp.event_id = eventId;
      memOp.risk_level = event.risk_level;
      insertMemoryOp(memOp);
    }

    // Evaluate and store alerts
    const alerts = evaluateAlerts(event, this.config);
    if (alerts.length > 0) {
      for (const a of alerts) a.event_id = eventId;
      persistAlerts(alerts);
      // Broadcast alert to SSE and dispatch notifications
      for (const a of alerts) {
        broadcastSSE('alert', { severity: a.severity, message: a.message, session_id: a.session_id, event_id: eventId });
        dispatchAlertNotifications(a).catch(() => {});
      }
    }

    // Composite risk: if 3+ warn/danger alerts in 5 minutes, fire escalation alert
    if (event.risk_level === 'warn' || event.risk_level === 'danger') {
      if (getRecentSessionAlertBurst(file.sessionId, 5, 5)) {
        const existing = alerts.find(a => a.alert_type === 'alert_burst');
        if (!existing) {
          const burstAlert = {
            event_id: eventId, session_id: file.sessionId, timestamp: event.timestamp,
            alert_type: 'alert_burst', severity: 'danger' as const,
            message: `High alert activity: 5+ warnings in 5 minutes in this session`,
            acknowledged: false,
          };
          insertAlert(burstAlert);
          broadcastSSE('alert', { severity: 'danger', message: burstAlert.message, session_id: file.sessionId, event_id: eventId });
        }
      }
    }

    // Update session counters
    const counters = this.sessionCounters.get(file.sessionId)!;
    counters.total++;
    if (event.risk_level === 'danger') counters.danger++;
    if (event.risk_level === 'warn') counters.warn++;

    // ── Agent tracking: register agent nodes and check authority ──
    if (event.agent_id) {
      const provider = this.sessionProvider.get(file.sessionId);
      upsertAgentNode({
        id: event.agent_id,
        session_id: file.sessionId,
        parent_id: null,
        provider: provider?.id || event.source_tool || 'unknown',
      });
      if (event.risk_level === 'danger') incrementAgentDanger(event.agent_id, file.sessionId);
      const actionTarget = event.command || event.file_paths?.[0] || event.summary || '';
      const authResult = checkAgentAuthority(event.agent_id, file.sessionId, { type: event.event_type, target: actionTarget });
      if (authResult) {
        broadcastSSE('authority-violation', { agent_id: event.agent_id, session_id: file.sessionId, event_type: event.event_type });
      }
    }

    // ── Auto-response evaluation ──
    try {
      const autoActions = evaluateAutoResponse({
        session_id: file.sessionId,
        event_id: eventId,
        event_type: event.event_type,
        risk_level: event.risk_level,
        danger_count: counters.danger,
      });
      for (const autoAction of autoActions) {
        broadcastSSE('auto-response', autoAction);
      }
    } catch {}

    // ── Plugin rules evaluation ──
    try {
      const pluginAlerts = evaluatePluginRules(event);
      for (const pa of pluginAlerts) {
        broadcastSSE('plugin-alert', { plugin: pa.plugin_id, rule: pa.rule_id, severity: pa.severity, message: pa.message, session_id: file.sessionId });
      }
    } catch {}

    // Periodically flush session stats
    if (counters.total % 10 === 0) {
      this.flushSession(file, counters);
    }
  }

  private flushSession(file: TranscriptFile, counters: { total: number; danger: number; warn: number }) {
    const provider = this.sessionProvider.get(file.sessionId);
    upsertSession({
      id: file.sessionId,
      workspace: file.workspace,
      project_name: file.projectName,
      started_at: '', // won't overwrite
      ended_at: null,
      total_events: counters.total,
      danger_count: counters.danger,
      warn_count: counters.warn,
      source_tool: provider?.id || 'unknown',
    });
  }

  /**
   * Extract the full untruncated prompt text from a user_message event.
   * The raw_log contains the original JSONL line from the transcript.
   * We parse it to get the full content without the 200-char summary truncation.
   */
  private extractFullPrompt(event: { summary: string; raw_log: string; source_tool: string }): string | null {
    // Try to parse the raw JSONL line for the full content
    if (event.raw_log) {
      try {
        const raw = JSON.parse(event.raw_log);
        // VS Code Copilot format
        if (raw.data?.content && typeof raw.data.content === 'string') {
          return raw.data.content;
        }
        // Claude Code format
        if (raw.message?.content) {
          if (typeof raw.message.content === 'string') return raw.message.content;
          if (Array.isArray(raw.message.content)) {
            const texts = raw.message.content
              .filter((c: Record<string, unknown>) => c.type === 'text' && c.text)
              .map((c: Record<string, unknown>) => c.text as string);
            if (texts.length > 0) return texts.join('\n');
          }
        }
        // Gemini CLI format
        if (raw.parts && Array.isArray(raw.parts)) {
          const texts = raw.parts
            .filter((p: Record<string, unknown>) => p.text)
            .map((p: Record<string, unknown>) => p.text as string);
          if (texts.length > 0) return texts.join('\n');
        }
        // Generic: content field
        if (typeof raw.content === 'string') return raw.content;
        if (Array.isArray(raw.content)) {
          const texts = raw.content
            .filter((c: Record<string, unknown>) => typeof c === 'string' || c?.text)
            .map((c: unknown) => typeof c === 'string' ? c : (c as Record<string, unknown>).text as string);
          if (texts.length > 0) return texts.join('\n');
        }
      } catch {
        // raw_log isn't valid JSON — fall through
      }
    }

    // Fallback: extract from summary (strip "User: " prefix and quotes)
    const summary = event.summary || '';
    const match = summary.match(/^User:\s*"(.+)"$/s);
    return match ? match[1] : (summary.replace(/^User:\s*/, '') || null);
  }

  stop() {
    if (this.sessionEndTimer) clearInterval(this.sessionEndTimer);
    this.tailer.stopAll();
  }
}
