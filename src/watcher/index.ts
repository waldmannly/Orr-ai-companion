import { Config, loadConfig } from '../config';
import { LogTailer } from './log-tailer';
import { SessionParserState } from '../parser';
import { classifyRiskWithReasons, extractMemoryOp } from '../risk/classifier';
import { evaluateAlerts, persistAlerts } from '../alerts/engine';
import { initDb, upsertSession, insertEvent, insertMemoryOp, getSession, markSessionEnded, enforceRetention, insertAlert, getRecentSessionAlertBurst } from '../storage/db';
import { SessionInfo } from '../parser/event-types';
import { LogProvider, TranscriptFile, getActiveProviders, createCustomProvider } from '../providers';
import { broadcastSSE } from '../dashboard/server';

export class Watcher {
  private config: Config;
  private tailer: LogTailer;
  private sessionCounters = new Map<string, { total: number; danger: number; warn: number }>();
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
    }

    if (!this.sessionCounters.has(file.sessionId)) {
      this.sessionCounters.set(file.sessionId, { total: 0, danger: 0, warn: 0 });
    }

    if (!this.parserStates.has(file.sessionId)) {
      this.parserStates.set(file.sessionId, new SessionParserState());
    }

    this.tailer.startTailing(file);
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

    // Store event
    const eventId = insertEvent(event);
    event.id = eventId;

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
      // Broadcast alert to SSE
      for (const a of alerts) {
        broadcastSSE('alert', { severity: a.severity, message: a.message, session_id: a.session_id, event_id: eventId });
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

  stop() {
    if (this.sessionEndTimer) clearInterval(this.sessionEndTimer);
    this.tailer.stopAll();
  }
}
