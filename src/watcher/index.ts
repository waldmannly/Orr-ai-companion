import { Config, loadConfig } from '../config';
import { LogTailer } from './log-tailer';
import { SessionParserState } from '../parser';
import { classifyRisk, extractMemoryOp } from '../risk/classifier';
import { evaluateAlerts, persistAlerts } from '../alerts/engine';
import { initDb, upsertSession, insertEvent, insertMemoryOp, getSession } from '../storage/db';
import { SessionInfo } from '../parser/event-types';
import { LogProvider, TranscriptFile, getActiveProviders, createCustomProvider } from '../providers';

export class Watcher {
  private config: Config;
  private tailer: LogTailer;
  private sessionCounters = new Map<string, { total: number; danger: number; warn: number }>();
  private parserStates = new Map<string, SessionParserState>();
  private providers: LogProvider[] = [];
  /** Map sessionId → provider so we know which parser to use */
  private sessionProvider = new Map<string, LogProvider>();

  constructor(config?: Config) {
    this.config = config || loadConfig();
    this.tailer = new LogTailer();
  }

  start() {
    console.log('[watcher] Initializing database...');
    initDb();

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
    if (!event) return;

    // Skip turn_start/turn_end for storage (too noisy)
    if (event.event_type === 'turn_start' || event.event_type === 'turn_end') return;

    // Classify risk
    event.risk_level = classifyRisk(event, this.config);

    // Store event
    const eventId = insertEvent(event);
    event.id = eventId;

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
    this.tailer.stopAll();
  }
}
