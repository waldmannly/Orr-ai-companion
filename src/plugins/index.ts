/**
 * Plugin System — custom rules, providers, and widgets via JS API.
 *
 * Plugins are plain JS/JSON files that register:
 *   - Detection rules (pattern → severity + message)
 *   - Custom event processors (transform events before storage)
 *   - Widget data providers (expose data to dashboard widgets)
 *
 * Plugins are loaded from a configurable directory and run in the same
 * process (no sandbox — trusted plugins only).
 */

import * as fs from 'fs';
import * as path from 'path';
import type { TrackerEvent, RiskLevel } from '../parser/event-types';

// ── Types ──

export interface PluginRule {
  id: string;
  name: string;
  description: string;
  /** What event types this rule applies to (empty = all) */
  eventTypes: string[];
  /** Pattern to match in event content (command, summary, file_paths) */
  pattern: string;
  /** Is the pattern a regex? */
  isRegex: boolean;
  severity: RiskLevel;
  message: string;
}

export interface PluginManifest {
  id: string;
  name: string;
  version: string;
  description: string;
  author: string;
  rules: PluginRule[];
  /** @deprecated Removed for security — use Worker threads for custom processors */
  processor?: never;
  /** Optional widget data config */
  widgets?: PluginWidget[];
}

export interface PluginWidget {
  id: string;
  name: string;
  /** SQL query to run for widget data */
  query: string;
  /** Display format: number, chart, table, list */
  format: 'number' | 'chart' | 'table' | 'list';
}

export interface LoadedPlugin {
  manifest: PluginManifest;
  compiledRules: Array<{
    rule: PluginRule;
    regex: RegExp | null;
  }>;
  loadedAt: string;
  filePath: string;
}

export interface PluginEvalResult {
  rule_id: string;
  plugin_id: string;
  severity: RiskLevel;
  message: string;
}

// ── Plugin Registry ──

const plugins = new Map<string, LoadedPlugin>();

/**
 * Load a plugin from a JSON manifest file.
 */
export function loadPlugin(filePath: string): LoadedPlugin {
  const raw = fs.readFileSync(filePath, 'utf-8');
  const manifest: PluginManifest = JSON.parse(raw);

  if (!manifest.id || !manifest.name) {
    throw new Error('Plugin manifest must have id and name');
  }

  // Compile regex patterns — with safety validation
  const compiledRules = (manifest.rules || []).map(rule => {
    let regex: RegExp | null = null;
    if (rule.isRegex) {
      // SECURITY: Reject overly complex regex patterns that could cause ReDoS
      if (rule.pattern.length > 500) throw new Error(`Plugin ${manifest.id}: regex pattern too long (max 500 chars)`);
      if (/(\+\+|\*\*|\{\d{3,}\})/.test(rule.pattern)) throw new Error(`Plugin ${manifest.id}: potentially dangerous regex pattern`);
      try {
        regex = new RegExp(rule.pattern, 'i');
      } catch (e) {
        throw new Error(`Plugin ${manifest.id}: invalid regex pattern in rule "${rule.name}"`);
      }
    }
    return { rule, regex };
  });

  const loaded: LoadedPlugin = {
    manifest,
    compiledRules,
    loadedAt: new Date().toISOString(),
    filePath,
  };

  plugins.set(manifest.id, loaded);
  return loaded;
}

/**
 * Load all plugins from a directory (*.plugin.json files).
 */
export function loadPluginsFromDirectory(dirPath: string): LoadedPlugin[] {
  if (!fs.existsSync(dirPath)) return [];
  const loaded: LoadedPlugin[] = [];
  const files = fs.readdirSync(dirPath).filter(f => f.endsWith('.plugin.json'));
  for (const file of files) {
    try {
      loaded.push(loadPlugin(path.join(dirPath, file)));
    } catch (err) {
      console.error(`[plugins] Failed to load ${file}:`, err);
    }
  }
  return loaded;
}

/**
 * Evaluate all loaded plugin rules against an event.
 */
export function evaluatePluginRules(event: TrackerEvent): PluginEvalResult[] {
  const results: PluginEvalResult[] = [];
  const searchText = [
    event.summary || '',
    event.command || '',
    ...(event.file_paths || []),
    event.raw_log || '',
  ].join(' ');

  for (const [, plugin] of plugins) {
    for (const { rule, regex } of plugin.compiledRules) {
      // Check event type filter
      if (rule.eventTypes.length > 0 && !rule.eventTypes.includes(event.event_type)) {
        continue;
      }

      // Check pattern
      let matched = false;
      if (regex) {
        matched = regex.test(searchText);
      } else {
        matched = searchText.toLowerCase().includes(rule.pattern.toLowerCase());
      }

      if (matched) {
        results.push({
          rule_id: rule.id,
          plugin_id: plugin.manifest.id,
          severity: rule.severity,
          message: rule.message,
        });
      }
    }
  }

  return results;
}

/** Get all loaded plugins */
export function getLoadedPlugins(): LoadedPlugin[] {
  return Array.from(plugins.values());
}

/** Get a specific plugin by ID */
export function getPlugin(id: string): LoadedPlugin | null {
  return plugins.get(id) || null;
}

/** Unload a plugin */
export function unloadPlugin(id: string): boolean {
  return plugins.delete(id);
}

/** Get all rules from all loaded plugins */
export function getAllPluginRules(): Array<PluginRule & { plugin_id: string }> {
  const rules: Array<PluginRule & { plugin_id: string }> = [];
  for (const [, plugin] of plugins) {
    for (const { rule } of plugin.compiledRules) {
      rules.push({ ...rule, plugin_id: plugin.manifest.id });
    }
  }
  return rules;
}

/** Execute a widget query safely (read-only) */
export function executeWidgetQuery(pluginId: string, widgetId: string, db: any): unknown {
  const plugin = plugins.get(pluginId);
  if (!plugin) return null;
  const widget = plugin.manifest.widgets?.find(w => w.id === widgetId);
  if (!widget) return null;

  // Only allow SELECT queries
  const trimmed = widget.query.trim().toUpperCase();
  if (!trimmed.startsWith('SELECT')) {
    throw new Error('Widget queries must be SELECT statements');
  }

  try {
    return db.prepare(widget.query).all();
  } catch (err) {
    return { error: String(err) };
  }
}

/** Reset all plugins — for testing */
export function _resetPlugins(): void {
  plugins.clear();
}
