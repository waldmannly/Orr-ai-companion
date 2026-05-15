import { TrackerEvent, Alert, RiskLevel } from '../parser/event-types';
import { Config } from '../config';
import { isSensitiveFile, detectInjectionPatterns } from '../risk/classifier';
import { insertAlert } from '../storage/db';

export function evaluateAlerts(event: TrackerEvent, config: Config): Alert[] {
  const alerts: Alert[] = [];

  // Dangerous commands
  if (event.command) {
    for (const pattern of config.dangerousCommands) {
      if (event.command.toLowerCase().includes(pattern.toLowerCase())) {
        alerts.push(makeAlert(event, 'destructive_command', 'danger',
          `Destructive command detected: ${event.command.substring(0, 120)}`));
        break;
      }
    }
    // Force push
    if (/git\s+push\s+.*--force|git\s+push\s+-f\b/.test(event.command)) {
      alerts.push(makeAlert(event, 'force_push', 'danger',
        `Force push detected: ${event.command.substring(0, 120)}`));
    }
  }

  // Sensitive file access
  for (const fp of event.file_paths) {
    if (isSensitiveFile(fp, config)) {
      alerts.push(makeAlert(event, 'sensitive_file', 'warn',
        `Sensitive file accessed: ${fp.split(/[/\\]/).pop()}`));
    }
  }

  // Memory writes
  if (event.event_type === 'memory_write' && event.parameters) {
    const content = (event.parameters.file_text as string) || (event.parameters.insert_text as string) || (event.parameters.new_str as string) || '';
    if (detectInjectionPatterns(content)) {
      alerts.push(makeAlert(event, 'memory_injection', 'danger',
        `Memory write contains suspicious instruction-like content`));
    } else if (content.length > 0) {
      alerts.push(makeAlert(event, 'memory_write', 'warn',
        `Memory write to ${(event.parameters.path as string) || 'unknown path'}`));
    }
  }

  // Memory delete
  if (event.event_type === 'memory_delete') {
    alerts.push(makeAlert(event, 'memory_delete', 'warn',
      `Memory entry deleted: ${(event.parameters?.path as string) || 'unknown'}`));
  }

  // Web fetch to unusual domain
  if (event.event_type === 'web_fetch' && event.parameters) {
    const urls = (event.parameters.urls as string[]) || [event.parameters.url as string].filter(Boolean);
    for (const url of urls) {
      if (url && /pastebin|hastebin|ghostbin|rentry/i.test(url)) {
        alerts.push(makeAlert(event, 'suspicious_fetch', 'warn',
          `Fetch to paste service: ${url.substring(0, 80)}`));
      }
    }
  }

  return alerts;
}

export function persistAlerts(alerts: Alert[]) {
  for (const alert of alerts) {
    insertAlert(alert);
  }
}

function makeAlert(event: TrackerEvent, alertType: string, severity: RiskLevel, message: string): Alert {
  return {
    event_id: event.id || null,
    session_id: event.session_id,
    timestamp: event.timestamp,
    alert_type: alertType,
    severity,
    message,
    acknowledged: false,
  };
}
