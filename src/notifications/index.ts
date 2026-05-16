import { Alert } from '../parser/event-types';
import { loadConfig, type NotificationsConfig, type WebhookConfig } from '../config';

// ── Notification dispatch ──

export async function dispatchAlertNotifications(alert: Alert): Promise<void> {
  const cfg = loadConfig().notifications;
  if (!cfg) return;

  const promises: Promise<void>[] = [];

  if (shouldNotify(cfg.slack, alert.severity)) {
    promises.push(sendSlack(cfg.slack, alert));
  }
  if (shouldNotify(cfg.webhook, alert.severity)) {
    promises.push(sendWebhook(cfg.webhook, alert));
  }
  if (cfg.teams && shouldNotify(cfg.teams, alert.severity)) {
    promises.push(sendTeams(cfg.teams, alert));
  }

  if (promises.length > 0) {
    await Promise.allSettled(promises);
  }
}

function shouldNotify(channel: WebhookConfig, severity: string): boolean {
  if (!channel.enabled || !channel.url) return false;
  const levels = ['watch', 'warn', 'danger'];
  return levels.indexOf(severity) >= levels.indexOf(channel.minSeverity);
}

async function sendSlack(cfg: WebhookConfig, alert: Alert): Promise<void> {
  const color = alert.severity === 'danger' ? '#e74c3c' : alert.severity === 'warn' ? '#f39c12' : '#3498db';
  const payload = {
    attachments: [{
      color,
      title: `[${alert.severity.toUpperCase()}] ${alert.alert_type}`,
      text: alert.message,
      fields: [
        { title: 'Session', value: alert.session_id.slice(0, 12), short: true },
        { title: 'Time', value: new Date(alert.timestamp).toLocaleString(), short: true },
      ],
      footer: 'AI Companion Tracker',
    }],
  };

  try {
    const resp = await fetch(cfg.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(5000),
    });
    if (!resp.ok) {
      console.warn(`[notifications] Slack webhook failed: ${resp.status}`);
    }
  } catch (err) {
    console.warn(`[notifications] Slack webhook error:`, err);
  }
}

async function sendWebhook(cfg: WebhookConfig, alert: Alert): Promise<void> {
  const payload = {
    event: 'alert',
    severity: alert.severity,
    type: alert.alert_type,
    message: alert.message,
    session_id: alert.session_id,
    timestamp: alert.timestamp,
    event_id: alert.event_id,
  };

  try {
    const resp = await fetch(cfg.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(5000),
    });
    if (!resp.ok) {
      console.warn(`[notifications] Webhook failed: ${resp.status}`);
    }
  } catch (err) {
    console.warn(`[notifications] Webhook error:`, err);
  }
}

async function sendTeams(cfg: WebhookConfig, alert: Alert): Promise<void> {
  const color = alert.severity === 'danger' ? 'attention' : alert.severity === 'warn' ? 'warning' : 'accent';
  const payload = {
    type: 'message',
    attachments: [{
      contentType: 'application/vnd.microsoft.card.adaptive',
      content: {
        $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
        type: 'AdaptiveCard',
        version: '1.4',
        body: [
          {
            type: 'TextBlock',
            size: 'medium',
            weight: 'bolder',
            color,
            text: `[${alert.severity.toUpperCase()}] ${alert.alert_type}`,
          },
          {
            type: 'TextBlock',
            text: alert.message,
            wrap: true,
          },
          {
            type: 'ColumnSet',
            columns: [
              { type: 'Column', width: 'auto', items: [{ type: 'TextBlock', text: 'Session', weight: 'bolder', size: 'small' }, { type: 'TextBlock', text: alert.session_id.slice(0, 12), size: 'small' }] },
              { type: 'Column', width: 'auto', items: [{ type: 'TextBlock', text: 'Time', weight: 'bolder', size: 'small' }, { type: 'TextBlock', text: new Date(alert.timestamp).toLocaleString(), size: 'small' }] },
            ],
          },
        ],
      },
    }],
  };

  try {
    const resp = await fetch(cfg.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(5000),
    });
    if (!resp.ok) {
      console.warn(`[notifications] Teams webhook failed: ${resp.status}`);
    }
  } catch (err) {
    console.warn(`[notifications] Teams webhook error:`, err);
  }
}

export async function testWebhook(type: 'slack' | 'webhook' | 'teams'): Promise<{ ok: boolean; error?: string }> {
  const cfg = loadConfig().notifications;
  const channel = type === 'slack' ? cfg.slack : type === 'teams' ? cfg.teams : cfg.webhook;
  if (!channel.url) return { ok: false, error: 'No URL configured' };

  const testAlert: Alert = {
    event_id: null,
    session_id: 'test-session',
    timestamp: new Date().toISOString(),
    alert_type: 'test',
    severity: 'watch',
    message: 'Test notification from AI Companion Tracker',
    acknowledged: false,
  };

  try {
    if (type === 'slack') {
      await sendSlack(channel, testAlert);
    } else if (type === 'teams') {
      await sendTeams(channel, testAlert);
    } else {
      await sendWebhook(channel, testAlert);
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}
