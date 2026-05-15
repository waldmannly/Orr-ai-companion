import * as path from 'path';
import * as fs from 'fs';

export interface Config {
  watchPaths: string[];
  sensitiveFiles: {
    patterns: string[];
    exactPaths: string[];
  };
  dangerousCommands: string[];
  alerts: {
    desktopNotifications: boolean;
    minSeverity: string;
  };
  dashboard: {
    port: number;
    host: string;
  };
  retention: {
    maxAgeDays: number;
    maxDbSizeMB: number;
  };
  customProviders: Array<{
    id: string;
    name: string;
    paths: string[];
    icon?: string;
  }>;
}

const DEFAULTS: Config = {
  watchPaths: [],
  sensitiveFiles: {
    patterns: ['**/.env*', '**/*.pem', '**/*.key', '**/id_rsa*', '**/credentials*', '**/secrets*', '**/personal/**', '**/private/**'],
    exactPaths: [],
  },
  dangerousCommands: [
    'rm -rf', 'git push --force', 'git push -f', 'git reset --hard',
    'DROP TABLE', 'DROP DATABASE', 'format C:', 'del /f /s /q',
    'Remove-Item -Recurse -Force', 'rmdir /s /q',
  ],
  alerts: { desktopNotifications: false, minSeverity: 'warn' },
  dashboard: { port: 3847, host: '127.0.0.1' },
  retention: { maxAgeDays: 90, maxDbSizeMB: 500 },
  customProviders: [],
};

export function loadConfig(): Config {
  const configPath = path.join(process.cwd(), 'config.json');
  if (fs.existsSync(configPath)) {
    try {
      const raw = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
      return { ...DEFAULTS, ...raw, sensitiveFiles: { ...DEFAULTS.sensitiveFiles, ...raw.sensitiveFiles }, alerts: { ...DEFAULTS.alerts, ...raw.alerts }, dashboard: { ...DEFAULTS.dashboard, ...raw.dashboard }, retention: { ...DEFAULTS.retention, ...raw.retention } };
    } catch {
      console.warn('[config] Failed to parse config.json, using defaults');
    }
  }
  return DEFAULTS;
}
