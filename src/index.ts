#!/usr/bin/env node

import { loadConfig } from './config';
import { Watcher } from './watcher';
import { startDashboard } from './dashboard/server';

console.log('');
console.log('  ╔══════════════════════════════════════╗');
console.log('  ║   🛡  AL Companion Tracker           ║');
console.log('  ║   AI Agent Activity Monitor           ║');
console.log('  ╚══════════════════════════════════════╝');
console.log('');

const config = loadConfig();

// Start the watcher (ingests logs → SQLite)
const watcher = new Watcher(config);
watcher.start();

// Start the dashboard web server
startDashboard(config);

console.log('');
console.log(`[tracker] Dashboard: http://${config.dashboard.host}:${config.dashboard.port}`);
console.log('[tracker] Press Ctrl+C to stop');
console.log('');

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n[tracker] Shutting down...');
  watcher.stop();
  process.exit(0);
});

process.on('SIGTERM', () => {
  watcher.stop();
  process.exit(0);
});
