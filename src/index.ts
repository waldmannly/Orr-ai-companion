#!/usr/bin/env node

import { loadConfig } from './config';
import { Watcher } from './watcher';
import { startDashboard } from './dashboard/server';
import { runCli } from './cli';

const args = process.argv.slice(2);

// If any CLI subcommand is given, delegate to CLI handler
if (args.length > 0 && !args[0].startsWith('-')) {
  runCli(args);
} else {
  // Default: start the full tracker (watcher + dashboard)
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
}
