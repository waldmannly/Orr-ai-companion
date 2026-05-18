/**
 * Auto-Start — Register Orr to start automatically.
 * 
 * Supports:
 *   - Windows: Startup folder shortcut via VBScript
 *   - macOS: launchd plist in ~/Library/LaunchAgents
 *   - Linux: systemd user service in ~/.config/systemd/user
 * 
 * Usage: orr autostart [enable|disable|status]
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'child_process';

const SERVICE_NAME = 'orr-ai-companion';

export function setupAutoStart(action: 'enable' | 'disable' | 'status' = 'enable') {
  const platform = os.platform();

  switch (action) {
    case 'enable':
      if (platform === 'win32') enableWindows();
      else if (platform === 'darwin') enableMacOS();
      else enableLinux();
      break;
    case 'disable':
      if (platform === 'win32') disableWindows();
      else if (platform === 'darwin') disableMacOS();
      else disableLinux();
      break;
    case 'status':
      checkStatus(platform);
      break;
  }
}

// ── Windows ──

function getStartupDir(): string {
  return path.join(os.homedir(), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup');
}

function enableWindows() {
  const startupDir = getStartupDir();
  const vbsPath = path.join(startupDir, 'orr.vbs');
  const nodePath = process.execPath;
  const trackerPath = path.join(__dirname, '..', 'index.js');

  const vbs = `Set WshShell = CreateObject("WScript.Shell")
WshShell.Run """${nodePath}"" ""${trackerPath}""", 0, False
`;
  fs.writeFileSync(vbsPath, vbs);
  console.log(`  ✓ Auto-start enabled (Windows startup folder)`);
  console.log(`    ${vbsPath}\n`);
}

function disableWindows() {
  const vbsPath = path.join(getStartupDir(), 'orr.vbs');
  if (fs.existsSync(vbsPath)) {
    fs.unlinkSync(vbsPath);
    console.log('  ✓ Auto-start disabled\n');
  } else {
    console.log('  Auto-start was not enabled.\n');
  }
}

// ── macOS ──

function getLaunchAgentPath(): string {
  return path.join(os.homedir(), 'Library', 'LaunchAgents', `com.${SERVICE_NAME}.plist`);
}

function enableMacOS() {
  const plistPath = getLaunchAgentPath();
  const nodePath = process.execPath;
  const trackerPath = path.join(__dirname, '..', 'index.js');
  const logPath = path.join(os.homedir(), '.orr', 'daemon.log');

  const dir = path.dirname(logPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.${SERVICE_NAME}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${nodePath}</string>
    <string>${trackerPath}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><false/>
  <key>StandardOutPath</key><string>${logPath}</string>
  <key>StandardErrorPath</key><string>${logPath}</string>
</dict>
</plist>`;

  fs.writeFileSync(plistPath, plist);
  try { execSync(`launchctl load "${plistPath}"`); } catch { /* ignore */ }
  console.log(`  ✓ Auto-start enabled (launchd)`);
  console.log(`    ${plistPath}\n`);
}

function disableMacOS() {
  const plistPath = getLaunchAgentPath();
  if (fs.existsSync(plistPath)) {
    try { execSync(`launchctl unload "${plistPath}"`); } catch { /* ignore */ }
    fs.unlinkSync(plistPath);
    console.log('  ✓ Auto-start disabled\n');
  } else {
    console.log('  Auto-start was not enabled.\n');
  }
}

// ── Linux ──

function getSystemdServicePath(): string {
  return path.join(os.homedir(), '.config', 'systemd', 'user', `${SERVICE_NAME}.service`);
}

function enableLinux() {
  const servicePath = getSystemdServicePath();
  const dir = path.dirname(servicePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const nodePath = process.execPath;
  const trackerPath = path.join(__dirname, '..', 'index.js');

  const unit = `[Unit]
Description=Orr — AI Agent Activity Monitor
After=network.target

[Service]
Type=simple
ExecStart=${nodePath} ${trackerPath}
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
`;

  fs.writeFileSync(servicePath, unit);
  try {
    execSync('systemctl --user daemon-reload');
    execSync(`systemctl --user enable ${SERVICE_NAME}`);
    execSync(`systemctl --user start ${SERVICE_NAME}`);
  } catch { /* ignore */ }
  console.log(`  ✓ Auto-start enabled (systemd user service)`);
  console.log(`    ${servicePath}\n`);
}

function disableLinux() {
  const servicePath = getSystemdServicePath();
  try {
    execSync(`systemctl --user stop ${SERVICE_NAME}`);
    execSync(`systemctl --user disable ${SERVICE_NAME}`);
  } catch { /* ignore */ }
  if (fs.existsSync(servicePath)) {
    fs.unlinkSync(servicePath);
    console.log('  ✓ Auto-start disabled\n');
  } else {
    console.log('  Auto-start was not enabled.\n');
  }
}

// ── Status check ──

function checkStatus(platform: string) {
  let installed = false;

  if (platform === 'win32') {
    installed = fs.existsSync(path.join(getStartupDir(), 'orr.vbs'));
  } else if (platform === 'darwin') {
    installed = fs.existsSync(getLaunchAgentPath());
  } else {
    installed = fs.existsSync(getSystemdServicePath());
  }

  if (installed) {
    console.log('  ✓ Auto-start is enabled\n');
  } else {
    console.log('  ✗ Auto-start is not enabled\n');
    console.log('  Run: orr autostart enable\n');
  }
}
