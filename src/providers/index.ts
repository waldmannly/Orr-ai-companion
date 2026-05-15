import { LogProvider } from './types';
import { VSCodeCopilotProvider } from './vscode-copilot';
import { ClaudeCodeProvider } from './claude-code';
import { GeminiCliProvider } from './gemini-cli';
import { GenericProvider } from './generic';

export { LogProvider, TranscriptFile } from './types';
export { SessionParserState } from '../parser';

/**
 * Returns all built-in providers.
 * Each provider auto-detects whether its tool is installed.
 */
export function getBuiltinProviders(): LogProvider[] {
  return [
    new VSCodeCopilotProvider(),
    new ClaudeCodeProvider(),
    new GeminiCliProvider(),
  ];
}

/**
 * Create a custom generic provider from user config.
 */
export function createCustomProvider(id: string, displayName: string, paths: string[], icon?: string): LogProvider {
  return new GenericProvider(id, displayName, paths, icon);
}

/**
 * Discover all active providers (built-in with logs + custom).
 * A provider is "active" if it has at least one log path that exists.
 */
export function getActiveProviders(customProviders?: LogProvider[]): LogProvider[] {
  const all = [...getBuiltinProviders(), ...(customProviders || [])];
  return all.filter(p => p.getDefaultLogPaths().length > 0);
}
