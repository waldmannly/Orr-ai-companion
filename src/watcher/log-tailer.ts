import * as fs from 'fs';
import * as readline from 'readline';
import { EventEmitter } from 'events';
import { TranscriptFile } from '../providers/types';

// Tails a JSONL transcript file, emitting new lines as they are appended.

export class LogTailer extends EventEmitter {
  private watchers = new Map<string, fs.FSWatcher>();
  private offsets = new Map<string, number>();
  private files = new Map<string, TranscriptFile>();

  /** Start tailing a transcript file. Processes existing content then watches for appends. */
  async startTailing(file: TranscriptFile) {
    if (this.watchers.has(file.filePath)) return; // Already tailing

    this.files.set(file.filePath, file);
    this.offsets.set(file.filePath, 0);

    // Process existing content
    await this.readNewLines(file.filePath);

    // Watch for changes
    try {
      const watcher = fs.watch(file.filePath, () => {
        this.readNewLines(file.filePath);
      });
      this.watchers.set(file.filePath, watcher);
    } catch {
      // File might have been deleted
    }
  }

  /** Stop tailing a specific file */
  stopTailing(filePath: string) {
    const watcher = this.watchers.get(filePath);
    if (watcher) {
      watcher.close();
      this.watchers.delete(filePath);
    }
    this.offsets.delete(filePath);
    this.files.delete(filePath);
  }

  /** Stop all tailing */
  stopAll() {
    for (const [fp] of this.watchers) {
      this.stopTailing(fp);
    }
  }

  get tailedFileCount(): number {
    return this.watchers.size;
  }

  private async readNewLines(filePath: string) {
    const file = this.files.get(filePath);
    if (!file) return;

    const offset = this.offsets.get(filePath) || 0;

    let stat: fs.Stats;
    try {
      stat = fs.statSync(filePath);
    } catch {
      return; // File gone
    }

    if (stat.size <= offset) return; // No new data

    const stream = fs.createReadStream(filePath, {
      start: offset,
      encoding: 'utf-8',
    });

    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

    let newOffset = offset;
    for await (const line of rl) {
      if (line.trim()) {
        this.emit('line', line.trim(), file);
        newOffset += Buffer.byteLength(line + '\n', 'utf-8');
      }
    }

    // Update offset to end of file
    this.offsets.set(filePath, stat.size);
  }
}
