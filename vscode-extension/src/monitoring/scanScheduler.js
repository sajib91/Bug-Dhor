'use strict';

/**
 * Small, dependency-free work scheduler for workspace-level scans.
 *
 * The scheduler coalesces repeated work by key, cancels superseded timers and
 * tokens, and bounds concurrency. It never reads source text itself and never
 * infers an author or model. Timers are injectable so scheduling behavior can
 * be tested deterministically.
 */

const { createCancellationTokenSource, isCancellation } = require('./realtimeMonitor');

const DEFAULT_DEBOUNCE_MS = 750;
const DEFAULT_MAX_CONCURRENT_SCANS = 2;
const MAX_RECORDED_TASKS = 25;

/**
 * @param {unknown} error
 * @returns {boolean}
 */
function isCancellationLike(error) {
  return isCancellation(error);
}

class ScanScheduler {
  /**
   * @param {{
   *   debounceMs?: number,
   *   maxConcurrentScans?: number,
   *   setTimer?: (callback: () => void, delay: number) => unknown,
   *   clearTimer?: (timer: unknown) => void
   * }} [options]
   */
  constructor(options = {}) {
    this.debounceMs = Number.isInteger(options.debounceMs)
      ? options.debounceMs
      : DEFAULT_DEBOUNCE_MS;
    this.maxConcurrentScans = Number.isInteger(options.maxConcurrentScans)
      ? options.maxConcurrentScans
      : DEFAULT_MAX_CONCURRENT_SCANS;
    this.setTimer =
      typeof options.setTimer === 'function'
        ? options.setTimer
        : (callback, delay) => setTimeout(callback, delay);
    this.clearTimer =
      typeof options.clearTimer === 'function'
        ? options.clearTimer
        : (timer) => clearTimeout(timer);

    /** @type {Map<string, { key: string, task: Function, generation: number, reason: string, ready: boolean, timer?: unknown }>} */
    this.queue = new Map();
    /** @type {Map<string, { key: string, task: Function, generation: number, reason: string, source: ReturnType<typeof createCancellationTokenSource> }>} */
    this.active = new Map();
    /** @type {Map<string, number>} */
    this.generations = new Map();
    /** @type {Array<object>} */
    this.history = [];

    this.stats = {
      scheduled: 0,
      completed: 0,
      cancelled: 0,
      failed: 0,
      duplicates: 0
    };
    this.disposed = false;
  }

  /**
   * @param {{ debounceMs?: number, maxConcurrentScans?: number }} settings
   */
  updateLimits(settings = {}) {
    if (Number.isInteger(settings.debounceMs)) {
      this.debounceMs = settings.debounceMs;
    }
    if (Number.isInteger(settings.maxConcurrentScans) && settings.maxConcurrentScans > 0) {
      this.maxConcurrentScans = settings.maxConcurrentScans;
    }
  }

  /**
   * Schedule one task per key. A newer task for the same key always replaces
   * the pending or in-flight task; obsolete results are ignored after they
   * settle.
   *
   * @param {string} key
   * @param {(context: { token: any, generation: number, reason: string }) => unknown} task
   * @param {{ immediate?: boolean, debounceMs?: number, reason?: string }} [options]
   */
  schedule(key, task, options = {}) {
    if (
      this.disposed ||
      typeof key !== 'string' ||
      key.length === 0 ||
      typeof task !== 'function'
    ) {
      return false;
    }

    const hadPending = this.queue.has(key) || this.active.has(key);
    this.cancel(key, 'superseded');
    if (hadPending) {
      this.stats.duplicates += 1;
    }

    const generation = (this.generations.get(key) ?? 0) + 1;
    this.generations.set(key, generation);
    const reason = typeof options.reason === 'string' ? options.reason : 'scheduled';
    const entry = { key, task, generation, reason, ready: options.immediate === true };
    this.stats.scheduled += 1;
    this.record({ key, generation, reason, status: 'scheduled' });

    if (options.immediate === true) {
      this.queue.set(key, entry);
      this.drain();
      return true;
    }

    const delay = Number.isInteger(options.debounceMs) ? options.debounceMs : this.debounceMs;
    entry.timer = this.setTimer(() => {
      entry.timer = undefined;
      if (this.queue.get(key) === entry) {
        entry.ready = true;
        this.drain();
      }
    }, delay);
    this.queue.set(key, entry);
    return true;
  }

  /**
   * Cancel pending and in-flight work for one key. Already published findings
   * are intentionally left untouched.
   *
   * @param {string} key
   * @param {string} [cause]
   */
  cancel(key, cause = 'cancelled') {
    const pending = this.queue.get(key);
    if (pending) {
      if (pending.timer !== undefined) {
        this.clearTimer(pending.timer);
      }
      this.queue.delete(key);
      this.stats.cancelled += 1;
      this.record({
        key,
        generation: pending.generation,
        reason: pending.reason,
        status: 'cancelled',
        cause
      });
    }

    const running = this.active.get(key);
    if (running) {
      running.source.cancel();
      this.active.delete(key);
      this.stats.cancelled += 1;
      this.record({
        key,
        generation: running.generation,
        reason: running.reason,
        status: 'cancelled',
        cause
      });
    }
  }

  /** @param {string} [cause] */
  cancelAll(cause = 'cancelled') {
    for (const key of [...new Set([...this.queue.keys(), ...this.active.keys()])]) {
      this.cancel(key, cause);
    }
  }

  /** Start as many queued tasks as the concurrency limit allows. */
  drain() {
    if (this.disposed) {
      return;
    }
    while (this.active.size < this.maxConcurrentScans && this.queue.size > 0) {
      const ready = [...this.queue.entries()].find(([, entry]) => entry.ready === true);
      if (!ready) {
        return;
      }
      const [key, entry] = ready;
      this.queue.delete(key);
      const source = createCancellationTokenSource();
      const running = { ...entry, source };
      this.active.set(key, running);
      void this.run(running);
    }
  }

  /** @param {{ key: string, task: Function, generation: number, reason: string, source: any }} entry */
  async run(entry) {
    try {
      const result = await Promise.resolve().then(() =>
        entry.task({
          token: entry.source.token,
          generation: entry.generation,
          reason: entry.reason
        })
      );
      if (this.generations.get(entry.key) !== entry.generation) {
        return;
      }
      this.stats.completed += 1;
      this.record({
        key: entry.key,
        generation: entry.generation,
        reason: entry.reason,
        status: 'completed',
        result
      });
    } catch (error) {
      if (isCancellationLike(error) || this.generations.get(entry.key) !== entry.generation) {
        return;
      }
      this.stats.failed += 1;
      this.record({
        key: entry.key,
        generation: entry.generation,
        reason: entry.reason,
        status: 'failed',
        detail: error instanceof Error ? error.message : String(error)
      });
    } finally {
      if (this.active.get(entry.key)?.generation === entry.generation) {
        this.active.delete(entry.key);
      }
      entry.source.dispose();
      this.drain();
    }
  }

  /** @param {object} entry */
  record(entry) {
    this.history.push({ ...entry, at: Date.now() });
    if (this.history.length > MAX_RECORDED_TASKS) {
      this.history.shift();
    }
  }

  /** Metadata-only observability. */
  getStats() {
    return {
      scheduled: this.stats.scheduled,
      completed: this.stats.completed,
      cancelled: this.stats.cancelled,
      failed: this.stats.failed,
      duplicates: this.stats.duplicates,
      pending: this.queue.size,
      inFlight: this.active.size,
      tasks: this.history.map((entry) => ({ ...entry }))
    };
  }

  dispose() {
    if (this.disposed) {
      return;
    }
    this.cancelAll('disposed');
    this.disposed = true;
  }
}

module.exports = { ScanScheduler, DEFAULT_DEBOUNCE_MS, DEFAULT_MAX_CONCURRENT_SCANS };
