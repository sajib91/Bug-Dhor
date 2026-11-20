'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { ScanScheduler } = require('../../src/monitoring/scanScheduler');

function createTimers() {
  const timers = new Map();
  let nextId = 1;
  return {
    setTimer(callback, delay) {
      const id = nextId;
      nextId += 1;
      timers.set(id, { callback, delay });
      return id;
    },
    clearTimer(id) {
      timers.delete(id);
    },
    get pending() {
      return timers.size;
    },
    fireNext() {
      const entry = timers.entries().next().value;
      assert.ok(entry, 'expected a pending timer');
      timers.delete(entry[0]);
      entry[1].callback();
      return entry[1].delay;
    }
  };
}

const flush = () => new Promise((resolve) => setImmediate(resolve));

test('coalesces repeated work by key and runs only the newest task', async () => {
  const timers = createTimers();
  const scheduler = new ScanScheduler({ setTimer: timers.setTimer, clearTimer: timers.clearTimer });
  const calls = [];

  scheduler.schedule('workspace', (context) => calls.push(context.generation), {
    debounceMs: 500
  });
  scheduler.schedule('workspace', (context) => calls.push(context.generation), {
    debounceMs: 100
  });

  assert.equal(timers.pending, 1);
  assert.equal(scheduler.getStats().scheduled, 2);
  assert.equal(scheduler.getStats().duplicates, 1);
  assert.equal(scheduler.getStats().cancelled, 1);

  assert.equal(timers.fireNext(), 100);
  await flush();
  assert.deepEqual(calls, [2]);
  assert.equal(scheduler.getStats().completed, 1);
});

test('honors the concurrency limit and drains queued work', async () => {
  const timers = createTimers();
  const scheduler = new ScanScheduler({
    maxConcurrentScans: 1,
    setTimer: timers.setTimer,
    clearTimer: timers.clearTimer
  });
  const calls = [];
  const resolvers = [];

  scheduler.schedule(
    'a',
    () => {
      calls.push('a');
      return new Promise((resolve) => resolvers.push(resolve));
    },
    { immediate: true, reason: 'first' }
  );
  scheduler.schedule(
    'b',
    () => {
      calls.push('b');
      return new Promise((resolve) => resolvers.push(resolve));
    },
    { immediate: true, reason: 'second' }
  );

  await flush();
  assert.deepEqual(calls, ['a']);
  assert.equal(scheduler.getStats().inFlight, 1);
  assert.equal(scheduler.getStats().pending, 1);

  resolvers[0]('done');
  await flush();
  assert.deepEqual(calls, ['a', 'b']);
  resolvers[1]('done');
  await flush();
  assert.equal(scheduler.getStats().completed, 2);
  assert.equal(scheduler.getStats().inFlight, 0);
});

test('cancels an in-flight task and ignores its obsolete result', async () => {
  const timers = createTimers();
  const scheduler = new ScanScheduler({ setTimer: timers.setTimer, clearTimer: timers.clearTimer });
  const calls = [];

  scheduler.schedule(
    'workspace',
    ({ token }) => {
      calls.push('first');
      return new Promise((resolve, reject) => {
        token.onCancellationRequested(() => {
          reject(Object.assign(new Error('cancelled'), { name: 'AbortError' }));
        });
      });
    },
    { immediate: true }
  );

  await flush();
  scheduler.schedule('workspace', () => calls.push('second'), { debounceMs: 200 });
  await flush();

  assert.equal(scheduler.getStats().cancelled, 1);
  assert.equal(scheduler.getStats().failed, 0);
  assert.equal(scheduler.getStats().completed, 0);

  timers.fireNext();
  await flush();
  assert.deepEqual(calls, ['first', 'second']);
  assert.equal(scheduler.getStats().completed, 1);
});

test('records failures but treats cancellation as an expected outcome', async () => {
  const timers = createTimers();
  const scheduler = new ScanScheduler({ setTimer: timers.setTimer, clearTimer: timers.clearTimer });

  scheduler.schedule(
    'failing',
    () => {
      throw new Error('backend unreachable');
    },
    { immediate: true }
  );
  await flush();
  assert.equal(scheduler.getStats().failed, 1);

  scheduler.schedule(
    'cancelled',
    ({ token }) =>
      new Promise((resolve, reject) => {
        token.onCancellationRequested(() =>
          reject(Object.assign(new Error('cancelled'), { code: 'E_CANCELLED' }))
        );
      }),
    { immediate: true }
  );
  await flush();
  scheduler.cancel('cancelled', 'test cancellation');
  await flush();

  assert.equal(scheduler.getStats().failed, 1);
  assert.equal(scheduler.getStats().cancelled, 1);
});

test('dispose clears pending timers and prevents new work', () => {
  const timers = createTimers();
  const scheduler = new ScanScheduler({ setTimer: timers.setTimer, clearTimer: timers.clearTimer });
  scheduler.schedule('workspace', () => {}, { debounceMs: 100 });
  assert.equal(timers.pending, 1);

  scheduler.dispose();
  assert.equal(timers.pending, 0);
  assert.equal(scheduler.getStats().pending, 0);
  assert.equal(
    scheduler.schedule('workspace', () => {}),
    false
  );
});
