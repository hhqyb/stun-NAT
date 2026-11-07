import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createWebhookQueue } from '../lib/webhook-queue.js';

test('webhook queue runs tasks one at a time with the configured gap', async () => {
  let fakeNow = 0; const sleeps = []; const starts = []; let active = 0; let maxActive = 0;
  const enqueue = createWebhookQueue({ minGapMs: 100, now: () => fakeNow, sleep: async (ms) => { sleeps.push(ms); fakeNow += ms; } });
  await Promise.all([0, 1, 2].map((index) => enqueue(async () => {
    active++; maxActive = Math.max(maxActive, active);
    starts.push(fakeNow); fakeNow += 10;
    active--;
    return index;
  })));
  assert.deepEqual(starts, [0, 100, 200]);
  assert.deepEqual(sleeps, [90, 90]);
  assert.equal(maxActive, 1);
});

test('webhook queue keeps ordering and survives failed tasks', async () => {
  const events = [];
  const enqueue = createWebhookQueue({ minGapMs: 0 });
  const failed = enqueue(async () => { events.push('fail'); throw new Error('boom'); });
  const next = enqueue(async () => { events.push('next'); return 1; });
  await assert.rejects(failed, /boom/);
  assert.equal(await next, 1);
  assert.deepEqual(events, ['fail', 'next']);
});
