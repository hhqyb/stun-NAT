import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { formatLogTime } from '../public/log-time.js';

test('formats UTC and existing offset timestamps in UTC+8 without shifting the instant', () => {
  for (const input of ['2026-11-06T02:34:01.391Z', '2026-11-06T10:34:01.391+08:00', '2026-11-05T18:34:01.391-08:00']) {
    assert.equal(formatLogTime(input), '2026-11-06T10:34:01.391+08:00');
    assert.equal(Date.parse(formatLogTime(input)), Date.parse(input));
  }
  assert.equal(formatLogTime('2026-12-31T20:00:00.000Z'), '2027-01-01T04:00:00.000+08:00');
  assert.equal(formatLogTime('invalid'), 'invalid');
  assert.equal(formatLogTime(null), '—');
});

test('formatting is independent of the server timezone and daylight saving', () => {
  for (const TZ of ['UTC', 'America/Los_Angeles', 'Asia/Shanghai']) {
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', "import { formatLogTime } from './public/log-time.js'; console.log(formatLogTime('2026-07-01T02:00:00.000Z'));"], { env: { ...process.env, TZ }, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), '2026-07-01T10:00:00.000+08:00');
  }
});
