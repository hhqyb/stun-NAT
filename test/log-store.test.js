import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { RotatingLogStore, MAX_LOG_BYTES, DEFAULT_LOG_FILE_BYTES } from '../lib/log-store.js';

function directory(t) {
  const value = fs.mkdtempSync(path.join(os.tmpdir(), 'stunmap-logs-'));
  t.after(() => fs.rmSync(value, { recursive: true, force: true }));
  return value;
}
function files(dir) { return fs.readdirSync(dir).filter((name) => name.includes('.log')); }
function total(dir) { return files(dir).reduce((sum, name) => sum + fs.statSync(path.join(dir, name)).size, 0); }

test('defaults to a shared 1 GiB budget and 16 MiB segments', (t) => {
  const store = new RotatingLogStore(directory(t));
  assert.equal(MAX_LOG_BYTES, 1073741824);
  assert.equal(store.maxTotalBytes, MAX_LOG_BYTES);
  assert.equal(store.maxFileBytes, DEFAULT_LOG_FILE_BYTES);
  assert.equal(store.maxFileBytes, 16777216);
});

test('rotates before crossing the segment limit and preserves complete records', (t) => {
  const dir = directory(t);
  const store = new RotatingLogStore(dir, { maxTotalBytes: 512, maxFileBytes: 64 });
  const line = `${'a'.repeat(31)}\n`;
  store.append('one', line); store.append('one', line);
  assert.deepEqual(files(dir), ['one.log']);
  store.append('one', 'latest\n');
  const archive = files(dir).find((name) => name.startsWith('one.log.'));
  assert.equal(fs.readFileSync(path.join(dir, archive), 'utf8'), line + line);
  assert.equal(fs.readFileSync(path.join(dir, 'one.log'), 'utf8'), 'latest\n');
  assert.equal(store.totalBytes, total(dir));
});

test('all rules share one ceiling and rotated history is evicted before active files', (t) => {
  const dir = directory(t);
  const store = new RotatingLogStore(dir, { maxTotalBytes: 192, maxFileBytes: 64 });
  store.append('first', 'a'.repeat(63));
  store.append('second', 'b'.repeat(63));
  store.append('first', 'c'.repeat(63));
  assert.equal(files(dir).length, 3);
  store.append('third', 'd'.repeat(63));
  assert.deepEqual(files(dir), ['first.log', 'second.log', 'third.log']);
  assert.equal(total(dir), 192);
  store.append('fourth', 'newest');
  assert.equal(fs.existsSync(path.join(dir, 'fourth.log')), true);
  assert.ok(total(dir) <= 192);
});

test('startup keeps bounded recent tails from oversized existing logs', (t) => {
  const dir = directory(t);
  const content = Array.from({ length: 100 }, (_, index) => `日志 ${index.toString().padStart(3, '0')}\n`).join('');
  fs.writeFileSync(path.join(dir, 'old.log'), content);
  fs.writeFileSync(path.join(dir, 'unrelated.txt'), 'leave this alone');
  const store = new RotatingLogStore(dir, { maxTotalBytes: 128, maxFileBytes: 64 });
  const retained = fs.readFileSync(path.join(dir, 'old.log'), 'utf8');
  assert.ok(content.endsWith(retained));
  assert.match(retained, /^日志 \d{3}\n/);
  assert.ok(retained.endsWith('日志 099\n'));
  assert.ok(Buffer.byteLength(retained) <= 128);
  assert.equal(fs.readFileSync(path.join(dir, 'unrelated.txt'), 'utf8'), 'leave this alone');
  store.append('old', 'newest after restart');
  assert.equal(store.totalBytes, total(dir));
  assert.ok(total(dir) <= 128);
});

test('startup prunes old archives across rules and enforces the total ceiling', (t) => {
  const dir = directory(t);
  for (const [name, age] of [['a.log.1-abcd', 1], ['b.log.2-abcd', 2], ['b.log', 3]]) {
    fs.writeFileSync(path.join(dir, name), 'x'.repeat(64));
    fs.utimesSync(path.join(dir, name), age, age);
  }
  const store = new RotatingLogStore(dir, { maxTotalBytes: 128, maxFileBytes: 64 });
  assert.deepEqual(files(dir), ['b.log', 'b.log.2-abcd']);
  store.append('b', 'next');
  assert.ok(total(dir) <= 128);
  assert.equal(store.totalBytes, total(dir));
});

test('one oversized UTF-8 record cannot defeat the cap or leave broken characters', (t) => {
  const dir = directory(t);
  const store = new RotatingLogStore(dir, { maxTotalBytes: 128, maxFileBytes: 64 });
  store.append('large', '2026-11-06T10:34:01.391+08:00 日志🙂'.repeat(100));
  const content = fs.readFileSync(path.join(dir, 'large.log'), 'utf8');
  assert.match(content, /日志过长，已截断/);
  assert.equal(content.includes('\ufffd'), false);
  assert.ok(total(dir) <= 64);
});

test('repeated cross-rule rotation and restart remain bounded', (t) => {
  const dir = directory(t);
  let store = new RotatingLogStore(dir, { maxTotalBytes: 300, maxFileBytes: 128 });
  for (let index = 0; index < 200; index++) {
    const name = `rule-${index % 7}`;
    const line = `entry-${index} ${'🙂'.repeat(index % 30)}`;
    store.append(name, line);
    assert.ok(total(dir) <= 300, `total at write ${index}`);
    assert.equal(store.totalBytes, total(dir));
    assert.ok(fs.readFileSync(path.join(dir, `${name}.log`), 'utf8').includes(`entry-${index} `));
    for (const file of files(dir)) assert.ok(fs.statSync(path.join(dir, file)).size <= 128);
    if (index % 17 === 0) store = new RotatingLogStore(dir, { maxTotalBytes: 300, maxFileBytes: 128 });
  }
});

test('rejects invalid limits and path-like rule IDs', (t) => {
  const dir = directory(t);
  for (const maxTotalBytes of [0, -1, NaN, Infinity, 1.5, MAX_LOG_BYTES + 1]) {
    assert.throws(() => new RotatingLogStore(dir, { maxTotalBytes }), /日志总上限/);
  }
  assert.throws(() => new RotatingLogStore(dir, { maxTotalBytes: 64, maxFileBytes: 65 }), /单个日志文件上限/);
  const store = new RotatingLogStore(dir);
  assert.throws(() => store.append('../outside', 'no'), /规则 ID/);
});


test('legacy files within the total budget are preserved and rotated on the next write', (t) => {
  const dir = directory(t);
  const content = 'existing history\n'.repeat(12);
  fs.writeFileSync(path.join(dir, 'legacy.log'), content);
  const store = new RotatingLogStore(dir, { maxTotalBytes: 512, maxFileBytes: 64 });
  assert.equal(fs.readFileSync(path.join(dir, 'legacy.log'), 'utf8'), content);
  store.append('legacy', 'new entry');
  const archive = files(dir).find((name) => name.startsWith('legacy.log.'));
  assert.equal(fs.readFileSync(path.join(dir, archive), 'utf8'), content);
  assert.equal(fs.readFileSync(path.join(dir, 'legacy.log'), 'utf8'), 'new entry\n');
  assert.ok(total(dir) <= 512);
});


test('startup tail copying handles overlapping multi-chunk files without corruption', (t) => {
  const dir = directory(t);
  const content = Array.from({ length: 12000 }, (_, index) => `行 ${index.toString().padStart(6, '0')} 🙂\n`).join('');
  const budget = Buffer.byteLength(content) - 1;
  fs.writeFileSync(path.join(dir, 'large.log'), content);
  const store = new RotatingLogStore(dir, { maxTotalBytes: budget, maxFileBytes: 128 });
  const retained = fs.readFileSync(path.join(dir, 'large.log'), 'utf8');
  assert.ok(content.endsWith(retained));
  assert.ok(retained.startsWith('行 000001 🙂\n'));
  assert.equal(retained.includes('\ufffd'), false);
  assert.ok(store.totalBytes <= budget);
  assert.equal(store.totalBytes, total(dir));
});
