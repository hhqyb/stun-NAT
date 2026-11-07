import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

let directory; let app; let port; let auth;

before(async () => {
  directory = await fs.mkdtemp(path.join(os.tmpdir(), 'stunmap-resilience-'));
  const reserve = http.createServer(); reserve.listen(0, '127.0.0.1'); await once(reserve, 'listening');
  port = reserve.address().port; await new Promise((resolve) => reserve.close(resolve));
  app = spawn(process.execPath, ['server.js'], { env: { ...process.env, PORT: String(port), STUNMAP_DATA_DIR: directory, NATMAP_BIN: '/does/not/exist', STUNMAP_ADMIN_PASSWORD: 'test-password' }, stdio: ['ignore', 'pipe', 'pipe'] });
  await once(app.stdout, 'data');
  auth = `Basic ${Buffer.from('admin:test-password').toString('base64')}`;
});

after(async () => {
  if (app.exitCode === null) { const exited = once(app, 'exit'); app.kill('SIGTERM'); await exited; }
  await fs.rm(directory, { recursive: true, force: true });
});

function request(route, options = {}) {
  return fetch(`http://127.0.0.1:${port}${route}`, { ...options, headers: { authorization: auth, 'content-type': 'application/json', ...(options.headers || {}) } });
}

test('backs up a corrupted rules file and keeps the console usable', async () => {
  await fs.writeFile(path.join(directory, 'rules.json'), '{ this is not json');
  const response = await request('/api/rules');
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.deepEqual(body.rules, []);
  assert.match(body.warning, /规则库损坏/);
  const files = await fs.readdir(directory);
  assert.ok(files.some((name) => name.startsWith('rules.json.corrupt-')));
});

test('serializes concurrent rule writes without losing any', async () => {
  const base = { enabled: false, protocol: 'tcp', stunServer: 'turn.cloudflare.com:3478', keepaliveServer: 'www.cloudflare.com:80', interval: 30, checkEvery: 10, mode: 'forward', targetHost: '192.168.1.20', targetPort: 443, routerMapping: 'none' };
  const responses = await Promise.all(Array.from({ length: 6 }, (_, index) => request('/api/rules', { method: 'POST', body: JSON.stringify({ ...base, name: `concurrent-${index}` }) })));
  assert.deepEqual(responses.map((response) => response.status), Array(6).fill(201));
  const { rules } = await (await request('/api/rules')).json();
  assert.deepEqual(rules.map((rule) => rule.name).sort(), ['concurrent-0', 'concurrent-1', 'concurrent-2', 'concurrent-3', 'concurrent-4', 'concurrent-5']);
});
