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
  directory = await fs.mkdtemp(path.join(os.tmpdir(), 'stunmap-hot-reload-'));
  const reserve = http.createServer(); reserve.listen(0, '127.0.0.1'); await once(reserve, 'listening');
  port = reserve.address().port; await new Promise((resolve) => reserve.close(resolve));
  const engine = path.join(directory, 'fake-engine.cjs');
  await fs.writeFile(engine, `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
fs.appendFileSync(path.join(process.env.STUNMAP_STATE_DIR, 'starts.log'), process.pid + '\\n');
const target = path.join(process.env.STUNMAP_STATE_DIR, process.env.STUNMAP_RULE_ID + '.json');
function beat() {
  const now = new Date().toISOString();
  fs.writeFileSync(target + '.tmp', JSON.stringify({ publicAddress: '203.0.113.9', publicPort: 41000, privateAddress: '127.0.0.1', privatePort: 41000, lastVerifiedAt: now, updatedAt: now }));
  fs.renameSync(target + '.tmp', target);
}
beat();
setInterval(beat, 200);
`, { mode: 0o755 });
  app = spawn(process.execPath, ['server.js'], { env: { ...process.env, PORT: String(port), STUNMAP_DATA_DIR: directory, NATMAP_BIN: engine, STUNMAP_ADMIN_PASSWORD: 'test-password' }, stdio: ['ignore', 'pipe', 'pipe'] });
  await once(app.stdout, 'data');
  auth = `Basic ${Buffer.from('admin:test-password').toString('base64')}`;
});

after(async () => {
  if (app.exitCode === null) { const exited = once(app, 'exit'); app.kill('SIGTERM'); await exited; }
  await fs.rm(directory, { recursive: true, force: true });
});

async function request(route, options = {}) {
  return fetch(`http://127.0.0.1:${port}${route}`, { ...options, headers: { authorization: auth, 'content-type': 'application/json', ...(options.headers || {}) } });
}

async function starts() {
  try { return (await fs.readFile(path.join(directory, 'state', 'starts.log'), 'utf8')).trim().split('\n').filter(Boolean); } catch { return []; }
}

async function snapshot(id) {
  const { rules } = await (await request('/api/rules')).json();
  return rules.find((rule) => rule.id === id);
}

async function waitFor(check, timeout = 6000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error('condition did not become true');
}

test('non-runtime edits keep the NATMap channel alive; target changes restart it', async () => {
  const created = await request('/api/rules', {
    method: 'POST',
    body: JSON.stringify({ name: 'hot', enabled: true, protocol: 'tcp', mode: 'forward', targetHost: '127.0.0.1', targetPort: 8080, routerMapping: 'none' })
  });
  assert.equal(created.status, 201);
  const { rule } = await created.json();
  await waitFor(async () => (await starts()).length === 1);
  await waitFor(async () => (await snapshot(rule.id))?.running === true);

  const renamed = await request(`/api/rules/${rule.id}`, {
    method: 'PUT',
    body: JSON.stringify({ name: 'hot-renamed', webhookUrl: 'https://example.com/hook', webhookMethod: 'post', webhookBody: '{"name":"{{STUN_RULE_NAME}}"}' })
  });
  assert.equal(renamed.status, 200);
  await new Promise((resolve) => setTimeout(resolve, 1400));
  assert.equal((await starts()).length, 1);
  const hot = await snapshot(rule.id);
  assert.equal(hot.running, true);
  assert.equal(hot.name, 'hot-renamed');

  const retargeted = await request(`/api/rules/${rule.id}`, { method: 'PUT', body: JSON.stringify({ targetPort: 8081 }) });
  assert.equal(retargeted.status, 200);
  await waitFor(async () => (await starts()).length === 2);
});
