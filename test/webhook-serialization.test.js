import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

let directory; let app; let port; let auth; let receiver; let starts; let active; let maxActive;

before(async () => {
  directory = await fs.mkdtemp(path.join(os.tmpdir(), 'stunmap-webhook-serial-'));
  const reserve = http.createServer(); reserve.listen(0, '127.0.0.1'); await once(reserve, 'listening');
  port = reserve.address().port; await new Promise((resolve) => reserve.close(resolve));
  const engine = path.join(directory, 'fake-engine.cjs');
  await fs.writeFile(engine, `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const target = path.join(process.env.STUNMAP_STATE_DIR, process.env.STUNMAP_RULE_ID + '.json');
function beat() {
  const now = new Date().toISOString();
  const state = { publicAddress: '203.0.113.10', publicPort: 40000, privateAddress: '127.0.0.1', privatePort: 40000, lastVerifiedAt: now, updatedAt: now, mappingChangedAt: '2026-01-01T00:00:00.000Z' };
  fs.writeFileSync(target + '.tmp', JSON.stringify(state));
  fs.renameSync(target + '.tmp', target);
}
beat();
setInterval(beat, 200);
`, { mode: 0o755 });
  starts = []; active = 0; maxActive = 0;
  receiver = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      starts.push(Date.now()); active++; maxActive = Math.max(maxActive, active);
      setTimeout(() => { active--; res.writeHead(200, { 'content-type': 'text/plain' }); res.end('ok'); }, 30);
    });
  });
  receiver.listen(0, '127.0.0.1'); await once(receiver, 'listening');
  app = spawn(process.execPath, ['server.js'], { env: { ...process.env, PORT: String(port), STUNMAP_DATA_DIR: directory, NATMAP_BIN: engine, STUNMAP_ADMIN_PASSWORD: 'test-password', STUNMAP_WEBHOOK_GAP_MS: '50' }, stdio: ['ignore', 'pipe', 'pipe'] });
  await once(app.stdout, 'data');
  auth = `Basic ${Buffer.from('admin:test-password').toString('base64')}`;
});

after(async () => {
  if (app.exitCode === null) { const exited = once(app, 'exit'); app.kill('SIGTERM'); await exited; }
  receiver.closeAllConnections(); await new Promise((resolve) => receiver.close(resolve));
  await fs.rm(directory, { recursive: true, force: true });
});

test('webhooks from concurrent rules are serialized with a minimum gap', async () => {
  const webhookUrl = `http://127.0.0.1:${receiver.address().port}/hook`;
  const base = { enabled: true, protocol: 'tcp', stunServer: 'turn.cloudflare.com:3478', keepaliveServer: 'www.cloudflare.com:80', interval: 10, checkEvery: 1, mode: 'forward', targetHost: '127.0.0.1', targetPort: 8080, routerMapping: 'none', webhookUrl, webhookMethod: 'post' };
  for (let index = 0; index < 3; index++) {
    const response = await fetch(`http://127.0.0.1:${port}/api/rules`, { method: 'POST', headers: { authorization: auth, 'content-type': 'application/json' }, body: JSON.stringify({ ...base, name: `serial-${index}` }) });
    assert.equal(response.status, 201);
  }
  const deadline = Date.now() + 6000;
  while (starts.length < 3 && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(starts.length, 3);
  assert.equal(maxActive, 1);
  assert.ok(starts[1] - starts[0] >= 35, `gap ${starts[1] - starts[0]}ms`);
  assert.ok(starts[2] - starts[1] >= 35, `gap ${starts[2] - starts[1]}ms`);
});
