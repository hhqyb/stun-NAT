import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { test } from 'node:test';

async function waitFor(check, timeout = 5000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { const value = await check(); if (value) return value; await delay(30); }
  throw new Error('condition did not become true');
}

test('stopping and editing a rule cancels in-flight checks without stale failures or false crash logs', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'stunmap-lifecycle-'));
  let webhookCalls = 0; let webhookAborted = false;
  const webhook = http.createServer((req, res) => {
    webhookCalls++; req.resume(); res.on('close', () => { webhookAborted = true; });
    // Intentionally leave the response pending, like an unresponsive webhook service.
  });
  webhook.listen(0, '127.0.0.1'); await once(webhook, 'listening');
  const reserve = http.createServer(); reserve.listen(0, '127.0.0.1'); await once(reserve, 'listening');
  const port = reserve.address().port; await new Promise((resolve) => reserve.close(resolve));
  const engine = path.join(directory, 'fake-engine.cjs');
  await fs.writeFile(engine, `#!${process.execPath}\nconst fs = require('node:fs'); const path = require('node:path');\nfunction beat() { const now = new Date().toISOString(); const target = path.join(process.env.STUNMAP_STATE_DIR, process.env.STUNMAP_RULE_ID + '.json'); const state = { publicAddress: '203.0.113.1', publicPort: 14170, privateAddress: '127.0.0.1', privatePort: 40000, lastVerifiedAt: now, updatedAt: now, mappingChangedAt: '2026-01-01T00:00:00.000Z' }; fs.writeFileSync(target + '.tmp', JSON.stringify(state)); fs.renameSync(target + '.tmp', target); } beat(); setInterval(beat, 100);\n`, { mode: 0o755 });
  const app = spawn(process.execPath, ['server.js'], { env: { ...process.env, PORT: String(port), STUNMAP_DATA_DIR: directory, NATMAP_BIN: engine, STUNMAP_ADMIN_PASSWORD: 'test-password' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = ''; app.stderr.on('data', (chunk) => { stderr += chunk; });
  t.after(async () => {
    if (app.exitCode === null) { const exited = once(app, 'exit'); app.kill('SIGTERM'); await exited; }
    webhook.closeAllConnections(); await new Promise((resolve) => webhook.close(resolve));
    await fs.rm(directory, { recursive: true, force: true });
  });
  await once(app.stdout, 'data');
  const api = async (route, options = {}) => {
    const response = await fetch(`http://127.0.0.1:${port}${route}`, { ...options, headers: { authorization: `Basic ${Buffer.from('admin:test-password').toString('base64')}`, 'content-type': 'application/json' } });
    assert.ok(response.ok, await response.clone().text()); return response.json();
  };
  const { rule } = await api('/api/rules', { method: 'POST', body: JSON.stringify({ name: 'lifecycle', enabled: true, protocol: 'tcp', mode: 'forward', targetHost: '127.0.0.1', targetPort: 12345, routerMapping: 'none', webhookUrl: `http://127.0.0.1:${webhook.address().port}/hook` }) });
  await waitFor(() => webhookCalls === 1);
  await api(`/api/rules/${rule.id}/stop`, { method: 'POST' });
  await waitFor(() => webhookAborted);
  await delay(1200);
  let snapshot = (await api('/api/rules')).rules[0];
  assert.equal(snapshot.running, false); assert.equal(snapshot.health.local, 'stopped');
  assert.equal(webhookCalls, 1); assert.equal(snapshot.logs.some((log) => log.message.includes('Webhook 调用失败')), false);
  assert.equal(snapshot.logs.some((log) => log.level === 'error' && log.message.includes('NATMap 已退出')), false);
  await api(`/api/rules/${rule.id}/start`, { method: 'POST' });
  await waitFor(async () => (await api('/api/rules')).rules[0].running);
  await api(`/api/rules/${rule.id}`, { method: 'PUT', body: JSON.stringify({ targetPort: 12346, webhookUrl: '' }) });
  await waitFor(async () => (await api('/api/rules')).rules[0].logs.filter((log) => log.message.startsWith('启动规则')).length === 3);
  snapshot = (await api('/api/rules')).rules[0];
  assert.equal(snapshot.running, true); assert.equal(snapshot.targetPort, 12346);
  assert.equal(snapshot.logs.some((log) => log.level === 'error' && log.message.includes('NATMap 已退出')), false);
  assert.equal(stderr, '');
});
