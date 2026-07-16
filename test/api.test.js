import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'stunmap-test-'));
const port = 17991;
const auth = `Basic ${Buffer.from('admin:test-password').toString('base64')}`;
let app;

async function request(url, options = {}) {
  return fetch(`http://127.0.0.1:${port}${url}`, { ...options, headers: { authorization: auth, 'content-type': 'application/json', ...(options.headers || {}) } });
}

before(async () => {
  app = spawn(process.execPath, ['server.js'], { env: { ...process.env, PORT: String(port), STUNMAP_DATA_DIR: directory, NATMAP_BIN: '/does/not/exist', STUNMAP_ADMIN_PASSWORD: 'test-password' } });
  await new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error('server did not start')), 3000); app.stdout.on('data', () => { clearTimeout(timer); resolve(); }); app.on('error', reject); });
});
after(async () => { app.kill('SIGTERM'); await fs.rm(directory, { recursive: true, force: true }); });

test('requires HTTP basic authentication', async () => {
  const response = await fetch(`http://127.0.0.1:${port}/api/rules`);
  assert.equal(response.status, 401);
});

test('creates, validates, and stops a Lucky-style STUN rule', async () => {
  const body = { name: 'web', enabled: false, protocol: 'tcp', bindPort: 0, stunServer: 'turn.cloudflare.com:3478', keepaliveServer: 'www.cloudflare.com:80', interval: 30, checkEvery: 10, mode: 'forward', targetHost: '192.168.1.20', targetPort: 443, routerMapping: 'upnp', firewallNote: 'WAN allowed' };
  const created = await request('/api/rules', { method: 'POST', body: JSON.stringify(body) });
  assert.equal(created.status, 201); const rule = (await created.json()).rule;
  assert.equal(rule.protocol, 'tcp'); assert.equal(rule.mode, 'forward'); assert.equal(rule.routerMapping, 'upnp');
  const list = await request('/api/rules'); const rules = (await list.json()).rules;
  assert.equal(rules.length, 1); assert.equal(rules[0].running, false);
  const invalid = await request('/api/rules', { method: 'POST', body: JSON.stringify({ ...body, name: 'bad', protocol: 'udp', mode: 'forward', targetPort: 0 }) });
  assert.equal(invalid.status, 400);
  const udpBind = await request('/api/rules', { method: 'POST', body: JSON.stringify({ ...body, name: 'udp-bind', protocol: 'udp', mode: 'bind', targetHost: '', targetPort: 0 }) });
  assert.equal(udpBind.status, 400);
  const incompleteProbe = await request('/api/rules', { method: 'POST', body: JSON.stringify({ ...body, name: 'incomplete-probe', externalProbeUrl: 'https://probe.example.com/probe' }) });
  assert.equal(incompleteProbe.status, 400);
  const webhook = await request('/api/rules', { method: 'POST', body: JSON.stringify({ ...body, name: 'webhook-template', webhookUrl: 'https://hooks.example.com/{{STUN_PUBLIC_ADDR}}', webhookMethod: 'post', webhookBody: '{"ip":"{{STUN_PUBLIC_IP}}","port":{{STUN_PUBLIC_PORT}},"name":"{{STUN_RULE_NAME}}"}' }) });
  assert.equal(webhook.status, 201); const webhookRule = (await webhook.json()).rule;
  assert.equal(webhookRule.webhookBody, '{"ip":"{{STUN_PUBLIC_IP}}","port":{{STUN_PUBLIC_PORT}},"name":"{{STUN_RULE_NAME}}"}');
  const invalidWebhookBody = await request('/api/rules', { method: 'POST', body: JSON.stringify({ ...body, name: 'invalid-webhook-template', webhookUrl: 'https://hooks.example.com', webhookMethod: 'post', webhookBody: '{"ip":"{{MISSING_VARIABLE}}"}' }) });
  assert.equal(invalidWebhookBody.status, 400);
  const removed = await request(`/api/rules/${rule.id}`, { method: 'DELETE' });
  assert.equal(removed.status, 204);
});

test('keeps the console available when an enabled mapping engine cannot start', async () => {
  const body = { name: 'engine-error', enabled: true, protocol: 'udp', bindPort: 0, stunServer: 'turn.cloudflare.com:3478', keepaliveServer: '', interval: 30, checkEvery: 10, mode: 'forward', targetHost: '192.168.1.20', targetPort: 51820, routerMapping: 'none' };
  const created = await request('/api/rules', { method: 'POST', body: JSON.stringify(body) });
  assert.equal(created.status, 201);
  await new Promise((resolve) => setTimeout(resolve, 40));
  const rules = (await (await request('/api/rules')).json()).rules;
  const rule = rules.find((item) => item.name === 'engine-error');
  assert.ok(rule.logs.some((entry) => entry.level === 'error'));
});
