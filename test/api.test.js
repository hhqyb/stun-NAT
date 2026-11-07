import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { APP_VERSION } from '../public/version.js';

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

test('exposes an unauthenticated health endpoint', async () => {
  const response = await fetch(`http://127.0.0.1:${port}/healthz`);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.status, 'ok');
  assert.equal(body.version, APP_VERSION);
  assert.equal(typeof body.uptimeSeconds, 'number');
});

test('serves a login page and authenticates browser sessions with cookies', async () => {
  const navigation = await fetch(`http://127.0.0.1:${port}/`, { redirect: 'manual', headers: { accept: 'text/html' } });
  assert.equal(navigation.status, 303);
  assert.equal(navigation.headers.get('location'), '/login.html?next=%2F');
  const loginPage = await fetch(`http://127.0.0.1:${port}/login.html`);
  assert.equal(loginPage.status, 200);
  assert.match(loginPage.headers.get('content-security-policy') || '', /default-src 'self'/);
  assert.match(await loginPage.text(), /登录控制台/);

  const denied = await fetch(`http://127.0.0.1:${port}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'wrong-password' }) });
  assert.equal(denied.status, 401);

  const login = await fetch(`http://127.0.0.1:${port}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'test-password' }) });
  assert.equal(login.status, 200);
  const setCookie = login.headers.get('set-cookie');
  assert.match(setCookie, /^stunmap_session=[\w-]+;/);
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /SameSite=Strict/);
  const cookie = setCookie.split(';')[0];

  const list = await fetch(`http://127.0.0.1:${port}/api/rules`, { headers: { cookie } });
  assert.equal(list.status, 200);
  const session = await fetch(`http://127.0.0.1:${port}/api/auth/session`, { headers: { cookie } });
  assert.deepEqual(await session.json(), { username: 'admin' });

  const loginRedirect = await fetch(`http://127.0.0.1:${port}/login.html`, { redirect: 'manual', headers: { cookie } });
  assert.equal(loginRedirect.status, 303);
  assert.equal(loginRedirect.headers.get('location'), '/');

  const logout = await fetch(`http://127.0.0.1:${port}/api/auth/logout`, { method: 'POST', headers: { cookie } });
  assert.equal(logout.status, 204);
  assert.match(logout.headers.get('set-cookie'), /Max-Age=0/);
  const expired = await fetch(`http://127.0.0.1:${port}/api/rules`, { headers: { cookie } });
  assert.equal(expired.status, 401);
});

test('creates, validates, and stops a STUN forwarding rule', async () => {
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
  const webhook = await request('/api/rules', { method: 'POST', body: JSON.stringify({ ...body, name: 'webhook-template', webhookUrl: 'https://hooks.example.com/{{STUN_PUBLIC_ADDR}}', webhookMethod: 'post', webhookBody: '{"ip":"{{STUN_PUBLIC_IP}}","port":{{STUN_PUBLIC_PORT}},"name":"{{STUN_RULE_NAME}}"}', webhookHeaders: 'Authorization: Bearer abc' }) });
  assert.equal(webhook.status, 201); const webhookRule = (await webhook.json()).rule;
  assert.equal(webhookRule.webhookBody, '{"ip":"{{STUN_PUBLIC_IP}}","port":{{STUN_PUBLIC_PORT}},"name":"{{STUN_RULE_NAME}}"}');
  assert.equal(webhookRule.webhookHeaders, 'Authorization: Bearer abc');
  const invalidHeaders = await request('/api/rules', { method: 'POST', body: JSON.stringify({ ...body, name: 'invalid-webhook-headers', webhookUrl: 'https://hooks.example.com', webhookHeaders: 'Host: evil' }) });
  assert.equal(invalidHeaders.status, 400);
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

test('defaults new rules to UPnP without overriding explicit none or NAT-PMP on edits', async () => {
  const created = await request('/api/rules', { method: 'POST', body: JSON.stringify({ name: 'default-upnp', enabled: false, targetHost: '192.168.1.20', targetPort: 443 }) });
  assert.equal(created.status, 201);
  const { rule } = await created.json();
  assert.equal(rule.routerMapping, 'upnp');
  for (const routerMapping of ['none', 'nat-pmp']) {
    const changed = await request(`/api/rules/${rule.id}`, { method: 'PUT', body: JSON.stringify({ routerMapping }) });
    assert.equal((await changed.json()).rule.routerMapping, routerMapping);
    const edited = await request(`/api/rules/${rule.id}`, { method: 'PUT', body: JSON.stringify({ targetPort: 8443 }) });
    assert.equal((await edited.json()).rule.routerMapping, routerMapping);
  }
});

test('API and persisted logs have stable IDs and explicit UTC+8 timestamps', async () => {
  const { rules } = await (await request('/api/rules')).json();
  const rule = rules.find((item) => item.name === 'engine-error');
  assert.ok(rule.logs.length);
  assert.equal(new Set(rule.logs.map((entry) => entry.id)).size, rule.logs.length);
  for (const entry of rule.logs) {
    assert.match(entry.id, /^[0-9a-f-]+$/);
    assert.match(entry.at, /\+08:00$/);
    assert.ok(Number.isFinite(Date.parse(entry.at)));
  }
  const log = await fs.readFile(path.join(directory, 'logs', `${rule.id}.log`), 'utf8');
  assert.match(log, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+08:00 /);
});

test('returns 304 when the rule list is unchanged', async () => {
  const first = await request('/api/rules');
  assert.equal(first.status, 200);
  const etag = first.headers.get('etag');
  assert.match(etag, /^".+"$/);
  await first.arrayBuffer();
  const second = await request('/api/rules', { headers: { 'if-none-match': etag } });
  assert.equal(second.status, 304);
  assert.equal(await second.text(), '');
});

test('downloads the current rule log', async () => {
  const { rules } = await (await request('/api/rules')).json();
  const rule = rules.find((item) => item.name === 'engine-error');
  const response = await request(`/api/rules/${rule.id}/logs`);
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type'), /text\/plain/);
  assert.match(response.headers.get('content-disposition'), /attachment/);
  assert.match(await response.text(), /启动规则/);
});

test('tests webhook templates against a receiver', async (t) => {
  let received;
  const receiver = http.createServer((req, res) => {
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      received = { method: req.method, body, authorization: req.headers.authorization };
      res.writeHead(202, { 'content-type': 'text/plain' });
      res.end('accepted');
    });
  });
  receiver.listen(0, '127.0.0.1'); await once(receiver, 'listening');
  t.after(() => new Promise((resolve) => { receiver.closeAllConnections(); receiver.close(resolve); }));
  const url = `http://127.0.0.1:${receiver.address().port}/hook`;
  const response = await request('/api/webhook/test', { method: 'POST', body: JSON.stringify({ url, method: 'post', body: '{"ip":"{{STUN_PUBLIC_IP}}","port":{{STUN_PUBLIC_PORT}},"name":"{{STUN_RULE_NAME}}"}', headers: 'Authorization: Bearer test-token' }) });
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.ok, true);
  assert.equal(result.status, 202);
  assert.equal(result.response, 'accepted');
  assert.deepEqual(received, { method: 'POST', body: '{"ip":"203.0.113.10","port":34567,"name":"测试规则"}', authorization: 'Bearer test-token' });
});

test('lists, downloads and clears rule log files', async () => {
  const { rules } = await (await request('/api/rules')).json();
  const rule = rules.find((item) => item.name === 'engine-error');
  const listed = await (await request(`/api/rules/${rule.id}/logs/files`)).json();
  assert.ok(listed.files.length >= 1);
  const current = listed.files.find((file) => file.current);
  assert.equal(current.name, `${rule.id}.log`);
  const downloaded = await request(`/api/rules/${rule.id}/logs/files/${current.name}`);
  assert.equal(downloaded.status, 200);
  assert.match(await downloaded.text(), /启动规则/);
  const removed = await request(`/api/rules/${rule.id}/logs/files`, { method: 'DELETE' });
  assert.equal(removed.status, 200);
  assert.ok((await removed.json()).removed >= 1);
  const empty = await (await request(`/api/rules/${rule.id}/logs/files`)).json();
  assert.deepEqual(empty.files, []);
  const missing = await request(`/api/rules/${rule.id}/logs`);
  assert.equal(missing.status, 404);
});

test('exports and imports rule configuration', async () => {
  const exported = await request('/api/rules/export');
  assert.equal(exported.status, 200);
  assert.match(exported.headers.get('content-disposition'), /attachment/);
  const payload = await exported.json();
  assert.ok(Array.isArray(payload.rules));
  assert.ok(payload.rules.length > 0);
  assert.ok(payload.rules.every((rule) => rule.id === undefined));
  const imported = [
    { name: 'import-a', enabled: false, protocol: 'tcp', stunServer: 'turn.cloudflare.com:3478', keepaliveServer: 'www.cloudflare.com:80', interval: 30, checkEvery: 10, mode: 'forward', targetHost: '192.168.1.40', targetPort: 443, routerMapping: 'none' },
    { name: 'import-b', enabled: false, protocol: 'udp', stunServer: 'turn.cloudflare.com:3478', interval: 10, checkEvery: 2, mode: 'forward', targetHost: '192.168.1.41', targetPort: 25565, routerMapping: 'none' }
  ];
  const response = await request('/api/rules/import', { method: 'POST', body: JSON.stringify({ rules: imported }) });
  assert.equal(response.status, 201);
  assert.equal((await response.json()).imported, 2);
  const duplicate = await request('/api/rules/import', { method: 'POST', body: JSON.stringify({ rules: imported }) });
  assert.equal(duplicate.status, 400);
  const invalid = await request('/api/rules/import', { method: 'POST', body: JSON.stringify({ rules: [{ ...imported[0], name: 'import-c', protocol: 'sctp' }] }) });
  assert.equal(invalid.status, 400);
  const { rules } = await (await request('/api/rules')).json();
  assert.deepEqual(rules.filter((rule) => rule.name.startsWith('import-')).map((rule) => rule.name).sort(), ['import-a', 'import-b']);
});

test('rejects duplicate names on edit and clears rule state on delete', async () => {
  const base = { enabled: false, protocol: 'tcp', stunServer: 'turn.cloudflare.com:3478', keepaliveServer: 'www.cloudflare.com:80', interval: 30, checkEvery: 10, mode: 'forward', targetHost: '192.168.1.20', targetPort: 443, routerMapping: 'none' };
  const source = await request('/api/rules', { method: 'POST', body: JSON.stringify({ ...base, name: 'rename-source' }) });
  assert.equal(source.status, 201);
  const target = await request('/api/rules', { method: 'POST', body: JSON.stringify({ ...base, name: 'rename-target' }) });
  assert.equal(target.status, 201);
  const second = (await target.json()).rule;
  const duplicate = await request(`/api/rules/${second.id}`, { method: 'PUT', body: JSON.stringify({ name: 'rename-source' }) });
  assert.equal(duplicate.status, 400);
  const stateFile = path.join(directory, 'state', `${second.id}.json`);
  await fs.writeFile(stateFile, '{}');
  const removed = await request(`/api/rules/${second.id}`, { method: 'DELETE' });
  assert.equal(removed.status, 204);
  await assert.rejects(fs.access(stateFile));
});

test('throttles repeated login failures', async () => {
  for (let attempt = 0; attempt < 5; attempt++) {
    const response = await fetch(`http://127.0.0.1:${port}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: `wrong-${attempt}` }) });
    assert.equal(response.status, 401);
  }
  const blocked = await fetch(`http://127.0.0.1:${port}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'test-password' }) });
  assert.equal(blocked.status, 429);
  assert.ok(Number(blocked.headers.get('retry-after')) > 0);
});
