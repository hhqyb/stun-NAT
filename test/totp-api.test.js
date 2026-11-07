import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { totpCode, totpStep } from '../lib/totp.js';

let directory; let app; let port; let basic;

before(async () => {
  directory = await fs.mkdtemp(path.join(os.tmpdir(), 'stunmap-totp-'));
  const reserve = http.createServer(); reserve.listen(0, '127.0.0.1'); await once(reserve, 'listening');
  port = reserve.address().port; await new Promise((resolve) => reserve.close(resolve));
  app = spawn(process.execPath, ['server.js'], { env: { ...process.env, PORT: String(port), STUNMAP_DATA_DIR: directory, NATMAP_BIN: '/does/not/exist', STUNMAP_ADMIN_PASSWORD: 'test-password' }, stdio: ['ignore', 'pipe', 'pipe'] });
  await once(app.stdout, 'data');
  basic = `Basic ${Buffer.from('admin:test-password').toString('base64')}`;
});

after(async () => {
  if (app.exitCode === null) { const exited = once(app, 'exit'); app.kill('SIGTERM'); await exited; }
  await fs.rm(directory, { recursive: true, force: true });
});

function api(route, options = {}, headers = {}) {
  return fetch(`http://127.0.0.1:${port}${route}`, { ...options, headers: { 'content-type': 'application/json', ...headers, ...(options.headers || {}) } });
}

test('enables TOTP, requires codes at login and disables it with a fresh code', async () => {
  const initial = await (await api('/api/auth/totp', {}, { authorization: basic })).json();
  assert.equal(initial.enabled, false);

  const setupResponse = await api('/api/auth/totp/setup', { method: 'POST' }, { authorization: basic });
  assert.equal(setupResponse.status, 200);
  const setup = await setupResponse.json();
  assert.match(setup.secret, /^[A-Z2-7]+$/);
  assert.match(setup.uri, /^otpauth:\/\/totp\//);

  const step = totpStep(Date.now());
  const enable = await api('/api/auth/totp/enable', { method: 'POST', body: JSON.stringify({ code: totpCode(setup.secret, step) }) }, { authorization: basic });
  assert.equal(enable.status, 200);
  assert.equal((await enable.json()).enabled, true);

  const basicAfter = await api('/api/rules', {}, { authorization: basic });
  assert.equal(basicAfter.status, 401);

  const noCode = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ username: 'admin', password: 'test-password' }) });
  assert.equal(noCode.status, 401);
  assert.equal((await noCode.json()).totpRequired, true);

  const wrongCode = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ username: 'admin', password: 'test-password', code: '000000' }) });
  assert.equal(wrongCode.status, 401);

  const code = totpCode(setup.secret, step);
  const login = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ username: 'admin', password: 'test-password', code }) });
  assert.equal(login.status, 200);
  const cookie = login.headers.get('set-cookie').split(';')[0];

  const replay = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ username: 'admin', password: 'test-password', code }) });
  assert.equal(replay.status, 401);
  assert.match((await replay.json()).error, /已使用/);

  const session = await api('/api/rules', {}, { cookie });
  assert.equal(session.status, 200);

  const disable = await api('/api/auth/totp/disable', { method: 'POST', body: JSON.stringify({ code: totpCode(setup.secret, step + 1) }) }, { cookie });
  assert.equal(disable.status, 200);
  assert.equal((await disable.json()).enabled, false);

  const basicAgain = await api('/api/rules', {}, { authorization: basic });
  assert.equal(basicAgain.status, 200);

  const stored = JSON.parse(await fs.readFile(path.join(directory, 'security.json'), 'utf8'));
  assert.equal(stored.totp.enabled, false);
});
