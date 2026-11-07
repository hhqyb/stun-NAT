import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import fs from 'node:fs/promises';
import { existsSync } from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { test } from 'node:test';

const chromePath = [process.env.CHROME_BIN, '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome'].find((candidate) => candidate && existsSync(candidate));
const publicDir = new URL('../public/', import.meta.url);
const records = (start, count = 80) => Array.from({ length: count }, (_, offset) => ({ id: `log-${start + offset}`, at: '2026-11-06T02:34:01.391Z', level: 'info', message: `日志条目 ${start + offset}` }));

async function connect(endpoint) {
  const socket = new WebSocket(endpoint);
  await once(socket, 'open');
  let sequence = 0;
  const pending = new Map();
  const exceptions = [];
  socket.addEventListener('message', ({ data }) => {
    const message = JSON.parse(data);
    if (message.method === 'Runtime.exceptionThrown') exceptions.push(message.params.exceptionDetails);
    const task = pending.get(message.id);
    if (!task) return;
    pending.delete(message.id); clearTimeout(task.timer);
    if (message.error) task.reject(new Error(JSON.stringify(message.error)));
    else task.resolve(message.result);
  });
  return {
    socket, exceptions,
    send(method, params = {}, sessionId) {
      return new Promise((resolve, reject) => {
        const id = ++sequence;
        const timer = setTimeout(() => { pending.delete(id); reject(new Error(`DevTools timed out: ${method}`)); }, 10000);
        pending.set(id, { resolve, reject, timer });
        socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
      });
    }
  };
}

test('browser: UPnP defaults, UTC+8 and stable log reading through polling', { skip: !chromePath && 'Set CHROME_BIN to run the real-browser regression', timeout: 120000 }, async (t) => {
  let rules = [
    { id: 'a', name: 'First', enabled: false, running: false, routerMapping: 'none', protocol: 'tcp', mode: 'forward', bindPort: 0, interval: 10, checkEvery: 1, targetHost: '127.0.0.1', targetPort: 8080, logs: records(0) },
    { id: 'b', name: 'Second', enabled: false, running: false, routerMapping: 'upnp', protocol: 'udp', mode: 'forward', interval: 10, checkEvery: 1, targetHost: '127.0.0.1', targetPort: 8081, logs: [] }
  ];
  const actions = [];
  const server = http.createServer(async (req, res) => {
    if (req.url === '/api/rules') { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ rules })); return; }
    if (req.url.startsWith('/api/rules/')) { actions.push(req.url); res.setHeader('content-type', 'application/json'); res.end('{}'); return; }
    try {
      const url = new URL(req.url === '/' ? 'index.html' : req.url.slice(1), publicDir);
      if (!url.href.startsWith(publicDir.href)) throw new Error('outside public');
      const body = await fs.readFile(url);
      res.setHeader('content-type', req.url.endsWith('.js') ? 'application/javascript' : req.url.endsWith('.css') ? 'text/css' : 'text/html');
      res.end(body);
    } catch { res.writeHead(404); res.end(); }
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const profile = await fs.mkdtemp(path.join(os.tmpdir(), 'stunmap-browser-'));
  const chrome = spawn(chromePath, ['--headless=new', '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1', `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-component-update', '--disable-dev-shm-usage', ...(process.getuid?.() === 0 ? ['--no-sandbox'] : []), 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
  let client;
  t.after(async () => {
    client?.socket.close();
    if (chrome.exitCode === null && chrome.signalCode === null) { const exited = once(chrome, 'exit'); chrome.kill('SIGTERM'); await exited; }
    server.closeAllConnections(); await new Promise((resolve) => server.close(resolve));
    await fs.rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });
  let endpoint;
  try {
    endpoint = await new Promise((resolve, reject) => {
      let stderr = '';
      const timeout = setTimeout(() => reject(new Error(`Chrome did not start: ${stderr}`)), 30000);
      chrome.stderr.on('data', (chunk) => { stderr += chunk; const match = stderr.match(/DevTools listening on (ws:\/\/[^\s]+)/); if (match) { clearTimeout(timeout); resolve(match[1]); } });
      chrome.once('error', (error) => { clearTimeout(timeout); reject(error); });
      chrome.once('exit', () => { clearTimeout(timeout); reject(new Error(`Chrome exited: ${stderr}`)); });
    });
  } catch (error) {
    t.skip(`browser regression skipped: ${error.message.split('\n')[0]}`);
    return;
  }
  client = await connect(endpoint);
  const { targetId } = await client.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await client.send('Target.attachToTarget', { targetId, flatten: true });
  const send = (method, params = {}) => client.send(method, params, sessionId);
  const evaluate = async (expression) => {
    const response = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    assert.equal(response.exceptionDetails, undefined, JSON.stringify(response.exceptionDetails));
    return response.result.value;
  };
  const waitFor = async (expression) => {
    for (let count = 0; count < 200; count++) { if (await evaluate(expression)) return; await delay(50); }
    throw new Error(`Browser condition timed out: ${expression}`);
  };
  await send('Runtime.enable'); await send('Page.enable');
  await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  await send('Emulation.setTimezoneOverride', { timezoneId: 'America/Los_Angeles' });
  await send('Page.addScriptToEvaluateOnNewDocument', { source: "const interval = window.setInterval; window.setInterval = (callback, ms, ...args) => { if (ms === 5000) { window.refreshRules = callback; return 1; } return interval(callback, ms, ...args); };" });
  await send('Page.navigate', { url: `http://127.0.0.1:${server.address().port}/` });
  await waitFor("document.querySelectorAll('.rule').length === 2 && typeof window.refreshRules === 'function'");

  await t.test('new editor defaults to UPnP, while an explicit existing none remains none', async () => {
    assert.equal(await evaluate("document.querySelector('#newRule').click(); document.querySelector('[name=routerMapping]').value"), 'upnp');
    assert.deepEqual(await evaluate("document.querySelector('#ruleTemplate').value = 'game'; document.querySelector('#ruleTemplate').dispatchEvent(new Event('change')); ({ protocol: document.querySelector('[name=protocol]').value, port: document.querySelector('[name=targetPort]').value, mode: document.querySelector('[name=mode]').value })"), { protocol: 'udp', port: '25565', mode: 'forward' });
    assert.equal(await evaluate("document.querySelector('#closeEditor').click(); document.querySelector('.edit').click(); document.querySelector('#templateField').classList.contains('hidden')"), true);
    assert.equal(await evaluate("document.querySelector('[name=routerMapping]').value"), 'none');
    await evaluate("document.querySelector('#closeEditor').click()");
  });

  await t.test('copy prefills a new rule with a new name', async () => {
    assert.deepEqual(await evaluate("document.querySelector('.copy').click(); ({ id: document.querySelector('[name=id]').value, name: document.querySelector('[name=name]').value, template: document.querySelector('#templateField').classList.contains('hidden') })"), { id: '', name: 'First 副本', template: false });
    await evaluate("document.querySelector('#closeEditor').click()");
  });

  await t.test('webhook preset fills the advanced webhook fields', async () => {
    const preset = await evaluate("document.querySelector('.edit').click(); const select = document.querySelector('#webhookPreset'); select.value = 'telegram'; select.dispatchEvent(new Event('change')); ({ method: document.querySelector('[name=webhookMethod]').value, url: document.querySelector('[name=webhookUrl]').value, body: document.querySelector('[name=webhookBody]').value })");
    assert.equal(preset.method, 'post');
    assert.match(preset.url, /api\.telegram\.org/);
    assert.match(preset.body, /STUN_PUBLIC_ADDR/);
    await evaluate("document.querySelector('#closeEditor').click()");
  });

  await evaluate("window.card = document.querySelector('.rule'); window.log = card.querySelector('.logs'); window.logDetails = card.querySelector('details'); logDetails.open = true;");
  await waitFor('log.clientHeight > 0 && log.scrollHeight - log.clientHeight - log.scrollTop <= 2');
  assert.match(await evaluate('log.textContent'), /2026-11-06T10:34:01\.391\+08:00/);

  await t.test('log level filter only shows matching entries', async () => {
    await evaluate("card.querySelector('.log-filter').value = 'error'; card.querySelector('.log-filter').dispatchEvent(new Event('change'))");
    assert.equal(await evaluate("log.querySelector('.log-placeholder')?.textContent"), '暂无日志');
    await evaluate("card.querySelector('.log-filter').value = 'all'; card.querySelector('.log-filter').dispatchEvent(new Event('change'))");
    assert.match(await evaluate('log.textContent'), /日志条目 0/);
  });

  await t.test('log search narrows visible entries', async () => {
    await evaluate("card.querySelector('.log-search').value = '日志条目 79'; card.querySelector('.log-search').dispatchEvent(new Event('input'))");
    assert.equal(await evaluate('log.children.length'), 1);
    assert.match(await evaluate('log.textContent'), /日志条目 79/);
    await evaluate("card.querySelector('.log-search').value = ''; card.querySelector('.log-search').dispatchEvent(new Event('input'))");
    assert.match(await evaluate('log.textContent'), /日志条目 0/);
  });

  await t.test('reading older lines preserves DOM, focus, open state and viewport after a rolling snapshot', async () => {
    await evaluate('log.focus(); log.scrollTop = 120; window.oldTop = log.scrollTop; window.oldPageTop = scrollY; window.oldText = log.textContent; window.oldRow = log.children[10];');
    await delay(30);
    rules[0].logs = records(1);
    await evaluate('window.refreshRules()');
    assert.deepEqual(await evaluate(`({ sameCard: card === document.querySelector('.rule'), sameLog: log === card.querySelector('.logs'), sameRow: oldRow === log.children[10], opened: logDetails.open, focused: document.activeElement === log, scroll: log.scrollTop === oldTop, page: scrollY === oldPageTop, text: log.textContent === oldText, pending: !card.querySelector('.log-latest').disabled })`), { sameCard: true, sameLog: true, sameRow: true, opened: true, focused: true, scroll: true, page: true, text: true, pending: true });
  });

  await t.test('selected text survives new logs even when its record disappears from the API window', async () => {
    await evaluate("var range = document.createRange(); range.setStart(oldRow.firstChild, 0); range.setEnd(oldRow.firstChild, 12); getSelection().removeAllRanges(); getSelection().addRange(range); window.selectedText = getSelection().toString();");
    for (const start of [40, 100, 100000]) { rules[0].logs = records(start); await evaluate('window.refreshRules()'); }
    assert.equal(await evaluate('getSelection().toString() === selectedText && log.scrollTop === oldTop && log.children.length === 80 && log.textContent === oldText'), true);
  });

  await t.test('explicitly viewing latest resumes following and retains unchanged log rows', async () => {
    await evaluate("getSelection().removeAllRanges(); card.querySelector('.log-latest').click(); window.retainedRow = log.children[1]");
    await waitFor('log.scrollHeight - log.clientHeight - log.scrollTop <= 2');
    rules[0].logs = records(100001);
    await evaluate('window.refreshRules()');
    assert.equal(await evaluate('log.children[0] === retainedRow && log.children.length === 80 && log.scrollTop > 0 && log.scrollHeight - log.clientHeight - log.scrollTop <= 2'), true);
    assert.match(await evaluate('log.lastElementChild.textContent'), /日志条目 100080$/);
  });

  await t.test('selecting text at the bottom pauses auto-follow until the selection is cleared', async () => {
    await evaluate("var range = document.createRange(); range.selectNodeContents(log.lastElementChild); getSelection().removeAllRanges(); getSelection().addRange(range); window.selectedText = getSelection().toString(); window.oldTop = log.scrollTop;");
    rules[0].logs = records(100002);
    await evaluate('window.refreshRules()');
    assert.equal(await evaluate('getSelection().toString() === selectedText && log.scrollTop === oldTop'), true);
    await evaluate('getSelection().removeAllRanges(); window.refreshRules()');
    assert.match(await evaluate('log.lastElementChild.textContent'), /日志条目 100081$/);
  });

  await t.test('closing and reopening paused logs does not discard the reading position', async () => {
    await evaluate('log.scrollTop = 100; window.oldTop = log.scrollTop; window.oldText = log.textContent;');
    await delay(30);
    await evaluate('logDetails.open = false');
    rules[0].logs = records(100010);
    await evaluate('window.refreshRules()');
    await evaluate('logDetails.open = true');
    await delay(30);
    assert.equal(await evaluate('log.scrollTop === oldTop && log.textContent === oldText'), true);
  });

  await t.test('persistent card actions use the most recent rule rather than stale closures', async () => {
    rules[0] = { ...rules[0], name: 'Updated', running: true, targetPort: 9999, routerMapping: 'upnp' };
    await evaluate('window.refreshRules()');
    assert.deepEqual(await evaluate("card.querySelector('.edit').click(); ({ port: document.querySelector('[name=targetPort]').value, mapping: document.querySelector('[name=routerMapping]').value })"), { port: '9999', mapping: 'upnp' });
    await evaluate("document.querySelector('#closeEditor').click(); card.querySelector('.toggle').click()");
    await delay(50);
    assert.equal(actions.at(-1), '/api/rules/a/stop');
  });
  assert.deepEqual(client.exceptions, []);
});
