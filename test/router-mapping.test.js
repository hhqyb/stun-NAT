import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { EventEmitter, once } from 'node:events';
import http from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import { test } from 'node:test';
import { createRouterMapper, discoverUpnp, natPmpMap, parseDeviceDescription, requestText, RouterMappingTask, soapEnvelope, UpnpClient } from '../lib/router-mapping.js';

const serviceType = 'urn:schemas-upnp-org:service:WANIPConnection:1';
const description = `<root><device><serviceList><service><serviceId>wan</serviceId><controlURL>/control</controlURL><serviceType>${serviceType}</serviceType></service></serviceList></device></root>`;
const input = { type: 'upnp', protocol: 'tcp', privateAddress: '192.168.10.20', privatePort: 40000, publicAddress: '203.0.113.1', description: 'STUN-NAT web & tools' };
const result = { externalAddress: '100.64.1.2', externalPort: 40000, lifetime: 3600 };
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const fault = (code, text) => ({ status: 500, text: `<s:Fault><detail><UPnPError><errorCode>${code}</errorCode><errorDescription>${text}</errorDescription></UPnPError></detail></s:Fault>` });
const actionOf = (options) => options.headers?.soapaction?.match(/#([^"#]+)/)?.[1];

class DiscoverySocket extends EventEmitter {
  constructor({ respond = false, bindError = null } = {}) { super(); this.respond = respond; this.bindError = bindError; this.sends = []; this.closes = 0; }
  bind(port, address, callback) { this.bound = { port, address }; if (this.bindError) throw this.bindError; queueMicrotask(callback); }
  setMulticastInterface(address) { this.multicastAddress = address; }
  send(message, port, address, callback) {
    this.sends.push({ message: message.toString(), port, address }); callback();
    if (this.respond) queueMicrotask(() => this.emit('message', Buffer.from('HTTP/1.1 200 OK\r\nLOCATION: http://192.168.10.1/igd.xml\r\n\r\n')));
  }
  close() { this.closes++; }
}

test('SSDP binds to the STUN interface, discovers IGD v1/v2 and closes exactly once', async () => {
  const socket = new DiscoverySocket({ respond: true });
  const location = await discoverUpnp({ privateAddress: input.privateAddress, createSocket: () => socket, timeoutMs: 20 });
  assert.equal(location, 'http://192.168.10.1/igd.xml');
  assert.deepEqual(socket.bound, { port: 0, address: input.privateAddress });
  assert.equal(socket.multicastAddress, input.privateAddress);
  assert.equal(socket.sends.length, 2);
  assert.match(socket.sends[1].message, /InternetGatewayDevice:2/);
  await delay(30); assert.equal(socket.closes, 1);
});

test('SSDP cleans up on timeout, cancellation and bind failure', async () => {
  const timeoutSocket = new DiscoverySocket();
  await assert.rejects(discoverUpnp({ privateAddress: input.privateAddress, createSocket: () => timeoutSocket, timeoutMs: 10 }), /未发现 UPnP IGD/);
  assert.equal(timeoutSocket.closes, 1);
  const abortSocket = new DiscoverySocket(); const controller = new AbortController();
  const pending = discoverUpnp({ privateAddress: input.privateAddress, createSocket: () => abortSocket, signal: controller.signal });
  controller.abort(); await assert.rejects(pending, { name: 'AbortError' }); assert.equal(abortSocket.closes, 1);
  const failedSocket = new DiscoverySocket({ bindError: new Error('bad interface') });
  await assert.rejects(discoverUpnp({ privateAddress: input.privateAddress, createSocket: () => failedSocket }), /bad interface/);
  assert.equal(failedSocket.closes, 1);
});

test('UPnP XML supports namespaces, reordered fields and URLBase', () => {
  assert.deepEqual(parseDeviceDescription(description, 'http://192.168.10.1/igd.xml'), { serviceType, controlUrl: 'http://192.168.10.1/control' });
  const xml = `<root><URLBase>http://192.168.10.1:1234/base/</URLBase><d:service><d:controlURL>control?a=1&amp;b=2</d:controlURL><d:serviceType>${serviceType}</d:serviceType></d:service></root>`;
  assert.equal(parseDeviceDescription(xml, 'http://192.168.10.1/igd.xml').controlUrl, 'http://192.168.10.1:1234/base/control?a=1&b=2');
  assert.throws(() => parseDeviceDescription('<root/>', 'http://192.168.10.1/'), /控制服务/);
  assert.match(soapEnvelope('AddPortMapping', { NewPortMappingDescription: `a & b <c> "d" 'e'` }, serviceType), /a &amp; b &lt;c&gt; &quot;d&quot; &apos;e&apos;/);
});

test('UPnP maps to the actual STUN address, falls back on 725 and caches discovery/WAN queries', async () => {
  let discoveries = 0; const calls = [];
  const client = new UpnpClient({ discover: async ({ privateAddress }) => { assert.equal(privateAddress, input.privateAddress); discoveries++; return 'http://192.168.10.1/igd.xml'; }, request: async (url, options) => {
    calls.push({ url, options });
    assert.equal(options.localAddress, input.privateAddress);
    if (options.method !== 'POST') return { status: 200, text: description };
    if (actionOf(options) === 'AddPortMapping') {
      assert.match(options.body, /<NewInternalClient>192\.168\.10\.20<\/NewInternalClient>/);
      assert.match(options.body, /web &amp; tools/);
      return options.body.includes('<NewLeaseDuration>3600') ? fault(725, 'OnlyPermanentLeasesSupported') : { status: 200, text: '' };
    }
    return { status: 200, text: '<u:NewExternalIPAddress>100.64.1.2</u:NewExternalIPAddress>' };
  } });
  const mapped = await client.map(input); await client.map({ ...input, privatePort: 40001 });
  assert.equal(mapped.lifetime, 0); assert.equal(mapped.externalAddress, '100.64.1.2');
  assert.equal(discoveries, 1);
  assert.equal(calls.filter(({ options }) => actionOf(options) === 'GetExternalIPAddress').length, 1);
  assert.equal(calls.filter(({ options }) => actionOf(options) === 'AddPortMapping').length, 4);
});

test('UPnP shares discovery failure cooldown across rules instead of flooding the router', async () => {
  let now = 0, discoveries = 0, requests = 0;
  const client = new UpnpClient({ now: () => now, discover: async () => { discoveries++; return 'http://192.168.10.1/igd.xml'; }, request: async () => { requests++; throw new Error('timeout'); } });
  for (let i = 0; i < 22; i++) await assert.rejects(client.map({ ...input, privatePort: 40000 + i }), /设备描述读取失败.*igd.xml.*timeout/);
  assert.equal(discoveries, 1); assert.equal(requests, 1);
  now = 10000;
  await assert.rejects(client.map(input)); assert.equal(discoveries, 2);
});

test('UPnP transport errors share a cooldown but SOAP conflicts do not block unrelated ports', async () => {
  let addCalls = 0;
  const client = new UpnpClient({ discover: async () => 'http://192.168.10.1/igd.xml', request: async (url, options) => {
    if (options.method !== 'POST') return { status: 200, text: description };
    if (actionOf(options) === 'GetExternalIPAddress') return { status: 200, text: '<NewExternalIPAddress>100.64.1.2</NewExternalIPAddress>' };
    addCalls++;
    if (options.body.includes('<NewInternalPort>40000')) return fault(718, 'ConflictInMappingEntry');
    if (options.body.includes('<NewInternalPort>40002')) throw new Error('socket timeout');
    return { status: 200, text: '' };
  } });
  await assert.rejects(client.map(input), /718 ConflictInMappingEntry/);
  await client.map({ ...input, privatePort: 40001 });
  await assert.rejects(client.map({ ...input, privatePort: 40002 }), /AddPortMapping.*socket timeout/);
  await assert.rejects(client.map({ ...input, privatePort: 40003 }), /socket timeout/);
  assert.equal(addCalls, 3);
});

test('a failed WAN-address query does not undo a successful mapping or claim address equality', async () => {
  const client = new UpnpClient({ discover: async () => 'http://192.168.10.1/igd.xml', request: async (url, options) => {
    if (options.method !== 'POST') return { status: 200, text: description };
    if (actionOf(options) === 'GetExternalIPAddress') throw new Error('WAN query timed out');
    return { status: 200, text: '' };
  } });
  const task = new RouterMappingTask({ map: (request) => client.map(request) });
  await task.update(input);
  assert.equal(task.state.status, 'mapped'); assert.equal(task.state.externalAddress, null); assert.equal(task.state.matchesStunAddress, null);
  assert.match(task.state.warning, /WAN query timed out/); assert.equal(task.state.lastError, undefined);
});

test('UPnP does not guess the first host interface when STUN has not reported its address', async () => {
  const client = new UpnpClient({ discover: () => { throw new Error('should not discover'); } });
  for (const address of [undefined, '', '0.0.0.0', '::1']) await assert.rejects(client.map({ ...input, privateAddress: address }), /实际局域网 IPv4/);
});

test('HTTP deadline includes an unfinished response body and supports cancellation', async (t) => {
  const server = http.createServer((req, res) => { res.writeHead(200); res.write('<root>'); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => { server.closeAllConnections(); server.close(); });
  const url = `http://127.0.0.1:${server.address().port}/igd.xml`;
  await assert.rejects(requestText(url, { localAddress: '127.0.0.1', timeoutMs: 30 }), /超时/);
  const controller = new AbortController(); const pending = requestText(url, { signal: controller.signal });
  controller.abort(); await assert.rejects(pending, { name: 'AbortError' });
});

test('all rules share a single router queue, including after a failed operation', async () => {
  let active = 0, maxActive = 0;
  const map = createRouterMapper({ upnp: { map: async (request) => {
    active++; maxActive = Math.max(maxActive, active); await delay(1); active--;
    if (request.privatePort === 40000) throw new Error('first rule fails');
    return { ...result, externalPort: request.privatePort };
  } } });
  const results = await Promise.allSettled(Array.from({ length: 22 }, (_, i) => map({ ...input, privatePort: 40000 + i })));
  assert.equal(maxActive, 1); assert.equal(results[0].status, 'rejected');
  assert.equal(results.filter((item) => item.status === 'fulfilled').length, 21);
});

test('repeated maintenance ticks cannot overlap a pending mapping', async () => {
  const pending = deferred(); let calls = 0;
  const task = new RouterMappingTask({ map: () => { calls++; return pending.promise; } });
  const first = task.update(input);
  for (let i = 0; i < 100; i++) assert.equal(task.update(input), first);
  await Promise.resolve(); assert.equal(calls, 1);
  pending.resolve(result); await first;
  assert.equal(task.state.status, 'mapped'); assert.equal(task.state.matchesStunAddress, false);
});

test('router retry backs off from 10 seconds to five minutes and clears errors on recovery', async () => {
  let now = 0, calls = 0, fail = true; const logs = [];
  const task = new RouterMappingTask({ now: () => now, map: async () => { calls++; if (fail) throw new Error('offline'); return result; }, log: (...args) => logs.push(args) });
  for (const duration of [10000, 20000, 40000, 80000, 160000, 300000, 300000]) {
    await task.update(input); const attempts = calls;
    assert.equal(Date.parse(task.state.nextRetryAt) - now, duration);
    for (let i = 0; i < 10; i++) await task.update(input);
    assert.equal(calls, attempts); now += duration;
  }
  assert.equal(logs.length, 7); fail = false; await task.update(input);
  assert.equal(task.state.lastError, undefined); assert.equal(task.state.status, 'mapped');
});

test('finite leases renew at half-life; permanent leases are periodically rechecked', async () => {
  let now = 0, calls = 0;
  const task = new RouterMappingTask({ now: () => now, map: async () => { calls++; return { ...result, lifetime: calls < 3 ? 4 : 0 }; } });
  await task.update(input); now = 1999; await task.update(input); assert.equal(calls, 1);
  now = 2000; await task.update(input); assert.equal(calls, 2);
  now = 4000; await task.update(input); assert.equal(calls, 3);
  assert.equal(Date.parse(task.state.nextRenewAt), now + 1800000);
  now += 1800000; await task.update(input); assert.equal(calls, 4);
});

test('changing the local channel invalidates the mapping while a public IP change only updates comparison', async () => {
  let calls = 0; const task = new RouterMappingTask({ map: async () => { calls++; return result; } });
  await task.update(input); await task.update({ ...input, publicAddress: result.externalAddress });
  assert.equal(calls, 1); assert.equal(task.state.matchesStunAddress, true);
  await task.update({ ...input, privateAddress: '192.168.10.21' }); assert.equal(calls, 2);
  task.reset(); await task.update({ ...input, type: 'none' }); assert.equal(calls, 2); assert.equal(task.state, null);
});

test('stop/reset cancels queued work and ignores late success or failure from an old channel', async () => {
  for (const fail of [false, true]) {
    const pending = deferred(); const logs = []; let signal;
    const task = new RouterMappingTask({ map: (request) => { signal = request.signal; return pending.promise; }, log: (...args) => logs.push(args) });
    const operation = task.update(input); await Promise.resolve(); task.reset();
    assert.equal(signal.aborted, true);
    if (fail) pending.reject(new Error('late failure')); else pending.resolve(result);
    await operation; assert.equal(task.state, null); assert.deepEqual(logs, []);
  }
  const gate = deferred(); let calls = 0;
  const map = createRouterMapper({ upnp: { map: async () => { calls++; await gate.promise; return result; } } });
  const first = new RouterMappingTask({ map }); const stopped = new RouterMappingTask({ map });
  const a = first.update(input); const b = stopped.update({ ...input, privatePort: 40001 });
  await Promise.resolve(); stopped.reset(); gate.resolve(); await Promise.all([a, b]);
  assert.equal(calls, 1); assert.equal(stopped.state, null);
});

test('an old asynchronous result cannot overwrite a new channel mapping', async () => {
  const pending = deferred();
  const task = new RouterMappingTask({ map: (request) => request.privatePort === 40000 ? pending.promise : Promise.resolve({ ...result, externalPort: 40001 }) });
  const old = task.update(input); await Promise.resolve(); await task.update({ ...input, privatePort: 40001 });
  pending.resolve(result); await old;
  assert.equal(task.state.externalPort, 40001);
});

test('NAT-PMP ignores truncated/unrelated packets and returns a validated lease', async (t) => {
  const server = dgram.createSocket('udp4'); server.bind(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => server.close());
  server.on('message', (message, remote) => {
    server.send(Buffer.from([0, 130]), remote.port, remote.address);
    const response = Buffer.alloc(16); response[1] = 130; response.writeUInt16BE(message.readUInt16BE(4), 8); response.writeUInt16BE(45000, 10); response.writeUInt32BE(120, 12);
    server.send(response, remote.port, remote.address);
  });
  const mapped = await natPmpMap({ ...input, privateAddress: '127.0.0.1', gateway: '127.0.0.1', gatewayPort: server.address().port });
  assert.equal(mapped.externalPort, 45000); assert.equal(mapped.lifetime, 120);
});
