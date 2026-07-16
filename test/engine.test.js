import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import net from 'node:net';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { after, test } from 'node:test';

const engine = process.env.NATMAP_BIN;
const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'stunmap-engine-'));
const children = [];
const sockets = [];
after(async () => { for (const child of children) child.kill('SIGTERM'); for (const socket of sockets) socket.close(); await fs.rm(directory, { recursive: true, force: true }); });

function bind(socket) { return new Promise((resolve) => socket.bind(0, '127.0.0.1', () => resolve(socket.address().port))); }
function listen(server) { return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port))); }
function waitFor(predicate, timeout = 5000) { return new Promise((resolve, reject) => { const deadline = Date.now() + timeout; const timer = setInterval(async () => { try { const value = await predicate(); if (value) { clearInterval(timer); resolve(value); } else if (Date.now() >= deadline) { clearInterval(timer); reject(new Error('timed out waiting for mapping')); } } catch (error) { clearInterval(timer); reject(error); } }, 40); }); }

test('NATMap UDP forward mode maps a STUN channel port to the local target', { skip: !engine }, async () => {
  const stun = dgram.createSocket('udp4'); sockets.push(stun); const stunPort = await bind(stun);
  stun.on('message', (message, remote) => {
    if (message.length < 20 || message.readUInt16BE(0) !== 1) return;
    const response = Buffer.alloc(32); response.writeUInt16BE(0x0101, 0); response.writeUInt16BE(12, 2); message.copy(response, 4, 4, 20); response.writeUInt16BE(0x0020, 20); response.writeUInt16BE(8, 22); response[25] = 1; response.writeUInt16BE(remote.port ^ 0x2112, 26); Buffer.from([0x7f ^ 0x21, 0x00 ^ 0x12, 0x00 ^ 0xa4, 0x01 ^ 0x42]).copy(response, 28); stun.send(response, remote.port, remote.address);
  });
  const echo = dgram.createSocket('udp4'); sockets.push(echo); const echoPort = await bind(echo); echo.on('message', (message, remote) => echo.send(message, remote.port, remote.address));
  const stateDir = path.join(directory, 'state'); await fs.mkdir(stateDir); const child = spawn(engine, ['-u', '-s', `127.0.0.1:${stunPort}`, '-b', '0', '-k', '1', '-c', '1', '-t', '127.0.0.1', '-p', String(echoPort), '-e', path.resolve('scripts/notify.js')], { env: { ...process.env, STUNMAP_RULE_ID: 'udp', STUNMAP_STATE_DIR: stateDir } }); children.push(child);
  let stderr = ''; child.stderr.on('data', (chunk) => { stderr += chunk; });
  const state = await waitFor(async () => { try { return JSON.parse(await fs.readFile(path.join(stateDir, 'udp.json'), 'utf8')); } catch { return null; } });
  const client = dgram.createSocket('udp4'); sockets.push(client); const response = await new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error(`UDP forwarding timed out: ${stderr}`)), 3000); client.on('message', (message) => { clearTimeout(timer); resolve(message.toString()); }); client.send(Buffer.from('stunmap-ok'), state.privatePort, '127.0.0.1'); });
  assert.equal(response, 'stunmap-ok');
  const initialHeartbeat = state.lastVerifiedAt; await new Promise((resolve) => setTimeout(resolve, 1200)); const refreshed = JSON.parse(await fs.readFile(path.join(stateDir, 'udp.json'), 'utf8'));
  assert.notEqual(refreshed.lastVerifiedAt, initialHeartbeat, 'each successful STUN check must refresh mapping health');
  echo.close(); sockets.splice(sockets.indexOf(echo), 1);
  const probe = dgram.createSocket('udp4'); sockets.push(probe); const probeResponse = await new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error('UDP channel health response timed out')), 3000); probe.on('message', (message) => { clearTimeout(timer); resolve(message.toString()); }); probe.send(Buffer.from('SMHP:target-is-irrelevant'), refreshed.privatePort, '127.0.0.1'); });
  assert.equal(probeResponse, 'SMHP:target-is-irrelevant');
});

test('NATMap TCP forward mode keeps a channel and proxies TCP traffic', { skip: !engine }, async () => {
  const keepalive = net.createServer((socket) => socket.on('data', () => socket.write('HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'))); const keepalivePort = await listen(keepalive);
  const stun = net.createServer((socket) => socket.once('data', (message) => { if (message.length < 20 || message.readUInt16BE(0) !== 1) return socket.destroy(); const remote = socket.address(); const response = Buffer.alloc(32); response.writeUInt16BE(0x0101, 0); response.writeUInt16BE(12, 2); message.copy(response, 4, 4, 20); response.writeUInt16BE(0x0020, 20); response.writeUInt16BE(8, 22); response[25] = 1; response.writeUInt16BE(remote.port ^ 0x2112, 26); Buffer.from([0x7f ^ 0x21, 0x00 ^ 0x12, 0x00 ^ 0xa4, 0x01 ^ 0x42]).copy(response, 28); socket.end(response); })); const stunPort = await listen(stun);
  const echo = net.createServer((socket) => socket.pipe(socket)); const echoPort = await listen(echo); after(() => { keepalive.close(); stun.close(); echo.close(); });
  const stateDir = path.join(directory, 'tcp-state'); await fs.mkdir(stateDir); const child = spawn(engine, ['-s', `127.0.0.1:${stunPort}`, '-h', `127.0.0.1:${keepalivePort}`, '-b', '0', '-k', '1', '-t', '127.0.0.1', '-p', String(echoPort), '-e', path.resolve('scripts/notify.js')], { env: { ...process.env, STUNMAP_RULE_ID: 'tcp', STUNMAP_STATE_DIR: stateDir } }); children.push(child);
  let stderr = ''; child.stderr.on('data', (chunk) => { stderr += chunk; });
  const state = await waitFor(async () => { try { return JSON.parse(await fs.readFile(path.join(stateDir, 'tcp.json'), 'utf8')); } catch { return null; } });
  const reply = await new Promise((resolve, reject) => { const socket = net.connect(state.privatePort, '127.0.0.1'); const timer = setTimeout(() => { socket.destroy(); reject(new Error(`TCP forwarding timed out: ${stderr}`)); }, 3000); socket.on('connect', () => socket.write('stunmap-tcp')); socket.on('data', (chunk) => { clearTimeout(timer); socket.end(); resolve(chunk.toString()); }); socket.on('error', reject); });
  assert.equal(reply, 'stunmap-tcp');
});
