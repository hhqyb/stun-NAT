import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';

const root = path.dirname(fileURLToPath(import.meta.url));
const dataDir = process.env.STUNMAP_DATA_DIR || path.join(root, 'data');
const natmapBin = process.env.NATMAP_BIN || 'natmap';
const port = Number(process.env.PORT || 16888);
const adminUser = process.env.STUNMAP_ADMIN_USER || 'admin';
const adminPassword = process.env.STUNMAP_ADMIN_PASSWORD || 'change-me-before-deploying';
const databasePath = path.join(dataDir, 'rules.json');
const stateDir = path.join(dataDir, 'state');
const logDir = path.join(dataDir, 'logs');
const runners = new Map();

if (process.env.NODE_ENV === 'production' && adminPassword === 'change-me-before-deploying') throw new Error('生产环境必须设置 STUNMAP_ADMIN_PASSWORD');

function json(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

function basicAuth(req, res) {
  const value = req.headers.authorization || '';
  const encoded = value.startsWith('Basic ') ? value.slice(6) : '';
  const expected = Buffer.from(`${adminUser}:${adminPassword}`).toString('base64');
  const sameLength = encoded.length === expected.length;
  const valid = sameLength && crypto.timingSafeEqual(Buffer.from(encoded), Buffer.from(expected));
  if (valid) return true;
  res.writeHead(401, { 'www-authenticate': 'Basic realm="STUN-NAT Console"' });
  res.end('Authentication required');
  return false;
}

async function ensureStorage() {
  await fsp.mkdir(stateDir, { recursive: true });
  await fsp.mkdir(logDir, { recursive: true });
  try { await fsp.access(databasePath); } catch { await saveDatabase({ rules: [] }); }
}

async function loadDatabase() {
  try { return JSON.parse(await fsp.readFile(databasePath, 'utf8')); } catch { return { rules: [] }; }
}

async function saveDatabase(database) {
  const temp = `${databasePath}.tmp`;
  await fsp.writeFile(temp, `${JSON.stringify(database, null, 2)}\n`, { mode: 0o600 });
  await fsp.rename(temp, databasePath);
}

function value(input, key, fallback = '') { return input[key] === undefined ? fallback : input[key]; }

const webhookTemplatePattern = /\{\{([A-Z][A-Z0-9_]*)\}\}|\$\{([A-Z][A-Z0-9_]*)\}|\{([A-Z][A-Z0-9_]*)\}/g;

function webhookTemplateValues(rule, state = {}, routerState = null) {
  const publicAddress = String(state.publicAddress || ''); const publicPort = String(state.publicPort || '');
  const privateAddress = String(state.privateAddress || ''); const privatePort = String(state.privatePort || '');
  const routerAddress = String(routerState?.externalAddress || ''); const routerPort = String(routerState?.externalPort || '');
  return {
    STUN_PUBLIC_IP: publicAddress, STUN_PUBLIC_PORT: publicPort, STUN_PUBLIC_ADDR: publicAddress && publicPort ? `${publicAddress}:${publicPort}` : publicAddress,
    STUN_PRIVATE_IP: privateAddress, STUN_PRIVATE_PORT: privatePort, STUN_PRIVATE_ADDR: privateAddress && privatePort ? `${privateAddress}:${privatePort}` : privateAddress,
    STUN_IP4P: String(state.ip4p || ''), STUN_PROTOCOL: String(rule.protocol || ''), STUN_RULE_ID: String(rule.id || ''), STUN_RULE_NAME: String(rule.name || ''),
    STUN_ROUTER_IP: routerAddress, STUN_ROUTER_PORT: routerPort
  };
}

function renderWebhookTemplate(template, variables) {
  return String(template || '').replace(webhookTemplatePattern, (match, mustache, dollar, brace) => {
    const name = mustache || dollar || brace;
    if (!Object.hasOwn(variables, name)) throw new Error(`未知 Webhook 变量：${name}`);
    return variables[name];
  });
}

function isInsideJsonString(source, index) {
  let quoted = false; let escaped = false;
  for (let offset = 0; offset < index; offset++) {
    const character = source[offset];
    if (escaped) { escaped = false; continue; }
    if (character === '\\') { escaped = true; continue; }
    if (character === '"') quoted = !quoted;
  }
  return quoted;
}

function renderWebhookJsonTemplate(template, variables) {
  const source = String(template || '');
  return source.replace(webhookTemplatePattern, (match, mustache, dollar, brace, offset) => {
    const name = mustache || dollar || brace;
    if (!Object.hasOwn(variables, name)) throw new Error(`未知 Webhook 变量：${name}`);
    const replacement = variables[name];
    return isInsideJsonString(source, offset) ? JSON.stringify(replacement).slice(1, -1) : replacement;
  });
}

function validateRule(input, existing = {}) {
  const rule = {
    id: existing.id || crypto.randomUUID(),
    name: String(value(input, 'name', existing.name)).trim(),
    enabled: Boolean(value(input, 'enabled', existing.enabled ?? true)),
    protocol: String(value(input, 'protocol', existing.protocol || 'tcp')).toLowerCase(),
    bindPort: Number(value(input, 'bindPort', existing.bindPort ?? 0)),
    stunServer: String(value(input, 'stunServer', existing.stunServer || 'turn.cloudflare.com:3478')).trim(),
    keepaliveServer: String(value(input, 'keepaliveServer', existing.keepaliveServer || 'www.cloudflare.com:80')).trim(),
    interval: Number(value(input, 'interval', existing.interval ?? 10)),
    checkEvery: Number(value(input, 'checkEvery', existing.checkEvery ?? 1)),
    externalProbeUrl: String(value(input, 'externalProbeUrl', existing.externalProbeUrl || '')).trim(),
    externalProbeToken: String(value(input, 'externalProbeToken', existing.externalProbeToken || '')).trim(),
    probeInterval: Number(value(input, 'probeInterval', existing.probeInterval ?? 10)),
    webhookUrl: String(value(input, 'webhookUrl', existing.webhookUrl || '')).trim(),
    webhookMethod: String(value(input, 'webhookMethod', existing.webhookMethod || 'post')).toLowerCase(),
    webhookBody: String(value(input, 'webhookBody', existing.webhookBody || '')).trim(),
    mode: String(value(input, 'mode', existing.mode || 'forward')).toLowerCase(),
    targetHost: String(value(input, 'targetHost', existing.targetHost || '')).trim(),
    targetPort: Number(value(input, 'targetPort', existing.targetPort ?? 0)),
    routerMapping: String(value(input, 'routerMapping', existing.routerMapping || 'none')).toLowerCase(),
    firewallAuto: Boolean(value(input, 'firewallAuto', existing.firewallAuto ?? false)),
    firewallNote: String(value(input, 'firewallNote', existing.firewallNote || '')).trim()
  };
  if (!rule.name || rule.name.length > 80) throw new Error('规则名称必须是 1-80 个字符');
  if (!['tcp', 'udp'].includes(rule.protocol)) throw new Error('穿透类型只能是 tcp 或 udp');
  if (!Number.isInteger(rule.bindPort) || rule.bindPort < 0 || rule.bindPort > 65535) throw new Error('监听端口必须在 0-65535');
  if (!rule.stunServer.includes(':')) throw new Error('STUN 服务器必须是 host:port');
  if (rule.protocol === 'tcp' && !rule.keepaliveServer.includes(':')) throw new Error('TCP 规则需要保活服务器 host:port');
  if (!Number.isInteger(rule.interval) || rule.interval < 5 || rule.interval > 3600) throw new Error('保活间隔必须在 5-3600 秒');
  if (!Number.isInteger(rule.checkEvery) || rule.checkEvery < 1 || rule.checkEvery > 3600) throw new Error('STUN 检测周期必须在 1-3600');
  if (!Number.isInteger(rule.probeInterval) || rule.probeInterval < 5 || rule.probeInterval > 3600) throw new Error('外部探针间隔必须在 5-3600 秒');
  if (Boolean(rule.externalProbeUrl) !== Boolean(rule.externalProbeToken)) throw new Error('外部探针地址和令牌必须同时填写');
  if (rule.externalProbeUrl && !/^https?:\/\//.test(rule.externalProbeUrl)) throw new Error('外部探针地址必须是 http:// 或 https:// URL');
  const webhookTestVariables = webhookTemplateValues(rule, { publicAddress: '203.0.113.10', publicPort: 34567, privateAddress: '192.168.1.10', privatePort: 45678, ip4p: 'test-ip4p' }, { externalAddress: '203.0.113.10', externalPort: 34567 });
  if (rule.webhookUrl) {
    try { const target = new URL(renderWebhookTemplate(rule.webhookUrl, webhookTestVariables)); if (!['http:', 'https:'].includes(target.protocol)) throw new Error('协议无效'); } catch (error) { throw new Error(`Webhook 地址无效：${error.message}`); }
  }
  if (!['get', 'post'].includes(rule.webhookMethod)) throw new Error('Webhook 方法只能是 get 或 post');
  if (rule.webhookBody && rule.webhookMethod === 'post') {
    try { JSON.parse(renderWebhookJsonTemplate(rule.webhookBody, webhookTestVariables)); } catch (error) { throw new Error(`Webhook POST JSON 模板无效：${error.message}`); }
  }
  if (!['forward', 'bind'].includes(rule.mode)) throw new Error('模式只能是 forward 或 bind');
  if (rule.protocol === 'udp' && rule.mode === 'bind') throw new Error('UDP 穿透不支持 bind 直转模式，必须使用内置转发');
  if (rule.mode === 'forward' && (!rule.targetHost || !Number.isInteger(rule.targetPort) || rule.targetPort < 1 || rule.targetPort > 65535)) throw new Error('内置转发必须填写目标地址和目标端口');
  if (!['none', 'nat-pmp', 'upnp'].includes(rule.routerMapping)) throw new Error('路由映射类型无效');
  return rule;
}

async function readRuleState(id) {
  try { return JSON.parse(await fsp.readFile(path.join(stateDir, `${id}.json`), 'utf8')); } catch { return null; }
}

class RuleRunner {
  constructor(rule) { this.rule = rule; this.child = null; this.desired = false; this.logs = []; this.restarting = false; this.routerFingerprint = ''; this.routerState = null; this.firewallPort = null; this.lastEndpoint = ''; this.lastWebhookKey = ''; this.lastWebhookAttempt = 0; this.lastProbeAt = 0; this.probeFailures = 0; this.health = { local: 'waiting', external: 'not-configured', verifiedAt: null, detail: '等待首个 STUN 心跳' }; }
  log(level, message) {
    const entry = { at: new Date().toISOString(), level, message: String(message).trim() };
    this.logs.push(entry); if (this.logs.length > 300) this.logs.shift();
    fs.appendFileSync(path.join(logDir, `${this.rule.id}.log`), `${entry.at} ${level.toUpperCase()} ${entry.message}\n`);
  }
  args() {
    const r = this.rule;
    const args = ['-s', r.stunServer, '-b', String(r.bindPort), '-k', String(r.interval), '-c', String(r.checkEvery), '-e', path.join(root, 'scripts', 'notify.js')];
    if (r.protocol === 'udp') args.push('-u'); else args.push('-h', r.keepaliveServer);
    if (r.mode === 'forward') args.push('-t', r.targetHost, '-p', String(r.targetPort));
    return args;
  }
  async start() {
    this.desired = true;
    if (this.child) return;
    await fsp.rm(path.join(stateDir, `${this.rule.id}.json`), { force: true });
    this.lastProbeAt = 0; this.probeFailures = 0; this.health = { local: 'waiting', external: this.rule.externalProbeUrl ? 'waiting' : 'not-configured', verifiedAt: null, detail: '正在建立 STUN 映射' };
    this.log('info', `启动规则：${this.args().join(' ')}`);
    try {
      this.child = spawn(natmapBin, this.args(), { env: { ...process.env, STUNMAP_RULE_ID: this.rule.id, STUNMAP_STATE_DIR: stateDir }, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (error) { this.log('error', error.message); throw error; }
    this.child.stdout.on('data', (chunk) => this.log('info', chunk));
    this.child.stderr.on('data', (chunk) => this.log('error', chunk));
    this.child.on('error', (error) => this.log('error', `无法启动 NATMap：${error.message}`));
    this.child.on('exit', (code, signal) => { this.log(code === 0 ? 'info' : 'error', `NATMap 已退出（code=${code}, signal=${signal || 'none'}）`); this.child = null; this.restarting = false; if (this.desired) setTimeout(() => this.start().catch((error) => this.log('error', error.message)), 1000).unref(); });
  }
  removeFirewallRule() {
    if (!this.firewallPort) return;
    const result = spawnSync('iptables', ['-D', 'INPUT', '-p', this.rule.protocol, '--dport', String(this.firewallPort), '-j', 'ACCEPT']);
    this.log(result.status === 0 ? 'info' : 'error', result.status === 0 ? `已移除防火墙放行端口 ${this.firewallPort}` : `移除防火墙规则失败：${result.error?.message || result.stderr?.toString() || 'iptables 返回错误'}`);
    this.firewallPort = null;
  }
  ensureFirewallRule(port) {
    if (!this.rule.firewallAuto || this.firewallPort === port) return;
    this.removeFirewallRule();
    if (process.platform !== 'linux') { this.log('error', '防火墙自动放行仅支持 Linux iptables'); return; }
    const check = spawnSync('iptables', ['-C', 'INPUT', '-p', this.rule.protocol, '--dport', String(port), '-j', 'ACCEPT']);
    if (check.status === 0) { this.log('info', `检测到已有防火墙放行端口 ${port}`); return; }
    const add = spawnSync('iptables', ['-I', 'INPUT', '1', '-p', this.rule.protocol, '--dport', String(port), '-j', 'ACCEPT']);
    if (add.status === 0) { this.firewallPort = port; this.log('info', `已自动放行防火墙端口 ${port}`); } else this.log('error', `防火墙自动放行失败：${add.error?.message || add.stderr?.toString() || 'iptables 返回错误'}`);
  }
  stop() {
    this.desired = false;
    this.removeFirewallRule();
    if (this.child) { this.log('info', '停止规则'); this.child.kill('SIGTERM'); }
  }
  restart(reason) {
    if (this.restarting || !this.child) return;
    this.restarting = true; this.log('error', `映射健康检查失败，重建通道：${reason}`); this.child.kill('SIGTERM');
  }
  observeState(state) {
    if (!state) return;
    const endpoint = `${state.publicAddress}:${state.publicPort}`;
    if (this.lastEndpoint && endpoint !== this.lastEndpoint) this.log('info', `公网映射已变化：${this.lastEndpoint} -> ${endpoint}`);
    this.lastEndpoint = endpoint;
    const verifiedAt = Date.parse(state.lastVerifiedAt || state.updatedAt || ''); const expected = this.rule.protocol === 'udp' ? this.rule.interval * this.rule.checkEvery : this.rule.interval;
    const age = Number.isFinite(verifiedAt) ? Date.now() - verifiedAt : Infinity;
    if (age <= expected * 2000 + 5000) this.health = { ...this.health, local: 'healthy', verifiedAt: state.lastVerifiedAt || state.updatedAt, detail: 'STUN/保活通道正常' };
    else { this.health = { ...this.health, local: 'unhealthy', verifiedAt: state.lastVerifiedAt || state.updatedAt, detail: `超过 ${Math.ceil(age / 1000)} 秒未收到映射心跳` }; this.restart(this.health.detail); }
  }
  async probe(state) {
    if (!this.rule.externalProbeUrl || this.health.local !== 'healthy' || Date.now() - this.lastProbeAt < this.rule.probeInterval * 1000) return;
    this.lastProbeAt = Date.now();
    try {
      const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 5000);
      const response = await fetch(this.rule.externalProbeUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, signal: controller.signal, body: JSON.stringify({ address: state.publicAddress, port: state.publicPort, protocol: this.rule.protocol, token: this.rule.externalProbeToken }) }); clearTimeout(timer);
      const result = await response.json(); if (!response.ok || !result.reachable) throw new Error(result.error || `HTTP ${response.status}`);
      this.probeFailures = 0; this.health = { ...this.health, external: 'healthy', externalVerifiedAt: new Date().toISOString() }; this.log('info', `外部探针验证通过：${state.publicAddress}:${state.publicPort}`);
    } catch (error) {
      this.probeFailures++; this.health = { ...this.health, external: 'unhealthy', externalVerifiedAt: new Date().toISOString(), externalDetail: error.message }; this.log('error', `外部探针失败（${this.probeFailures}/2）：${error.message}`); if (this.probeFailures >= 2) this.restart('连续两次外部通道探测失败');
    }
  }
  async notifyWebhook(state) {
    if (!this.rule.webhookUrl) return;
    const key = `${state.mappingChangedAt || state.updatedAt}:${state.publicAddress}:${state.publicPort}`;
    if (this.lastWebhookKey === key || Date.now() - this.lastWebhookAttempt < 5000) return;
    this.lastWebhookAttempt = Date.now();
    const payload = { event: 'mapping.updated', occurredAt: new Date().toISOString(), rule: { id: this.rule.id, name: this.rule.name, protocol: this.rule.protocol, mode: this.rule.mode }, mapping: { stunAddress: state.publicAddress, stunPort: state.publicPort, privateAddress: state.privateAddress, privatePort: state.privatePort, ip4p: state.ip4p }, routerMapping: this.routerState };
    const variables = webhookTemplateValues(this.rule, state, this.routerState);
    try {
      let url = renderWebhookTemplate(this.rule.webhookUrl, variables); const options = { method: this.rule.webhookMethod.toUpperCase(), headers: {} };
      if (this.rule.webhookMethod === 'get') { const target = new URL(url); for (const [keyName, value] of Object.entries({ event: payload.event, rule_id: payload.rule.id, rule_name: payload.rule.name, protocol: payload.rule.protocol, public_address: payload.mapping.stunAddress, public_port: String(payload.mapping.stunPort), private_address: payload.mapping.privateAddress, private_port: String(payload.mapping.privatePort), ip4p: payload.mapping.ip4p || '' })) if (!target.searchParams.has(keyName)) target.searchParams.append(keyName, value); url = target.toString(); }
      else { options.headers['content-type'] = 'application/json'; options.body = this.rule.webhookBody ? renderWebhookJsonTemplate(this.rule.webhookBody, variables) : JSON.stringify(payload); }
      const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 5000); options.signal = controller.signal;
      const response = await fetch(url, options); clearTimeout(timer); if (!response.ok) throw new Error(`HTTP ${response.status}`);
      this.lastWebhookKey = key; this.log('info', `映射 Webhook 调用成功：${this.rule.webhookMethod.toUpperCase()} ${this.rule.webhookUrl}`);
    } catch (error) { this.log('error', `映射 Webhook 调用失败：${error.message}`); }
  }
  snapshot(state) { return { ...this.rule, running: Boolean(this.child), state, routerState: this.routerState, health: this.health, logs: this.logs.slice(-80) }; }
}

function gatewayAddress() {
  if (process.platform !== 'linux') throw new Error('NAT-PMP 自动网关发现目前仅支持 Linux');
  const rows = fs.readFileSync('/proc/net/route', 'utf8').trim().split('\n').slice(1);
  const row = rows.map((line) => line.trim().split(/\s+/)).find((cells) => cells[1] === '00000000' && (Number.parseInt(cells[3], 16) & 2));
  if (!row) throw new Error('未找到默认网关');
  const value = Number.parseInt(row[2], 16);
  return [value & 255, (value >> 8) & 255, (value >> 16) & 255, (value >> 24) & 255].join('.');
}

function natPmpMap(protocol, privatePort, lifetime = 3600) {
  return new Promise((resolve, reject) => {
    let gateway;
    try { gateway = gatewayAddress(); } catch (error) { reject(error); return; }
    const socket = dgram.createSocket('udp4'); const request = Buffer.alloc(12); request[1] = protocol === 'tcp' ? 2 : 1; request.writeUInt16BE(privatePort, 4); request.writeUInt16BE(privatePort, 6); request.writeUInt32BE(lifetime, 8);
    const timer = setTimeout(() => { socket.close(); reject(new Error('NAT-PMP 请求超时')); }, 3000);
    socket.on('error', (error) => { clearTimeout(timer); socket.close(); reject(error); });
    socket.on('message', (message) => { clearTimeout(timer); socket.close(); if (message.length < 16 || message[2] !== 0 || message[3] !== 0) { reject(new Error(`NAT-PMP 返回错误码 ${message.readUInt16BE(2)}`)); return; } resolve({ gateway, externalPort: message.readUInt16BE(10), lifetime: message.readUInt32BE(12) }); });
    socket.send(request, 5351, gateway);
  });
}

function soapEnvelope(action, fields, serviceType) { return `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:${action} xmlns:u="${serviceType}">${Object.entries(fields).map(([key, val]) => `<${key}>${val}</${key}>`).join('')}</u:${action}></s:Body></s:Envelope>`; }

function localPrivateAddress() {
  for (const entries of Object.values(os.networkInterfaces())) for (const entry of entries || []) if (entry.family === 'IPv4' && !entry.internal) return entry.address;
  throw new Error('未找到可用于 UPnP 的局域网 IPv4 地址');
}

async function upnpMap(protocol, privatePort, description) {
  const location = await new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4'); const payload = Buffer.from('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n'); const timer = setTimeout(() => { socket.close(); reject(new Error('未发现 UPnP IGD')); }, 3000);
    socket.on('message', (message) => { const match = message.toString().match(/^location:\s*(.+)$/im); if (match) { clearTimeout(timer); socket.close(); resolve(match[1].trim()); } }); socket.on('error', reject); socket.send(payload, 1900, '239.255.255.250');
  });
  const device = await fetch(location).then((res) => res.text());
  const service = device.match(/<service>\s*<serviceType>(urn:schemas-upnp-org:service:(?:WANIPConnection|WANPPPConnection):\d+)<\/serviceType>[\s\S]*?<controlURL>([^<]+)<\/controlURL>[\s\S]*?<\/service>/i);
  if (!service) throw new Error('UPnP IGD 未提供 WANIP/WANPPP 控制服务');
  const controlUrl = new URL(service[2], location).toString(); const body = soapEnvelope('AddPortMapping', { NewRemoteHost: '', NewExternalPort: privatePort, NewProtocol: protocol.toUpperCase(), NewInternalPort: privatePort, NewInternalClient: localPrivateAddress(), NewEnabled: 1, NewPortMappingDescription: description, NewLeaseDuration: 3600 }, service[1]);
  const response = await fetch(controlUrl, { method: 'POST', headers: { 'content-type': 'text/xml; charset="utf-8"', soapaction: `"${service[1]}#AddPortMapping"` }, body });
  if (!response.ok) throw new Error(`UPnP AddPortMapping 失败：HTTP ${response.status}`);
  const query = await fetch(controlUrl, { method: 'POST', headers: { 'content-type': 'text/xml; charset="utf-8"', soapaction: `"${service[1]}#GetExternalIPAddress"` }, body: soapEnvelope('GetExternalIPAddress', {}, service[1]) });
  const externalAddress = query.ok ? (await query.text()).match(/<NewExternalIPAddress>([^<]+)<\/NewExternalIPAddress>/i)?.[1] : null;
  return { controlUrl, externalAddress: externalAddress || null, externalPort: privatePort, lifetime: 3600 };
}

async function reconcileRouterMappings() {
  for (const runner of runners.values()) {
    const state = await readRuleState(runner.rule.id); runner.observeState(state); if (!runner.child || !state) continue;
    runner.ensureFirewallRule(state.privatePort);
    const fingerprint = `${state.privatePort}:${runner.rule.routerMapping}:${runner.rule.protocol}`;
    if (runner.rule.routerMapping !== 'none' && runner.routerFingerprint !== fingerprint) try {
      const result = runner.rule.routerMapping === 'nat-pmp' ? await natPmpMap(runner.rule.protocol, state.privatePort) : await upnpMap(runner.rule.protocol, state.privatePort, `STUN-NAT ${runner.rule.name}`);
      runner.routerFingerprint = fingerprint; const sameWan = !result.externalAddress || result.externalAddress === state.publicAddress;
      runner.routerState = { type: runner.rule.routerMapping, externalAddress: result.externalAddress || null, externalPort: result.externalPort, matchesStunAddress: sameWan, verifiedAt: new Date().toISOString() };
      runner.log('info', `${runner.rule.routerMapping.toUpperCase()} 映射成功，路由 WAN ${result.externalAddress || '未知'}，外部端口 ${result.externalPort}${sameWan ? '' : '；与 STUN 地址不一致，存在上游 NAT'}`);
    } catch (error) { runner.log('error', `${runner.rule.routerMapping.toUpperCase()} 映射失败：${error.message}`); }
    await runner.probe(state); await runner.notifyWebhook(state);
  }
}

async function refreshRunners() {
  const { rules } = await loadDatabase(); const ids = new Set(rules.map((rule) => rule.id));
  for (const [id, runner] of runners) if (!ids.has(id)) { runner.stop(); runners.delete(id); }
  for (const rule of rules) { let runner = runners.get(rule.id); if (!runner) { runner = new RuleRunner(rule); runners.set(rule.id, runner); } else runner.rule = rule; runner.desired = rule.enabled; if (rule.enabled && !runner.child) await runner.start(); if (!rule.enabled) runner.stop(); }
}

async function parseBody(req) {
  const chunks = []; for await (const chunk of req) { chunks.push(chunk); if (Buffer.concat(chunks).length > 1024 * 1024) throw new Error('请求过大'); }
  try { return JSON.parse(Buffer.concat(chunks).toString() || '{}'); } catch { throw new Error('JSON 格式无效'); }
}

function staticFile(res, pathname) {
  const target = pathname === '/' ? '/index.html' : pathname; const file = path.resolve(root, 'public', `.${target}`); if (!file.startsWith(path.join(root, 'public'))) return json(res, 403, { error: 'forbidden' });
  fs.readFile(file, (error, data) => { if (error) return json(res, 404, { error: 'not found' }); const contentType = file.endsWith('.css') ? 'text/css' : file.endsWith('.js') ? 'application/javascript' : 'text/html'; res.writeHead(200, { 'content-type': `${contentType}; charset=utf-8` }); res.end(data); });
}

const server = http.createServer(async (req, res) => {
  if (!basicAuth(req, res)) return;
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`); const match = url.pathname.match(/^\/api\/rules\/([0-9a-f-]+)(?:\/(start|stop))?$/);
  try {
    if (req.method === 'GET' && url.pathname === '/api/rules') { const { rules } = await loadDatabase(); const output = await Promise.all(rules.map(async (rule) => { const runner = runners.get(rule.id); return runner ? runner.snapshot(await readRuleState(rule.id)) : { ...rule, running: false, state: await readRuleState(rule.id), logs: [] }; })); return json(res, 200, { rules: output }); }
    if (req.method === 'POST' && url.pathname === '/api/rules') { const body = await parseBody(req); const database = await loadDatabase(); const rule = validateRule(body); if (database.rules.some((item) => item.name === rule.name)) throw new Error('规则名称已存在'); database.rules.push(rule); await saveDatabase(database); await refreshRunners(); return json(res, 201, { rule }); }
    if (match && req.method === 'PUT' && !match[2]) { const body = await parseBody(req); const database = await loadDatabase(); const index = database.rules.findIndex((rule) => rule.id === match[1]); if (index < 0) return json(res, 404, { error: '规则不存在' }); database.rules[index] = validateRule(body, database.rules[index]); await saveDatabase(database); const runner = runners.get(match[1]); runner?.stop(); await refreshRunners(); return json(res, 200, { rule: database.rules[index] }); }
    if (match && req.method === 'DELETE' && !match[2]) { const database = await loadDatabase(); database.rules = database.rules.filter((rule) => rule.id !== match[1]); await saveDatabase(database); const runner = runners.get(match[1]); runner?.stop(); runners.delete(match[1]); return json(res, 204, {}); }
    if (match && req.method === 'POST' && match[2]) { const runner = runners.get(match[1]); if (!runner) return json(res, 404, { error: '规则不存在' }); if (match[2] === 'start') await runner.start(); else runner.stop(); return json(res, 200, runner.snapshot(await readRuleState(match[1]))); }
    staticFile(res, url.pathname);
  } catch (error) { json(res, 400, { error: error.message }); }
});

await ensureStorage(); await refreshRunners(); setInterval(reconcileRouterMappings, 1000).unref();
server.listen(port, '0.0.0.0', () => console.log(`STUN-NAT Console listening on :${port}`));
process.on('SIGTERM', () => { for (const runner of runners.values()) runner.stop(); server.close(() => process.exit(0)); });
