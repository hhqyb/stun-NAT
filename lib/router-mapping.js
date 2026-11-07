import dgram from 'node:dgram';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { isIPv4 } from 'node:net';
import os from 'node:os';

const closeSocket = (socket) => { try { socket.close(); } catch {} };
const xmlEscape = (value) => String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[char]));
const xmlDecode = (value) => value.replace(/&(amp|lt|gt|quot|apos);/g, (_, name) => ({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }[name]));
function element(xml, name) {
  const match = xml.match(new RegExp(`<(?:[\\w.-]+:)?${name}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?${name}\\s*>`, 'i'));
  return match ? xmlDecode(match[1].trim()) : '';
}

export function soapEnvelope(action, fields, serviceType) {
  return `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:${action} xmlns:u="${xmlEscape(serviceType)}">${Object.entries(fields).map(([key, val]) => `<${key}>${xmlEscape(val)}</${key}>`).join('')}</u:${action}></s:Body></s:Envelope>`;
}

// The deadline covers the response body as well as connecting/receiving headers.
export function requestText(url, { method = 'GET', headers = {}, body, localAddress, signal, timeoutMs = 4000 } = {}) {
  return new Promise((resolve, reject) => {
    signal?.throwIfAborted();
    const target = new URL(url);
    if (!['http:', 'https:'].includes(target.protocol)) throw new Error('UPnP 控制地址必须使用 HTTP(S)');
    const transport = target.protocol === 'https:' ? https : http;
    const request = transport.request(target, { method, headers: { ...headers, ...(body ? { 'content-length': Buffer.byteLength(body) } : {}) }, localAddress, signal });
    const timer = setTimeout(() => request.destroy(new Error(`请求超时（${timeoutMs}ms）`)), timeoutMs);
    let settled = false;
    const finish = (error, result) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (error) reject(error); else resolve(result);
    };
    request.on('error', (error) => finish(error));
    request.on('response', (response) => {
      const chunks = []; let size = 0;
      response.on('error', (error) => finish(error));
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > 1024 * 1024) { request.destroy(new Error('UPnP 响应超过 1 MiB')); return; }
        chunks.push(chunk);
      });
      response.on('end', () => finish(null, { status: response.statusCode, text: Buffer.concat(chunks).toString() }));
    });
    request.end(body);
  });
}

export function discoverUpnp({ privateAddress, signal, timeoutMs = 3000, createSocket = dgram.createSocket } = {}) {
  return new Promise((resolve, reject) => {
    signal?.throwIfAborted();
    const socket = createSocket('udp4'); let settled = false;
    const finish = (error, location) => {
      if (settled) return;
      settled = true; clearTimeout(timer); signal?.removeEventListener('abort', onAbort); closeSocket(socket);
      if (error) reject(error); else resolve(location);
    };
    const onAbort = () => finish(signal.reason);
    const timer = setTimeout(() => finish(new Error(`未发现 UPnP IGD（源地址 ${privateAddress}，请检查路由器 UPnP 和组播连通性）`)), timeoutMs);
    signal?.addEventListener('abort', onAbort, { once: true });
    socket.on('error', (error) => finish(error));
    socket.on('message', (message) => {
      const location = message.toString().match(/^location:\s*(.+)$/im)?.[1]?.trim();
      if (!location) return;
      try { if (['http:', 'https:'].includes(new URL(location).protocol)) finish(null, location); } catch {}
    });
    try {
      socket.bind(0, privateAddress, () => {
        if (settled) return;
        try {
          socket.setMulticastInterface(privateAddress);
          for (const version of [1, 2]) {
            const message = Buffer.from(`M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:${version}\r\n\r\n`);
            socket.send(message, 1900, '239.255.255.250', (error) => { if (error) finish(error); });
          }
        } catch (error) { finish(error); }
      });
    } catch (error) { finish(error); }
  });
}

export function parseDeviceDescription(xml, location) {
  const base = element(xml, 'URLBase') || location;
  const services = xml.match(/<(?:[\w.-]+:)?service(?:\s[^>]*)?>[\s\S]*?<\/(?:[\w.-]+:)?service\s*>/gi) || [];
  for (const service of services) {
    const serviceType = element(service, 'serviceType'); const control = element(service, 'controlURL');
    if (!/^urn:schemas-upnp-org:service:(WANIPConnection|WANPPPConnection):\d+$/.test(serviceType) || !control) continue;
    const controlUrl = new URL(control, base).toString();
    if (!['http:', 'https:'].includes(new URL(controlUrl).protocol)) continue;
    return { serviceType, controlUrl };
  }
  throw new Error('UPnP IGD 未提供 WANIP/WANPPP 控制服务');
}

export class UpnpClient {
  constructor({ discover = discoverUpnp, request = requestText, now = Date.now, timeoutMs = 4000, cacheMs = 300000, retryMs = 10000 } = {}) {
    Object.assign(this, { discover, request, now, timeoutMs, cacheMs, retryMs });
    this.devices = new Map();
  }
  async service(privateAddress, signal) {
    const cached = this.devices.get(privateAddress);
    if (cached?.error && this.now() < cached.retryAt) throw cached.error;
    if (cached?.service && this.now() < cached.expiresAt) return cached.service;
    try {
      const location = await this.discover({ privateAddress, signal });
      let response;
      try { response = await this.request(location, { localAddress: privateAddress, signal, timeoutMs: this.timeoutMs }); }
      catch (error) { throw new Error(`UPnP 设备描述读取失败（${location}）：${error.cause?.code || error.code || error.message}`, { cause: error }); }
      if (response.status < 200 || response.status >= 300) throw new Error(`UPnP 设备描述读取失败（${location}）：HTTP ${response.status}`);
      const service = parseDeviceDescription(response.text, location);
      this.devices.set(privateAddress, { service, expiresAt: this.now() + this.cacheMs });
      return service;
    } catch (error) {
      if (!signal?.aborted) this.devices.set(privateAddress, { error, retryAt: this.now() + this.retryMs });
      throw error;
    }
  }
  async soap(service, action, fields, privateAddress, signal) {
    let response;
    try {
      response = await this.request(service.controlUrl, { method: 'POST', headers: { 'content-type': 'text/xml; charset="utf-8"', soapaction: `"${service.serviceType}#${action}"` }, body: soapEnvelope(action, fields, service.serviceType), localAddress: privateAddress, signal, timeoutMs: this.timeoutMs });
    } catch (cause) {
      const error = new Error(`UPnP ${action} 请求失败（${service.controlUrl}）：${cause.cause?.code || cause.code || cause.message}`, { cause });
      error.transport = true; throw error;
    }
    const code = element(response.text, 'errorCode');
    if (response.status < 200 || response.status >= 300 || code) {
      const error = new Error(`UPnP ${action} 失败：HTTP ${response.status}${code ? `，${code} ${element(response.text, 'errorDescription')}` : ''}`);
      error.upnpCode = Number(code) || null; throw error;
    }
    return response.text;
  }
  async map({ protocol, privatePort, privateAddress, description, signal }) {
    if (!isIPv4(privateAddress) || privateAddress === '0.0.0.0') throw new Error('UPnP 缺少 STUN 通道的实际局域网 IPv4 地址');
    signal?.throwIfAborted();
    const service = await this.service(privateAddress, signal);
    let lifetime = 3600;
    const fields = { NewRemoteHost: '', NewExternalPort: privatePort, NewProtocol: protocol.toUpperCase(), NewInternalPort: privatePort, NewInternalClient: privateAddress, NewEnabled: 1, NewPortMappingDescription: description, NewLeaseDuration: lifetime };
    try {
      try { await this.soap(service, 'AddPortMapping', fields, privateAddress, signal); }
      catch (error) {
        if (error.upnpCode !== 725) throw error;
        lifetime = 0;
        await this.soap(service, 'AddPortMapping', { ...fields, NewLeaseDuration: 0 }, privateAddress, signal);
      }
    } catch (error) {
      // Share transport cooldowns across rules; per-port SOAP faults must not block other ports.
      if (error.transport && !signal?.aborted) this.devices.set(privateAddress, { error, retryAt: this.now() + this.retryMs });
      throw error;
    }
    signal?.throwIfAborted();
    if (service.externalCheckedAt === undefined || this.now() - service.externalCheckedAt >= 60000) {
      service.externalCheckedAt = this.now(); service.externalAddress = null; service.warning = null;
      try {
        const xml = await this.soap(service, 'GetExternalIPAddress', {}, privateAddress, signal);
        const address = element(xml, 'NewExternalIPAddress');
        if (isIPv4(address) && address !== '0.0.0.0') service.externalAddress = address;
        else service.warning = '路由器未返回有效 WAN IPv4 地址';
      } catch (error) {
        signal?.throwIfAborted();
        // AddPortMapping already succeeded: a WAN lookup failure is not a mapping failure.
        service.warning = error.message;
      }
    }
    return { controlUrl: service.controlUrl, externalAddress: service.externalAddress, externalPort: privatePort, lifetime, warning: service.warning };
  }

  async remove({ protocol, privateAddress, externalPort, signal }) {
    if (!isIPv4(privateAddress) || privateAddress === '0.0.0.0') return false;
    signal?.throwIfAborted();
    const service = await this.service(privateAddress, signal);
    try {
      await this.soap(service, 'DeletePortMapping', { NewRemoteHost: '', NewExternalPort: String(externalPort), NewProtocol: String(protocol).toUpperCase() }, privateAddress, signal);
      return true;
    } catch (error) {
      if (error.upnpCode && [713, 714].includes(error.upnpCode)) return false;
      if (error.transport && !signal?.aborted) this.devices.set(privateAddress, { error, retryAt: this.now() + this.retryMs });
      throw error;
    }
  }

  async cleanup({ privateAddress, prefix = 'STUN-NAT ', signal }) {
    if (!isIPv4(privateAddress) || privateAddress === '0.0.0.0') throw new Error('UPnP 缺少 STUN 通道的实际局域网 IPv4 地址');
    signal?.throwIfAborted();
    const service = await this.service(privateAddress, signal);
    const result = { scanned: 0, deleted: 0, failed: 0, warning: '' };
    let index = 0;
    while (index < 512) {
      let xml;
      try {
        xml = await this.soap(service, 'GetGenericPortMappingEntry', { NewPortMappingIndex: String(index) }, privateAddress, signal);
      } catch (error) {
        if (error.transport) throw error;
        if (![713, 714, 900].includes(error.upnpCode)) result.warning = error.message;
        break;
      }
      result.scanned++;
      const description = element(xml, 'NewPortMappingDescription');
      if (!description.startsWith(prefix)) { index++; continue; }
      const externalPort = element(xml, 'NewExternalPort');
      const protocol = element(xml, 'NewProtocol');
      try {
        await this.soap(service, 'DeletePortMapping', { NewRemoteHost: '', NewExternalPort: externalPort, NewProtocol: protocol }, privateAddress, signal);
        result.deleted++;
      } catch (error) {
        if (error.transport) throw error;
        result.failed++;
        index++;
      }
    }
    if (index >= 512 && !result.warning) result.warning = '达到 512 条枚举上限，可能仍有残留';
    return result;
  }
}

function gatewayAddress(privateAddress) {
  if (process.platform !== 'linux') throw new Error('NAT-PMP 自动网关发现目前仅支持 Linux');
  const iface = Object.entries(os.networkInterfaces()).find(([, entries]) => entries?.some((entry) => entry.address === privateAddress))?.[0];
  const routes = fs.readFileSync('/proc/net/route', 'utf8').trim().split('\n').slice(1).map((line) => line.trim().split(/\s+/));
  const row = routes.filter((cells) => cells[1] === '00000000' && (Number.parseInt(cells[3], 16) & 2) && (!iface || cells[0] === iface)).sort((a, b) => Number(a[6]) - Number(b[6]))[0];
  if (!row) throw new Error('未找到 STUN 通道所在网卡的默认网关');
  const value = Number.parseInt(row[2], 16);
  return [value & 255, (value >> 8) & 255, (value >> 16) & 255, (value >> 24) & 255].join('.');
}

export function natPmpMap({ protocol, privatePort, privateAddress, signal, lifetime = 3600, gateway = gatewayAddress(privateAddress), gatewayPort = 5351, timeoutMs = 3000 }) {
  return new Promise((resolve, reject) => {
    signal?.throwIfAborted();
    const socket = dgram.createSocket('udp4'); const opcode = protocol === 'tcp' ? 2 : 1; let settled = false;
    const finish = (error, result) => {
      if (settled) return;
      settled = true; clearTimeout(timer); signal?.removeEventListener('abort', onAbort); closeSocket(socket);
      if (error) reject(error); else resolve(result);
    };
    const onAbort = () => finish(signal.reason);
    const timer = setTimeout(() => finish(new Error(`NAT-PMP 请求超时（网关 ${gateway}）`)), timeoutMs);
    signal?.addEventListener('abort', onAbort, { once: true });
    socket.on('error', (error) => finish(error));
    socket.on('message', (message, remote) => {
      if (remote.address !== gateway || remote.port !== gatewayPort || message.length < 4 || message[0] !== 0 || message[1] !== opcode + 128) return;
      if (message.readUInt16BE(2)) { finish(new Error(`NAT-PMP 返回错误码 ${message.readUInt16BE(2)}`)); return; }
      if (message.length < 16 || message.readUInt16BE(8) !== privatePort) return;
      finish(null, { gateway, externalPort: message.readUInt16BE(10), lifetime: message.readUInt32BE(12) });
    });
    const request = Buffer.alloc(12); request[1] = opcode; request.writeUInt16BE(privatePort, 4); request.writeUInt16BE(privatePort, 6); request.writeUInt32BE(lifetime, 8);
    try { socket.bind(0, privateAddress, () => { if (!settled) socket.send(request, gatewayPort, gateway, (error) => { if (error) finish(error); }); }); }
    catch (error) { finish(error); }
  });
}

// All rules share one queue so a slow/embedded IGD never receives overlapping requests.
export function createRouterMapper({ upnp = new UpnpClient(), natPmp = natPmpMap } = {}) {
  let tail = Promise.resolve();
  return (request) => {
    const result = tail.then(() => {
      request.signal?.throwIfAborted();
      if (request.type === 'cleanup') return upnp.cleanup(request);
      if (request.type === 'remove') return upnp.remove(request);
      if (request.type === 'nat-pmp') return natPmp(request);
      return upnp.map(request);
    });
    tail = result.catch(() => {});
    return result;
  };
}

export class RouterMappingTask {
  constructor({ map, remove = null, log = () => {}, now = Date.now, retryMs = 10000, maxRetryMs = 300000 } = {}) {
    Object.assign(this, { map, remove, log, now, retryMs, maxRetryMs });
    this.generation = 0; this.reset();
  }
  reset() {
    const previous = this.remove && this.state?.type === 'upnp' && this.state.externalPort && this.current
      ? { type: 'remove', protocol: this.current.protocol, privateAddress: this.current.privateAddress, externalPort: this.state.externalPort }
      : null;
    if (previous) this.remove(previous).catch((error) => this.log('warn', `清理旧 UPnP 映射失败：${error.message}`));
    this.controller?.abort(); this.generation++;
    this.fingerprint = ''; this.state = null; this.inFlight = null; this.nextAttemptAt = 0; this.failures = 0; this.current = null;
  }
  update(request) {
    const fingerprint = `${request.type}:${request.protocol}:${request.privateAddress}:${request.privatePort}`;
    const endpoint = request.publicAddress ? `${request.publicAddress}:${request.publicPort ?? ''}` : '';
    const previousEndpoint = this.current?.publicAddress ? `${this.current.publicAddress}:${this.current.publicPort ?? ''}` : '';
    if (fingerprint !== this.fingerprint || (previousEndpoint && endpoint && previousEndpoint !== endpoint)) {
      this.reset();
      this.fingerprint = fingerprint;
    }
    this.current = request;
    if (request.type === 'none') return;
    if (this.state?.externalAddress) this.state.matchesStunAddress = this.state.externalAddress === request.publicAddress;
    if (this.inFlight || this.now() < this.nextAttemptAt) return this.inFlight;
    const generation = this.generation; const controller = this.controller = new AbortController();
    this.state = { ...this.state, type: request.type, status: 'pending' };
    const operation = Promise.resolve().then(() => this.map({ ...request, signal: controller.signal })).then((result) => {
      if (generation !== this.generation || controller.signal.aborted) return;
      this.failures = 0;
      const lifetime = result.lifetime ?? 3600;
      this.nextAttemptAt = this.now() + (lifetime > 0 ? Math.max(1000, lifetime * 500) : 1800000);
      this.state = { type: request.type, status: 'mapped', externalAddress: result.externalAddress || null, externalPort: result.externalPort, matchesStunAddress: result.externalAddress ? result.externalAddress === this.current.publicAddress : null, lifetime, verifiedAt: new Date(this.now()).toISOString(), nextRenewAt: new Date(this.nextAttemptAt).toISOString(), warning: result.warning || null };
      this.log('info', `${request.type.toUpperCase()} 映射成功，路由 WAN ${result.externalAddress || '未知'}，外部端口 ${result.externalPort}${this.state.matchesStunAddress === false ? '；与 STUN 地址不一致，存在上游 NAT' : ''}`);
      if (result.warning) this.log('warn', `路由映射已添加，但 WAN 地址查询未确认：${result.warning}`);
    }).catch((error) => {
      if (generation !== this.generation || controller.signal.aborted) return;
      const delay = Math.min(this.maxRetryMs, this.retryMs * (2 ** Math.min(this.failures++, 20)));
      this.nextAttemptAt = this.now() + delay;
      this.state = { ...this.state, status: 'failed', lastError: error.message, attemptedAt: new Date(this.now()).toISOString(), nextRetryAt: new Date(this.nextAttemptAt).toISOString() };
      this.log('error', `${request.type.toUpperCase()} 映射失败：${error.message}；${Math.ceil(delay / 1000)} 秒后重试`);
    }).finally(() => { if (this.inFlight === operation) this.inFlight = null; });
    this.inFlight = operation;
    return operation;
  }
}
