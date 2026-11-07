import { LogViewer } from './log-view.js';
import { APP_VERSION } from './version.js';

const rulesEl = document.querySelector('#rules');
const emptyEl = document.querySelector('#empty');
const editor = document.querySelector('#editor');
const form = document.querySelector('#ruleForm');
const template = document.querySelector('#ruleTemplate');
document.querySelector('#version').textContent = APP_VERSION;
const cards = new Map();
let rules = [];
let loadSequence = 0;
let rulesEtag = '';
let redirecting = false;

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

function goToLogin() {
  if (redirecting) return;
  redirecting = true;
  location.replace(`/login.html?next=${encodeURIComponent(location.pathname + location.search)}`);
}

async function api(url, options = {}) {
  const endpoint = new URL(url, `${location.protocol}//${location.host}`);
  const response = await fetch(endpoint, { ...options, headers: { 'content-type': 'application/json', ...(options.headers || {}) } });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    if (response.status === 401) goToLogin();
    throw new ApiError(body.error || `请求失败：${response.status}`, response.status);
  }
  return response.status === 204 ? null : response.json();
}

async function loadSession() {
  try {
    const session = await api('/api/auth/session');
    if (!session?.username) return;
    const user = document.querySelector('#user');
    user.textContent = session.username;
    user.hidden = false;
  } catch {}
}

const toasts = document.querySelector('#toasts');
const confirmDialog = document.querySelector('#confirmDialog');
let lastLoadError = '';
let lastWarning = '';

function notify(message, kind = 'error') {
  const toast = document.createElement('div');
  toast.className = `toast ${kind}`;
  toast.setAttribute('role', kind === 'error' ? 'alert' : 'status');
  toast.textContent = message;
  toasts.append(toast);
  while (toasts.children.length > 3) toasts.firstElementChild.remove();
  setTimeout(() => toast.remove(), kind === 'error' ? 7000 : 4000);
}

function askConfirm(message) {
  document.querySelector('#confirmMessage').textContent = message;
  confirmDialog.returnValue = '';
  confirmDialog.showModal();
  return new Promise((resolve) => {
    confirmDialog.addEventListener('close', () => resolve(confirmDialog.returnValue === 'ok'), { once: true });
  });
}

document.querySelector('#confirmCancel').addEventListener('click', () => confirmDialog.close('cancel'));
document.querySelector('#confirmOk').addEventListener('click', () => confirmDialog.close('ok'));

function setMode() {
  const udp = form.protocol.value === 'udp';
  const bindOption = form.mode.querySelector('option[value="bind"]');
  bindOption.disabled = udp;
  if (udp && form.mode.value === 'bind') form.mode.value = 'forward';
  const bind = form.mode.value === 'bind';
  const advanced = document.querySelector('#viewMode').value === 'advanced';
  document.querySelectorAll('.target').forEach((el) => el.classList.toggle('hidden', bind));
  document.querySelectorAll('.advanced').forEach((el) => el.classList.toggle('hidden', !advanced));
  document.querySelector('.tcp-only').classList.toggle('hidden', udp || !advanced);
  document.querySelector('.webhook-body').classList.toggle('hidden', !advanced || form.webhookMethod.value !== 'post');
}

function setText(element, value) {
  const next = String(value || '—');
  if (element.textContent !== next) element.textContent = next;
}

function localTime(value, timeOnly = false) {
  const date = new Date(value);
  return timeOnly ? date.toLocaleTimeString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false }) : date.toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false });
}

function detailsFor(rule) {
  const router = rule.routerState;
  const routerValue = !router ? (rule.routerMapping === 'none' ? '不使用' : '等待路由器响应')
    : router.lastError ? `${router.type.toUpperCase()} 失败：${router.lastError}${router.nextRetryAt ? `；下次重试 ${localTime(router.nextRetryAt, true)}` : ''}`
      : router.status === 'pending' && !router.externalPort ? '正在等待路由映射'
        : `${router.type.toUpperCase()} ${router.externalAddress || 'WAN 地址未知'}:${router.externalPort}${router.matchesStunAddress === false ? '（存在上游 NAT）' : router.matchesStunAddress == null ? '（WAN 地址未确认）' : ''}${router.warning ? `；${router.warning}` : ''}`;
  return [
    ['通道健康', rule.health?.local === 'healthy' ? 'STUN/保活正常（非入站验证）' : rule.health?.detail || '等待建立'],
    ['公网探针', rule.health?.external === 'not-configured' ? '未配置，公网可达性未知' : rule.health?.external === 'healthy' ? '公网通道可达（目标服务另行检查）' : rule.health?.externalDetail || '等待探测'],
    ['最近验证（东八区）', rule.health?.verifiedAt ? localTime(rule.health.verifiedAt) : '—'],
    ['STUN 观测', rule.state?.publicAddress ? `${rule.state.publicAddress}:${rule.state.publicPort}` : '—'],
    ['路由器映射', routerValue],
    ['目标服务', rule.mode === 'forward' ? `${rule.targetHost}:${rule.targetPort}` : '由路由器端口转发决定'],
    ['保活 / 检测', `${rule.interval}s / 每 ${rule.checkEvery} 次`],
    ['本地绑定', rule.state?.privateAddress ? `${rule.state.privateAddress}:${rule.state.privatePort}` : '等待建立'],
    ['IP4P', rule.state?.ip4p || '—']
  ];
}

function createCard(rule) {
  const node = template.content.firstElementChild.cloneNode(true);
  const card = { node, rule, fields: [] };
  card.viewer = new LogViewer(node.querySelector('.logs'), node.querySelector('.log-latest'), node.querySelector('.log-filter'));
  node.querySelector('details').addEventListener('toggle', (event) => { if (event.target.open) card.viewer.reveal(); });
  node.querySelector('.log-download').addEventListener('click', () => { location.assign(`/api/rules/${card.rule.id}/logs`); });
  node.querySelector('.toggle').addEventListener('click', async () => {
    try {
      await api(`/api/rules/${card.rule.id}/${card.rule.running ? 'stop' : 'start'}`, { method: 'POST' });
      notify(card.rule.running ? '规则已停止' : '规则已启动', 'success');
      await load();
    } catch (error) { notify(error.message); }
  });
  node.querySelector('.edit').addEventListener('click', () => openEditor(card.rule));
  node.querySelector('.delete').addEventListener('click', async () => {
    if (!(await askConfirm(`删除规则“${card.rule.name}”？此操作不可撤销。`))) return;
    try {
      await api(`/api/rules/${card.rule.id}`, { method: 'DELETE' });
      notify('规则已删除', 'success');
      await load();
    } catch (error) { notify(error.message); }
  });
  for (const [label] of detailsFor(rule)) {
    const field = document.createElement('div');
    field.className = 'detail';
    const title = document.createElement('div');
    title.className = 'detail-label';
    title.textContent = label;
    const value = document.createElement('div');
    value.className = 'detail-value';
    field.append(title, value);
    node.querySelector('.details').append(field);
    card.fields.push(value);
  }
  return card;
}

function renderHistory(node, rule) {
  const list = node.querySelector('.history');
  const history = rule.history || [];
  list.replaceChildren();
  if (!history.length) {
    const item = document.createElement('li');
    item.className = 'history-empty';
    item.textContent = '暂无映射记录';
    list.append(item);
    return;
  }
  for (const entry of [...history].reverse()) {
    const item = document.createElement('li');
    const time = document.createElement('time');
    time.dateTime = entry.at;
    time.textContent = localTime(entry.at);
    const endpoint = document.createElement('code');
    endpoint.textContent = `${entry.address}:${entry.port}`;
    item.append(time, endpoint);
    list.append(item);
  }
}

function render() {
  emptyEl.hidden = rules.length > 0;
  setText(document.querySelector('#summary'), `${rules.filter((rule) => rule.running).length}/${rules.length} 条规则运行中`);
  const ids = new Set(rules.map((rule) => rule.id));
  for (const [id, card] of cards) {
    if (!ids.has(id)) { card.node.remove(); cards.delete(id); }
  }
  rules.forEach((rule, index) => {
    let card = cards.get(rule.id);
    if (!card) { card = createCard(rule); cards.set(rule.id, card); }
    card.rule = rule;
    const { node } = card;
    // Do not detach unchanged cards: details, scroll, keyboard focus and selected text survive.
    if (rulesEl.children[index] !== node) rulesEl.insertBefore(node, rulesEl.children[index] || null);
    setText(node.querySelector('.name'), rule.name);
    setText(node.querySelector('.meta'), `${rule.protocol.toUpperCase()} · ${rule.mode === 'forward' ? '本机代理转发' : '路由器直转'} · 本地通道 ${rule.bindPort || '随机'}`);
    const mapping = node.querySelector('.mapping');
    setText(mapping, rule.state?.publicAddress ? `公网映射  ${rule.state.publicAddress}:${rule.state.publicPort}` : rule.running ? '正在建立 STUN 映射…' : '规则未运行');
    mapping.classList.toggle('offline', !rule.state?.publicAddress);
    detailsFor(rule).forEach(([, value], fieldIndex) => setText(card.fields[fieldIndex], value));
    renderHistory(node, rule);
    card.viewer.update(rule.logs || []);
    const toggle = node.querySelector('.toggle');
    setText(toggle, rule.running ? '停止' : '启动');
    toggle.classList.toggle('secondary', rule.running);
  });
}

async function load() {
  const sequence = ++loadSequence;
  try {
    const response = await fetch('/api/rules', { headers: rulesEtag ? { 'if-none-match': rulesEtag } : {} });
    if (response.status === 304) return;
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      if (response.status === 401) { goToLogin(); return; }
      throw new ApiError(body.error || `请求失败：${response.status}`, response.status);
    }
    const result = await response.json();
    if (sequence !== loadSequence) return;
    rulesEtag = response.headers.get('etag') || '';
    rules = result.rules;
    lastLoadError = '';
    render();
    if (result.warning && result.warning !== lastWarning) { lastWarning = result.warning; notify(result.warning); }
  } catch (error) {
    if (error.status === 401) return;
    if (sequence === loadSequence) {
      setText(document.querySelector('#summary'), error.message);
      if (error.message !== lastLoadError) { lastLoadError = error.message; notify(error.message); }
    }
  }
}

function openEditor(rule = null) {
  form.reset();
  form.id.value = rule?.id || '';
  form.name.value = rule?.name || '';
  document.querySelector('#viewMode').value = rule ? 'advanced' : 'simple';
  form.protocol.value = rule?.protocol || 'tcp';
  form.bindPort.value = rule?.bindPort ?? 0;
  form.stunServer.value = rule?.stunServer || 'turn.cloudflare.com:3478';
  form.keepaliveServer.value = rule?.keepaliveServer || 'www.cloudflare.com:80';
  form.interval.value = rule?.interval || 10;
  form.checkEvery.value = rule?.checkEvery || 1;
  form.externalProbeUrl.value = rule?.externalProbeUrl || '';
  form.externalProbeToken.value = rule?.externalProbeToken || '';
  form.probeInterval.value = rule?.probeInterval || 10;
  form.webhookUrl.value = rule?.webhookUrl || '';
  form.webhookMethod.value = rule?.webhookMethod || 'post';
  form.webhookBody.value = rule?.webhookBody || '';
  form.mode.value = rule?.mode || 'forward';
  form.targetHost.value = rule?.targetHost || '';
  form.targetPort.value = rule?.targetPort || '';
  form.routerMapping.value = rule?.routerMapping ?? 'upnp';
  form.firewallAuto.checked = rule?.firewallAuto || false;
  form.firewallNote.value = rule?.firewallNote || '';
  form.enabled.checked = rule?.enabled ?? true;
  document.querySelector('#dialogTitle').textContent = rule ? '编辑穿透规则' : '添加穿透规则';
  setMode();
  editor.showModal();
}

document.querySelector('#newRule').addEventListener('click', () => openEditor());
document.querySelector('#closeEditor').addEventListener('click', () => editor.close());
document.querySelector('#cancelEditor').addEventListener('click', () => editor.close());
form.protocol.addEventListener('change', setMode);
form.mode.addEventListener('change', setMode);
form.webhookMethod.addEventListener('change', setMode);
document.querySelector('#viewMode').addEventListener('change', setMode);
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(form));
  data.enabled = form.enabled.checked;
  data.firewallAuto = form.firewallAuto.checked;
  ['bindPort', 'interval', 'checkEvery', 'targetPort', 'probeInterval'].forEach((key) => { data[key] = Number(data[key] || 0); });
  try {
    await api(form.id.value ? `/api/rules/${form.id.value}` : '/api/rules', { method: form.id.value ? 'PUT' : 'POST', body: JSON.stringify(data) });
    editor.close();
    notify('规则已保存', 'success');
    await load();
  } catch (error) { notify(error.message); }
});
document.querySelector('#logout').addEventListener('click', async (event) => {
  event.currentTarget.disabled = true;
  try { await api('/api/auth/logout', { method: 'POST' }); } catch {}
  location.replace('/login.html');
});
loadSession();
load();
setInterval(load, 5000);
