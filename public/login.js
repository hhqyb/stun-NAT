import { APP_VERSION } from './version.js';

const form = document.querySelector('#loginForm');
const username = document.querySelector('#username');
const password = document.querySelector('#password');
const toggle = document.querySelector('#passwordToggle');
const submit = document.querySelector('#loginSubmit');
const errorBox = document.querySelector('#loginError');
const capsHint = document.querySelector('#capsHint');
document.querySelector('#version').textContent = APP_VERSION;

function destination() {
  const next = new URLSearchParams(location.search).get('next') || '/';
  try {
    const target = new URL(next, location.origin);
    return target.origin === location.origin ? `${target.pathname}${target.search}${target.hash}` : '/';
  } catch {
    return '/';
  }
}

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = !message;
}

function setBusy(busy) {
  submit.disabled = busy;
  submit.dataset.busy = String(busy);
  submit.textContent = busy ? '正在登录' : '登录';
}

toggle.addEventListener('click', () => {
  const revealing = password.type === 'password';
  password.type = revealing ? 'text' : 'password';
  toggle.textContent = revealing ? '隐藏' : '显示';
  toggle.setAttribute('aria-pressed', String(revealing));
  password.focus({ preventScroll: true });
});

for (const field of [username, password]) {
  const updateCaps = (event) => {
    if (typeof event.getModifierState !== 'function') return;
    capsHint.hidden = !event.getModifierState('CapsLock');
  };
  field.addEventListener('keydown', updateCaps);
  field.addEventListener('keyup', updateCaps);
  field.addEventListener('blur', () => { capsHint.hidden = true; });
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (submit.disabled) return;
  showError('');
  const account = username.value.trim();
  if (!account || !password.value) {
    showError('请输入账号和密码');
    (account ? password : username).focus();
    return;
  }
  setBusy(true);
  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: account, password: password.value })
    });
    if (response.ok) {
      location.replace(destination());
      return;
    }
    const body = await response.json().catch(() => ({}));
    showError(body.error || '登录失败，请重试');
    password.select();
  } catch {
    showError('无法连接到服务器，请检查网络后重试');
  } finally {
    setBusy(false);
  }
});
