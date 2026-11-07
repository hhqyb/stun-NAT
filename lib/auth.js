import crypto from 'node:crypto';

const COOKIE_NAME = 'stunmap_session';
const DEFAULT_TTL_MS = 12 * 60 * 60 * 1000;
const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_WINDOW_MS = 5 * 60 * 1000;

function digest(value) {
  return crypto.createHash('sha256').update(String(value ?? '')).digest();
}

function safeEqual(left, right) {
  return crypto.timingSafeEqual(digest(left), digest(right));
}

export function createAuth({ username, password, ttlMs = DEFAULT_TTL_MS, maxAttempts = DEFAULT_MAX_ATTEMPTS, windowMs = DEFAULT_WINDOW_MS }) {
  const sessions = new Map();
  const failures = new Map();

  function verifyCredentials(candidateUser, candidatePassword) {
    const userOk = safeEqual(candidateUser, username);
    const passwordOk = safeEqual(candidatePassword, password);
    return userOk && passwordOk;
  }

  function verifyBasic(header) {
    const value = String(header || '');
    if (!value.startsWith('Basic ')) return false;
    const decoded = Buffer.from(value.slice(6), 'base64').toString('utf8');
    const separator = decoded.indexOf(':');
    if (separator < 0) return false;
    return verifyCredentials(decoded.slice(0, separator), decoded.slice(separator + 1));
  }

  function createSession() {
    const token = crypto.randomBytes(32).toString('base64url');
    sessions.set(digest(token).toString('hex'), { expiresAt: Date.now() + ttlMs });
    return token;
  }

  function readSession(token) {
    if (!token) return null;
    const key = digest(token).toString('hex');
    const session = sessions.get(key);
    if (!session) return null;
    if (session.expiresAt <= Date.now()) { sessions.delete(key); return null; }
    return session;
  }

  function destroySession(token) {
    if (token) sessions.delete(digest(token).toString('hex'));
  }

  function blockedFor(key) {
    const record = failures.get(key);
    if (!record) return 0;
    if (record.resetAt <= Date.now()) { failures.delete(key); return 0; }
    if (record.count < maxAttempts) return 0;
    return Math.max(1, Math.ceil((record.resetAt - Date.now()) / 1000));
  }

  function recordFailure(key) {
    const record = failures.get(key);
    if (!record || record.resetAt <= Date.now()) failures.set(key, { count: 1, resetAt: Date.now() + windowMs });
    else record.count++;
  }

  function resetFailures(key) {
    failures.delete(key);
  }

  function cleanup() {
    const now = Date.now();
    for (const [key, session] of sessions) if (session.expiresAt <= now) sessions.delete(key);
    for (const [key, record] of failures) if (record.resetAt <= now) failures.delete(key);
  }

  function parseCookies(header) {
    const cookies = {};
    for (const part of String(header || '').split(';')) {
      const separator = part.indexOf('=');
      if (separator < 0) continue;
      const name = part.slice(0, separator).trim();
      if (!name || Object.hasOwn(cookies, name)) continue;
      let value = part.slice(separator + 1).trim();
      if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
      try { cookies[name] = decodeURIComponent(value); } catch { cookies[name] = value; }
    }
    return cookies;
  }

  function sessionCookie(token, { secure = false } = {}) {
    const parts = [`${COOKIE_NAME}=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${Math.floor(ttlMs / 1000)}`];
    if (secure) parts.push('Secure');
    return parts.join('; ');
  }

  function clearCookie({ secure = false } = {}) {
    const parts = [`${COOKIE_NAME}=`, 'Path=/', 'HttpOnly', 'SameSite=Strict', 'Max-Age=0'];
    if (secure) parts.push('Secure');
    return parts.join('; ');
  }

  return { COOKIE_NAME, verifyCredentials, verifyBasic, createSession, readSession, destroySession, blockedFor, recordFailure, resetFailures, cleanup, parseCookies, sessionCookie, clearCookie };
}
