import crypto from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buffer) {
  let bits = 0; let value = 0; let output = '';
  for (const byte of buffer) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { output += ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) output += ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

export function base32Decode(text) {
  const clean = String(text || '').toUpperCase().replace(/[\s=]/g, '');
  let bits = 0; let value = 0; const bytes = [];
  for (const char of clean) {
    const index = ALPHABET.indexOf(char);
    if (index < 0) throw new Error('Base32 密钥格式无效');
    value = (value << 5) | index; bits += 5;
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(bytes);
}

export function generateSecret(bytes = 20) {
  return base32Encode(crypto.randomBytes(bytes));
}

export function totpStep(at = Date.now(), period = 30) {
  return Math.floor(at / 1000 / period);
}

export function totpCode(secret, step, digits = 6) {
  const counter = Buffer.alloc(8);
  counter.writeUInt32BE(Math.floor(step / 0x100000000), 0);
  counter.writeUInt32BE(step % 0x100000000, 4);
  const digest = crypto.createHmac('sha1', base32Decode(secret)).update(counter).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const value = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(value % 10 ** digits).padStart(digits, '0');
}

export function verifyTotp(secret, code, at = Date.now(), { window = 1, digits = 6, period = 30 } = {}) {
  const normalized = String(code || '').replace(/\s+/g, '');
  if (!new RegExp(`^\\d{${digits}}$`).test(normalized)) return null;
  try {
    const current = totpStep(at, period);
    for (let offset = -window; offset <= window; offset++) {
      const candidate = totpCode(secret, current + offset, digits);
      if (crypto.timingSafeEqual(Buffer.from(candidate), Buffer.from(normalized))) return current + offset;
    }
  } catch { return null; }
  return null;
}

export function totpUri(secret, { issuer = 'STUN-NAT', account = 'admin', digits = 6, period = 30 } = {}) {
  const label = encodeURIComponent(`${issuer}:${account}`);
  return `otpauth://totp/${label}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${digits}&period=${period}`;
}
