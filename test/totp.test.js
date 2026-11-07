import assert from 'node:assert/strict';
import { test } from 'node:test';
import { base32Decode, base32Encode, generateSecret, totpCode, totpStep, totpUri, verifyTotp } from '../lib/totp.js';

test('base32 round-trips binary secrets', () => {
  const buffer = Buffer.from('12345678901234567890');
  const encoded = base32Encode(buffer);
  assert.equal(encoded, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  assert.deepEqual(base32Decode(encoded), buffer);
});

test('matches RFC 6238 SHA-1 vectors', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  assert.equal(totpCode(secret, totpStep(59000), 8), '94287082');
  assert.equal(totpCode(secret, totpStep(1111111109000), 8), '07081804');
});

test('verifies current and adjacent codes and rejects others', () => {
  const secret = generateSecret();
  const at = 1700000000000;
  const step = totpStep(at);
  assert.equal(verifyTotp(secret, totpCode(secret, step), at), step);
  assert.equal(verifyTotp(secret, totpCode(secret, step - 1), at), step - 1);
  assert.equal(verifyTotp(secret, totpCode(secret, step + 1), at), step + 1);
  assert.equal(verifyTotp(secret, 'abcdef', at), null);
  assert.equal(verifyTotp(secret, totpCode(secret, step + 3), at), null);
});

test('builds an otpauth URI', () => {
  const uri = totpUri('ABC234', { issuer: 'STUN-NAT', account: 'admin' });
  assert.match(uri, /^otpauth:\/\/totp\/STUN-NAT%3Aadmin\?/);
  assert.match(uri, /secret=ABC234/);
  assert.match(uri, /issuer=STUN-NAT/);
  assert.match(uri, /digits=6/);
});
