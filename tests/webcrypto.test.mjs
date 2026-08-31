import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pbkdf2Sync } from 'node:crypto';
import { pbkdf2Sha512, hkdfSha256, hmacSha256 } from '../src/webcrypto.js';
import { bytesToHex, hexToBytes, utf8 } from '../src/encoding.js';

test('HKDF-SHA256 matches RFC 5869 test case 1', async () => {
  const ikm = hexToBytes('0b'.repeat(22));
  const salt = hexToBytes('000102030405060708090a0b0c');
  const info = hexToBytes('f0f1f2f3f4f5f6f7f8f9');
  const okm = await hkdfSha256(ikm, salt, info, 42);
  assert.equal(
    bytesToHex(okm),
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
  );
});

test('HMAC-SHA256 matches RFC 4231 test case 1', async () => {
  const key = hexToBytes('0b'.repeat(20));
  const data = utf8('Hi There');
  const mac = await hmacSha256(key, data);
  assert.equal(
    bytesToHex(mac),
    'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
  );
});

test('PBKDF2-SHA512 matches node:crypto', async () => {
  const ours = await pbkdf2Sha512(utf8('password'), utf8('salt'), 1000, 32);
  const nodes = pbkdf2Sync(Buffer.from('password'), Buffer.from('salt'), 1000, 32, 'sha512');
  assert.equal(bytesToHex(ours), nodes.toString('hex'));
});

test('PBKDF2-SHA512 is deterministic', async () => {
  const a = await pbkdf2Sha512(utf8('pw'), utf8('id'), 500, 32);
  const b = await pbkdf2Sha512(utf8('pw'), utf8('id'), 500, 32);
  assert.equal(bytesToHex(a), bytesToHex(b));
});
