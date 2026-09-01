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

import { aesGcmEncrypt, aesGcmDecrypt } from '../src/webcrypto.js';

test('AES-256-GCM matches McGrew GCM test case 14', async () => {
  const key = hexToBytes('00'.repeat(32));
  const iv = hexToBytes('00'.repeat(12));
  const pt = hexToBytes('00'.repeat(16));
  const out = await aesGcmEncrypt(key, iv, pt, new Uint8Array(0));
  // Web Crypto returns ciphertext || 16-byte tag.
  assert.equal(
    bytesToHex(out),
    'cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919',
  );
});

test('AES-256-GCM round-trips with AAD', async () => {
  const key = hexToBytes('11'.repeat(32));
  const iv = hexToBytes('22'.repeat(12));
  const aad = utf8('kunji-vault-v1');
  const msg = utf8('{"entries":[],"settings":{}}');
  const ct = await aesGcmEncrypt(key, iv, msg, aad);
  const back = await aesGcmDecrypt(key, iv, ct, aad);
  assert.equal(bytesToHex(back), bytesToHex(msg));
});

test('AES-256-GCM rejects a tampered ciphertext', async () => {
  const key = hexToBytes('33'.repeat(32));
  const iv = hexToBytes('44'.repeat(12));
  const ct = await aesGcmEncrypt(key, iv, utf8('hello'), new Uint8Array(0));
  ct[0] ^= 0x01;
  await assert.rejects(() => aesGcmDecrypt(key, iv, ct, new Uint8Array(0)));
});

test('AES-256-GCM rejects a wrong AAD', async () => {
  const key = hexToBytes('55'.repeat(32));
  const iv = hexToBytes('66'.repeat(12));
  const ct = await aesGcmEncrypt(key, iv, utf8('hello'), utf8('aad-one'));
  await assert.rejects(() => aesGcmDecrypt(key, iv, ct, utf8('aad-two')));
});

import { hmac } from '../src/webcrypto.js';
import { createHmac } from 'node:crypto';

test('hmac(SHA-1) matches node:crypto', async () => {
  const key = new Uint8Array([1, 2, 3, 4]);
  const msg = new Uint8Array([9, 9, 9]);
  const got = await hmac('SHA-1', key, msg);
  const want = new Uint8Array(createHmac('sha1', Buffer.from(key)).update(Buffer.from(msg)).digest());
  assert.deepEqual(got, want);
});

test('hmac(SHA-256) still equals hmacSha256', async () => {
  const key = new Uint8Array([5, 6, 7]);
  const msg = new Uint8Array([1, 1, 1, 1]);
  assert.deepEqual(await hmac('SHA-256', key, msg), await hmacSha256(key, msg));
});

test('hmac(SHA-512) matches node:crypto', async () => {
  const got = await hmac('SHA-512', new Uint8Array([1]), new Uint8Array([2]));
  const want = new Uint8Array(createHmac('sha512', Buffer.from([1])).update(Buffer.from([2])).digest());
  assert.deepEqual(got, want);
});
