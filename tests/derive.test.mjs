import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CHARSETS, DEFAULT_LENGTH, MIN_LENGTH, MAX_LENGTH, DEFAULT_RULES, PROFILE,
  normaliseInput, requiredClasses, classChars,
} from '../src/derive.js';

test('profile id is v1', () => {
  assert.equal(PROFILE, 'v1');
});

test('charsets are the exact frozen strings', () => {
  assert.equal(
    CHARSETS.standard,
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*+-=?@_',
  );
  assert.equal(
    CHARSETS['letters-digits'],
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
  );
  assert.equal(
    CHARSETS['max-symbols'],
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*()-_=+[]{};:,.?@',
  );
});

test('charset lengths', () => {
  assert.equal(CHARSETS.standard.length, 74);
  assert.equal(CHARSETS['letters-digits'].length, 62);
  assert.equal(CHARSETS['max-symbols'].length, 84);
});

test('defaults', () => {
  assert.equal(DEFAULT_LENGTH, 20);
  assert.equal(MIN_LENGTH, 8);
  assert.equal(MAX_LENGTH, 64);
  assert.equal(DEFAULT_RULES, 'standard');
});

test('normaliseInput: NFKC, trim, lowercase', () => {
  assert.equal(normaliseInput('  GitHub.com  '), 'github.com');
  assert.equal(normaliseInput('ﬁle'), 'file');        // fi ligature -> "fi"
  assert.equal(normaliseInput('ＦＵＬＬ'), 'full');           // full-width -> ascii
  assert.equal(normaliseInput('Ä'), 'ä');
});

test('requiredClasses', () => {
  assert.deepEqual(requiredClasses('standard'), ['lower', 'upper', 'digit', 'symbol']);
  assert.deepEqual(requiredClasses('max-symbols'), ['lower', 'upper', 'digit', 'symbol']);
  assert.deepEqual(requiredClasses('letters-digits'), ['lower', 'upper', 'digit']);
});

test('classChars: symbol pool is the non-alnum chars of the active charset', () => {
  assert.equal(classChars('lower', CHARSETS.standard), 'abcdefghijklmnopqrstuvwxyz');
  assert.equal(classChars('upper', CHARSETS.standard), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  assert.equal(classChars('digit', CHARSETS.standard), '0123456789');
  assert.equal(classChars('symbol', CHARSETS.standard), '!#$%&*+-=?@_');
  assert.equal(classChars('symbol', CHARSETS['letters-digits']), '');
});

import { makeKeystream, sampleIndex } from '../src/derive.js';
import { hexToBytes, bytesToHex } from '../src/encoding.js';

test('makeKeystream block 0 equals HMAC-SHA256(seed, "gen" || uint32be(0))', async () => {
  const seed = hexToBytes('00'.repeat(64));
  const ks = makeKeystream(seed, 'gen');
  // Pull 32 bytes, which is exactly block 0.
  const collected = [];
  for (let i = 0; i < 32; i++) collected.push(await ks.next());
  // Independently compute block 0.
  const { hmacSha256 } = await import('../src/webcrypto.js');
  const { concatBytes, utf8, uint32be } = await import('../src/encoding.js');
  const expected = await hmacSha256(seed, concatBytes(utf8('gen'), uint32be(0)));
  assert.equal(bytesToHex(Uint8Array.from(collected)), bytesToHex(expected));
});

test('makeKeystream rolls into block 1 after 32 bytes', async () => {
  const seed = hexToBytes('11'.repeat(64));
  const ks = makeKeystream(seed, 'gen');
  for (let i = 0; i < 32; i++) await ks.next();
  const first = await ks.next();
  const { hmacSha256 } = await import('../src/webcrypto.js');
  const { concatBytes, utf8, uint32be } = await import('../src/encoding.js');
  const block1 = await hmacSha256(seed, concatBytes(utf8('gen'), uint32be(1)));
  assert.equal(first, block1[0]);
});

test('sampleIndex only returns values in range and rejects biased bytes', async () => {
  // Fake keystream: 250, 251, ..., then 3. n = 10 -> limit = 250, so 250 and 251 are rejected.
  const queue = [250, 251, 3];
  const fake = { next: async () => queue.shift() };
  const idx = await sampleIndex(fake, 10);
  assert.equal(idx, 3);
  assert.equal(queue.length, 0);
});

test('sampleIndex maps within [0, n)', async () => {
  const fake = { next: async () => 0 };
  assert.equal(await sampleIndex(fake, 62), 0);
});
