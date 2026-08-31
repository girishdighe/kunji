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

import { deriveEntrySeed } from '../src/derive.js';

test('deriveEntrySeed returns 64 bytes and is deterministic', async () => {
  const masterKey = hexToBytes('22'.repeat(32));
  const params = { site: 'github.com', account: 'alex', counter: 1, rules: 'standard', length: 20 };
  const a = await deriveEntrySeed(masterKey, params);
  const b = await deriveEntrySeed(masterKey, params);
  assert.equal(a.length, 64);
  assert.equal(bytesToHex(a), bytesToHex(b));
});

test('deriveEntrySeed uses the exact info string "gen|site|account|counter|rules|length"', async () => {
  const masterKey = hexToBytes('22'.repeat(32));
  const fromApi = await deriveEntrySeed(masterKey, {
    site: 'github.com', account: 'alex', counter: 3, rules: 'standard', length: 24,
  });
  const { hkdfSha256 } = await import('../src/webcrypto.js');
  const { utf8 } = await import('../src/encoding.js');
  const manual = await hkdfSha256(
    masterKey, utf8('kunji/v1'), utf8('gen|github.com|alex|3|standard|24'), 64,
  );
  assert.equal(bytesToHex(fromApi), bytesToHex(manual));
});

test('deriveEntrySeed changes when any field changes', async () => {
  const mk = hexToBytes('22'.repeat(32));
  const base = { site: 'a', account: 'b', counter: 1, rules: 'standard', length: 20 };
  const baseSeed = bytesToHex(await deriveEntrySeed(mk, base));
  for (const mut of [
    { ...base, site: 'a2' },
    { ...base, account: 'b2' },
    { ...base, counter: 2 },
    { ...base, rules: 'letters-digits' },
    { ...base, length: 21 },
  ]) {
    assert.notEqual(bytesToHex(await deriveEntrySeed(mk, mut)), baseSeed);
  }
});

import { generateChars } from '../src/derive.js';

test('generateChars: correct length, all chars from the charset, deterministic', async () => {
  const seed = hexToBytes('33'.repeat(64));
  const out1 = await generateChars(seed, CHARSETS.standard, 20);
  const out2 = await generateChars(seed, CHARSETS.standard, 20);
  assert.equal(out1.length, 20);
  assert.equal(out1.join(''), out2.join(''));
  for (const ch of out1) assert.ok(CHARSETS.standard.includes(ch), `char ${ch} not in charset`);
});

test('generateChars: length 64 works and does not repeat blockwise', async () => {
  const seed = hexToBytes('44'.repeat(64));
  const out = await generateChars(seed, CHARSETS['letters-digits'], 64);
  assert.equal(out.length, 64);
  // First 32 chars should not equal the next 32 (would indicate a repeating hash bug).
  assert.notEqual(out.slice(0, 32).join(''), out.slice(32).join(''));
});

import { enforceClasses } from '../src/derive.js';

function classesPresent(str) {
  const set = new Set();
  for (const ch of str) {
    if (/[a-z]/.test(ch)) set.add('lower');
    else if (/[A-Z]/.test(ch)) set.add('upper');
    else if (/[0-9]/.test(ch)) set.add('digit');
    else set.add('symbol');
  }
  return set;
}

test('enforceClasses is a no-op when all required classes already present', async () => {
  const seed = hexToBytes('55'.repeat(64));
  const chars = 'aB3!aB3!aB3!aB3!aB3!'.split('');
  const out = await enforceClasses(chars, seed, 'standard', CHARSETS.standard);
  assert.equal(out.join(''), chars.join(''));
});

test('enforceClasses injects every missing required class', async () => {
  const seed = hexToBytes('66'.repeat(64));
  const chars = 'aaaaaaaaaaaaaaaaaaaa'.split(''); // only lowercase
  const out = await enforceClasses(chars, seed, 'standard', CHARSETS.standard);
  const present = classesPresent(out.join(''));
  for (const c of ['lower', 'upper', 'digit', 'symbol']) assert.ok(present.has(c), `missing ${c}`);
});

test('enforceClasses changes at most (number of missing classes) positions', async () => {
  const seed = hexToBytes('77'.repeat(64));
  const chars = 'aaaaaaaaaaaaaaaaaaaa'.split('');
  const out = await enforceClasses(chars, seed, 'standard', CHARSETS.standard);
  let changed = 0;
  for (let i = 0; i < chars.length; i++) if (chars[i] !== out[i]) changed += 1;
  assert.ok(changed <= 3, `changed ${changed} positions, expected <= 3 (upper, digit, symbol)`);
});

test('enforceClasses is deterministic', async () => {
  const seed = hexToBytes('88'.repeat(64));
  const chars = 'aaaaaaaaaaaaaaaaaaaa'.split('');
  const a = await enforceClasses(chars, seed, 'standard', CHARSETS.standard);
  const b = await enforceClasses(chars, seed, 'standard', CHARSETS.standard);
  assert.equal(a.join(''), b.join(''));
});

test('enforceClasses for letters-digits does not require a symbol', async () => {
  const seed = hexToBytes('99'.repeat(64));
  const chars = 'aA1aA1aA1aA1aA1aA1aA'.split('');
  const out = await enforceClasses(chars, seed, 'letters-digits', CHARSETS['letters-digits']);
  assert.equal(out.join(''), chars.join(''));
});

import { deriveMasterKey, computeKcv, derivePassword } from '../src/derive.js';

const FIXED_MK = hexToBytes('abababababababababababababababababababababababababababababababab12');

test('deriveMasterKey is PBKDF2-SHA512 over passphrase with normalised identity as salt', async () => {
  const mk = await deriveMasterKey('correct horse battery staple', '  ALEX@example.com ', 1000);
  const { pbkdf2Sha512 } = await import('../src/webcrypto.js');
  const { utf8 } = await import('../src/encoding.js');
  const expected = await pbkdf2Sha512(
    utf8('correct horse battery staple'), utf8('alex@example.com'), 1000, 32,
  );
  assert.equal(bytesToHex(mk), bytesToHex(expected));
});

test('computeKcv returns a 4-byte base64 string, deterministic, key-sensitive', async () => {
  const a = await computeKcv(FIXED_MK);
  const b = await computeKcv(FIXED_MK);
  assert.equal(a, b);
  assert.match(a, /^[A-Za-z0-9+/]{5,8}={0,2}$/);
  const other = await computeKcv(hexToBytes('cd'.repeat(32)));
  assert.notEqual(a, other);
});

test('derivePassword with a fixed masterKey: deterministic, right length, all classes', async () => {
  const params = {
    masterKey: FIXED_MK, site: 'github.com', account: 'alex',
    counter: 1, rules: 'standard', length: 20,
  };
  const p1 = await derivePassword(params);
  const p2 = await derivePassword(params);
  assert.equal(p1, p2);
  assert.equal(p1.length, 20);
  const present = classesPresent(p1);
  for (const c of ['lower', 'upper', 'digit', 'symbol']) assert.ok(present.has(c));
  for (const ch of p1) assert.ok(CHARSETS.standard.includes(ch));
});

test('derivePassword: counter bump changes the password', async () => {
  const base = { masterKey: FIXED_MK, site: 'x', account: 'y', counter: 1, rules: 'standard', length: 16 };
  assert.notEqual(await derivePassword(base), await derivePassword({ ...base, counter: 2 }));
});

test('derivePassword: validates length and counter', async () => {
  await assert.rejects(() => derivePassword({ masterKey: FIXED_MK, site: 'x', account: 'y', length: 7 }));
  await assert.rejects(() => derivePassword({ masterKey: FIXED_MK, site: 'x', account: 'y', length: 65 }));
  await assert.rejects(() => derivePassword({ masterKey: FIXED_MK, site: 'x', account: 'y', counter: 0 }));
  await assert.rejects(() => derivePassword({ masterKey: FIXED_MK, site: 'x', account: 'y', rules: 'nope' }));
});

test('derivePassword: normalises site and account before deriving', async () => {
  const a = await derivePassword({ masterKey: FIXED_MK, site: 'GitHub.com', account: 'Alex', length: 16 });
  const b = await derivePassword({ masterKey: FIXED_MK, site: 'github.com', account: 'alex', length: 16 });
  assert.equal(a, b);
});
