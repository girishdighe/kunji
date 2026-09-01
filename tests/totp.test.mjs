import { test } from 'node:test';
import assert from 'node:assert/strict';
import { base32Decode, hotp, totp, parseOtpauth } from '../src/totp.js';

const td = (u8) => Buffer.from(u8).toString('latin1');

test('base32Decode: RFC 4648 examples', () => {
  assert.equal(td(base32Decode('MY======')), 'f');
  assert.equal(td(base32Decode('MZXW6===')), 'foo');
  assert.equal(td(base32Decode('MZXW6YTBOI======')), 'foobar');
});

test('base32Decode: case-insensitive, tolerates spaces and missing padding', () => {
  assert.equal(td(base32Decode('mzxw6ytboi')), 'foobar');
  assert.equal(td(base32Decode('MZXW 6YTB OI')), 'foobar');
});

test('base32Decode: throws on a non-alphabet char', () => {
  assert.throws(() => base32Decode('MZXW0YTB'));   // 0 and 1 are not in base32
  assert.throws(() => base32Decode('abc!def'));
});

test('hotp: RFC 4226 Appendix D vectors (secret "12345678901234567890")', async () => {
  const key = new TextEncoder().encode('12345678901234567890');
  const expected = ['755224','287082','359152','969429','338314','254676','287922','162583','399871','520489'];
  for (let c = 0; c < 10; c++) {
    assert.equal(await hotp(key, c, { algorithm: 'SHA-1', digits: 6 }), expected[c], `counter ${c}`);
  }
});

const SEED_SHA1 = '12345678901234567890';
const SEED_SHA256 = '12345678901234567890123456789012';
const SEED_SHA512 = '1234567890123456789012345678901234567890123456789012345678901234';
const b32 = (ascii) => {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes = new TextEncoder().encode(ascii);
  let bits = 0, val = 0, out = '';
  for (const byte of bytes) { val = (val << 8) | byte; bits += 8;
    while (bits >= 5) { bits -= 5; out += A[(val >>> bits) & 31]; } }
  if (bits > 0) out += A[(val << (5 - bits)) & 31];
  return out;
};

const RFC6238 = [
  [59,          '94287082', 'SHA-1',   SEED_SHA1],
  [1111111109,  '07081804', 'SHA-1',   SEED_SHA1],
  [1234567890,  '89005924', 'SHA-1',   SEED_SHA1],
  [2000000000,  '69279037', 'SHA-1',   SEED_SHA1],
  [59,          '46119246', 'SHA-256', SEED_SHA256],
  [1111111109,  '68084774', 'SHA-256', SEED_SHA256],
  [59,          '90693936', 'SHA-512', SEED_SHA512],
  [1234567890,  '93441116', 'SHA-512', SEED_SHA512],
];

for (const [t, code, algorithm, seed] of RFC6238) {
  test(`totp: RFC 6238 ${algorithm} @ ${t}`, async () => {
    const r = await totp({ secret: b32(seed), algorithm, digits: 8, period: 30 }, { now: t * 1000 });
    assert.equal(r.code, code);
    assert.equal(r.period, 30);
  });
}

test('totp: secondsRemaining is period at a boundary and 1 just before', async () => {
  const o = { secret: b32(SEED_SHA1), algorithm: 'SHA-1', digits: 6, period: 30 };
  assert.equal((await totp(o, { now: 30_000 })).secondsRemaining, 30);
  assert.equal((await totp(o, { now: 29_000 })).secondsRemaining, 1);
});

test('parseOtpauth: full URI -> fields', () => {
  const r = parseOtpauth('otpauth://totp/ACME:alice@acme.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA256&digits=8&period=60');
  assert.equal(r.secret, 'JBSWY3DPEHPK3PXP');
  assert.equal(r.algorithm, 'SHA-256');
  assert.equal(r.digits, 8);
  assert.equal(r.period, 60);
  assert.equal(r.issuer, 'ACME');
});

test('parseOtpauth: defaults and rejects', () => {
  const r = parseOtpauth('otpauth://totp/x?secret=ABCDEF');
  assert.equal(r.algorithm, 'SHA-1');
  assert.equal(r.digits, 6);
  assert.equal(r.period, 30);
  assert.equal(parseOtpauth('otpauth://hotp/x?secret=A&counter=0'), null);
  assert.equal(parseOtpauth('https://example.com'), null);
  assert.equal(parseOtpauth('not a uri'), null);
});
