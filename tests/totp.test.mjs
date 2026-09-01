import { test } from 'node:test';
import assert from 'node:assert/strict';
import { base32Decode, hotp } from '../src/totp.js';

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
