import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  utf8, fromUtf8, uint32be, concatBytes,
  bytesToHex, hexToBytes, bytesToBase64, base64ToBytes,
} from '../src/encoding.js';

test('utf8 / fromUtf8 round-trip incl. non-ASCII', () => {
  const s = 'héllo · 世界';
  assert.equal(fromUtf8(utf8(s)), s);
});

test('utf8 of "abc" is 0x61 0x62 0x63', () => {
  assert.deepEqual([...utf8('abc')], [0x61, 0x62, 0x63]);
});

test('uint32be encodes big-endian', () => {
  assert.deepEqual([...uint32be(0)], [0, 0, 0, 0]);
  assert.deepEqual([...uint32be(1)], [0, 0, 0, 1]);
  assert.deepEqual([...uint32be(0x01020304)], [1, 2, 3, 4]);
  assert.deepEqual([...uint32be(0xffffffff)], [255, 255, 255, 255]);
});

test('concatBytes joins in order', () => {
  const out = concatBytes(Uint8Array.of(1, 2), Uint8Array.of(), Uint8Array.of(3));
  assert.deepEqual([...out], [1, 2, 3]);
});

test('hex round-trip', () => {
  const bytes = Uint8Array.of(0, 15, 16, 255);
  assert.equal(bytesToHex(bytes), '000f10ff');
  assert.deepEqual([...hexToBytes('000f10ff')], [0, 15, 16, 255]);
});

test('hexToBytes rejects odd length', () => {
  assert.throws(() => hexToBytes('abc'));
});

test('base64 round-trip and known value', () => {
  assert.equal(bytesToBase64(utf8('hello')), 'aGVsbG8=');
  assert.equal(fromUtf8(base64ToBytes('aGVsbG8=')), 'hello');
});

import { uint64be } from '../src/encoding.js';

test('uint64be is 8 big-endian bytes', () => {
  assert.deepEqual([...uint64be(0)], [0, 0, 0, 0, 0, 0, 0, 0]);
  assert.deepEqual([...uint64be(1)], [0, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual([...uint64be(0x0102030405)], [0, 0, 0, 1, 2, 3, 4, 5]);
  assert.deepEqual([...uint64be(0xffffffff)], [0, 0, 0, 0, 255, 255, 255, 255]);
});
