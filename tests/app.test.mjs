import { test } from 'node:test';
import assert from 'node:assert/strict';
import { estimateEntropyBits, groupInFours } from '../src/app.js';

test('estimateEntropyBits = floor(length * log2(charsetSize))', () => {
  assert.equal(estimateEntropyBits(20, 72), Math.floor(20 * Math.log2(72)));
  assert.equal(estimateEntropyBits(16, 62), 95); // 16 * 5.954... = 95.27 -> 95
  assert.equal(estimateEntropyBits(0, 72), 0);
});

test('groupInFours inserts a space every 4 chars, no trailing space', () => {
  assert.equal(groupInFours('abcdefghij'), 'abcd efgh ij');
  assert.equal(groupInFours('abcd'), 'abcd');
  assert.equal(groupInFours(''), '');
});
