import { test } from 'node:test';
import assert from 'node:assert/strict';

test('node test runner works', () => {
  assert.equal(1 + 1, 2);
});

test('crypto.subtle is available', () => {
  assert.ok(globalThis.crypto && globalThis.crypto.subtle, 'crypto.subtle missing; need Node >= 20');
});
