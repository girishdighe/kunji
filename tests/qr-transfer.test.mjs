import { test } from 'node:test';
import assert from 'node:assert/strict';
import { splitTransfer, joinTransfer } from '../src/qr-transfer.js';

const TEXT = JSON.stringify({ format: 'kunji-data', v: 1, ct: 'x'.repeat(1200) });

test('split then join (in order) round-trips', () => {
  const frames = splitTransfer(TEXT, { frameBytes: 200 });
  assert.ok(frames.length > 1);
  assert.deepEqual(joinTransfer(frames), { text: TEXT });
});

test('join tolerates shuffled frames', () => {
  const frames = splitTransfer(TEXT, { frameBytes: 200 }).slice().reverse();
  assert.deepEqual(joinTransfer(frames), { text: TEXT });
});

test('single-frame case', () => {
  const frames = splitTransfer('short', { frameBytes: 400 });
  assert.equal(frames.length, 1);
  assert.deepEqual(joinTransfer(frames), { text: 'short' });
});

test('missing a frame -> { need: [k] }', () => {
  const frames = splitTransfer(TEXT, { frameBytes: 200 });
  const got = joinTransfer(frames.filter((_, i) => i !== 2));
  assert.deepEqual(got.need, [2]);
});

test('a frame with a different nonce is ignored, not an error', () => {
  const a = splitTransfer(TEXT, { frameBytes: 200 });
  const b = splitTransfer('OTHER TRANSFER ENTIRELY', { frameBytes: 200 });
  const mixed = [a[0], b[0], a[1], ...a.slice(2)];
  assert.deepEqual(joinTransfer(mixed), { text: TEXT });
});

test('malformed frame -> { error }', () => {
  assert.ok(joinTransfer(['not a KQR1 frame']).error);
  assert.ok(joinTransfer([]).error);
});

test('every produced frame string is <= frameBytes', () => {
  for (const f of splitTransfer(TEXT, { frameBytes: 200 })) {
    assert.ok(Buffer.byteLength(f, 'utf8') <= 200, f.length);
  }
});
