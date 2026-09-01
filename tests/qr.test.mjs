import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { qrMatrix, QR_CAPACITY } from '../src/qr.js';

for (const f of readdirSync('tests/fixtures/qr').filter((x) => x.endsWith('.json'))) {
  const fx = JSON.parse(readFileSync(`tests/fixtures/qr/${f}`, 'utf8'));
  test(`qrMatrix reproduces fixture ${fx.name}`, () => {
    const m = qrMatrix(Uint8Array.from(fx.bytes), { ecc: fx.ecc });
    assert.equal(m.length, fx.size);
    assert.deepEqual(m.map((r) => r.map((b) => (b ? 1 : 0)).join('')), fx.rows);
  });
}

test('qrMatrix picks the smallest fitting version', () => {
  const small = qrMatrix(Uint8Array.from(Buffer.from('x')), { ecc: 'M' });
  assert.equal(small.length, 21); // v1
});

test('qrMatrix throws past v40 capacity', () => {
  assert.throws(() => qrMatrix(new Uint8Array(QR_CAPACITY[40].L + 1), { ecc: 'L' }));
});

test('qrMatrix is deterministic', () => {
  const b = Uint8Array.from(Buffer.from('deterministic?'));
  assert.deepEqual(qrMatrix(b, { ecc: 'Q' }), qrMatrix(b, { ecc: 'Q' }));
});
