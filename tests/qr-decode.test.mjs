import { test } from 'node:test';
import assert from 'node:assert/strict';
import { qrMatrix } from '../src/qr.js';
import { decodeQr } from '../src/qr-decode.js';

// Render a boolean matrix to an RGBA image with a `quiet`-module border, scaled ×`s`.
function render(matrix, { quiet = 4, s = 4 } = {}) {
  const n = matrix.length;
  const dim = (n + quiet * 2) * s;
  const data = new Uint8ClampedArray(dim * dim * 4).fill(255);
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) {
    if (!matrix[y][x]) continue;
    for (let dy = 0; dy < s; dy++) for (let dx = 0; dx < s; dx++) {
      const px = ((quiet + x) * s + dx) + ((quiet + y) * s + dy) * dim;
      data[px * 4] = data[px * 4 + 1] = data[px * 4 + 2] = 0;
    }
  }
  return { data, width: dim, height: dim };
}
function rot90(img) {
  const { data, width: w, height: h } = img;
  const out = new Uint8ClampedArray(data.length);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const s = (y * w + x) * 4, d = (x * h + (h - 1 - y)) * 4;
    out[d] = data[s]; out[d + 1] = data[s + 1]; out[d + 2] = data[s + 2]; out[d + 3] = data[s + 3];
  }
  return { data: out, width: h, height: w };
}

const CASES = [
  { bytes: [...Buffer.from('HELLO WORLD')], ecc: 'M' },
  { bytes: Array.from({ length: 64 }, (_, i) => (i * 37 + 11) & 0xff), ecc: 'L' },
  { bytes: Array.from({ length: 180 }, (_, i) => (i * 97 + 5) & 0xff), ecc: 'Q' },
  { bytes: Array.from({ length: 300 }, (_, i) => (i * 53 + 9) & 0xff), ecc: 'H' },
];

for (const c of CASES) {
  test(`round-trip ${c.bytes.length}B / ${c.ecc}`, () => {
    const img = render(qrMatrix(Uint8Array.from(c.bytes), { ecc: c.ecc }), { s: 5 });
    assert.deepEqual([...decodeQr(img)], c.bytes);
  });
  test(`round-trip ${c.bytes.length}B / ${c.ecc} rotated 90/180/270`, () => {
    let img = render(qrMatrix(Uint8Array.from(c.bytes), { ecc: c.ecc }), { s: 5 });
    for (let i = 0; i < 3; i++) { img = rot90(img); assert.deepEqual([...decodeQr(img)], c.bytes); }
  });
}

test('flipping modules within the RS budget still decodes; past it -> null', () => {
  const bytes = Array.from({ length: 100 }, (_, i) => i & 0xff);
  const m = qrMatrix(Uint8Array.from(bytes), { ecc: 'H' }); // H = ~30% recovery
  for (const [y, x] of [[10, 10], [10, 11], [11, 10], [12, 12]]) m[y][x] = !m[y][x];
  assert.deepEqual([...decodeQr(render(m, { s: 5 }))], bytes);
  // 100 bytes at H is version 10: 8 blocks x 28 EC codewords, so each block
  // tolerates floor(28/2) = 14 symbol errors. A 12x12 flip only reaches 25
  // codewords, spread [3,2,5,5,4,2,2,2] across those 8 blocks -- comfortably
  // inside the budget, so a conforming decoder is required to recover it.
  // Wreck 32x32 instead: 143 corrupt codewords, 16-20 per block, past the
  // budget everywhere. Finders, timing and both format copies stay intact, so
  // the null comes from RS exhaustion rather than a failed detection.
  for (let y = 8; y < 40; y++) for (let x = 8; x < 40; x++) m[y][x] = !m[y][x];
  assert.equal(decodeQr(render(m, { s: 5 })), null);
});

test('blank / noise image -> null, never throws', () => {
  assert.equal(decodeQr({ data: new Uint8ClampedArray(200 * 200 * 4).fill(255), width: 200, height: 200 }), null);
  const noise = new Uint8ClampedArray(200 * 200 * 4);
  for (let i = 0; i < noise.length; i++) noise[i] = (i * 2654435761) & 0xff;
  assert.equal(decodeQr({ data: noise, width: 200, height: 200 }), null);
});
