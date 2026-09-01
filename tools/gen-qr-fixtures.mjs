import { writeFileSync, mkdirSync } from 'node:fs';
import { qrMatrix } from '../src/qr.js';

mkdirSync('tests/fixtures/qr', { recursive: true });
const cases = [
  { name: 'hello-world-1M', bytes: [...Buffer.from('HELLO WORLD')], ecc: 'M' },
  { name: 'ascii-32-1L', bytes: Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff), ecc: 'L' },
  { name: 'bytes-220-6H', bytes: Array.from({ length: 220 }, (_, i) => (i * 131 + 17) & 0xff), ecc: 'H' },
];
for (const c of cases) {
  const m = qrMatrix(Uint8Array.from(c.bytes), { ecc: c.ecc });
  writeFileSync(`tests/fixtures/qr/${c.name}.json`, JSON.stringify({
    ...c, size: m.length, rows: m.map((r) => r.map((b) => (b ? 1 : 0)).join('')),
  }, null, 0) + '\n');
}
console.log('qr fixtures written');
