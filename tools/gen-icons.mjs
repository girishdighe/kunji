// Dependency-free PNG icon generator. Flat brand ground (#0F1419) with a centred
// blue square (#1D9BF0) at ~46% side. Deterministic: no RNG, fixed filter 0.
import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';

const CRC = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return (buf) => {
    let c = 0xffffffff;
    for (let i = 0; i < buf.length; i++) c = t[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
})();

function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0);
  const body = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(CRC(body), 0);
  return Buffer.concat([len, body, crc]);
}

function png(size) {
  const bg = [0x0f, 0x14, 0x19, 0xff];
  const fg = [0x1d, 0x9b, 0xf0, 0xff];
  const inset = Math.round(size * 0.27);
  const raw = Buffer.alloc(size * (1 + size * 4));
  for (let y = 0; y < size; y++) {
    const row = y * (1 + size * 4);
    raw[row] = 0; // filter: none
    for (let x = 0; x < size; x++) {
      const inSquare = x >= inset && x < size - inset && y >= inset && y < size - inset;
      const px = inSquare ? fg : bg;
      raw.set(px, row + 1 + x * 4);
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

const outDir = process.argv[2] || 'dist/pwa';
mkdirSync(outDir, { recursive: true });
for (const [name, size] of [['icon-192.png', 192], ['icon-512.png', 512], ['icon-512-maskable.png', 512], ['apple-touch-icon.png', 180]]) {
  writeFileSync(`${outDir}/${name}`, png(size));
}
console.log(`icons written to ${outDir}`);
