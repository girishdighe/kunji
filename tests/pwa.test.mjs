import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync, rmSync } from 'node:fs';

test('gen-icons writes four valid PNGs', () => {
  rmSync('dist/pwa', { recursive: true, force: true });
  execFileSync('node', ['tools/gen-icons.mjs', 'dist/pwa'], { stdio: 'pipe' });
  for (const [name, w] of [['icon-192.png', 192], ['icon-512.png', 512], ['icon-512-maskable.png', 512], ['apple-touch-icon.png', 180]]) {
    const p = `dist/pwa/${name}`;
    assert.ok(existsSync(p), `${name} exists`);
    const b = readFileSync(p);
    assert.deepEqual([...b.slice(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], `${name} PNG signature`);
    // IHDR width at bytes 16..20 (big-endian)
    assert.equal(b.readUInt32BE(16), w, `${name} width`);
  }
});

test('gen-icons is deterministic', () => {
  execFileSync('node', ['tools/gen-icons.mjs', 'dist/pwa'], { stdio: 'pipe' });
  const a = readFileSync('dist/pwa/icon-192.png');
  execFileSync('node', ['tools/gen-icons.mjs', 'dist/pwa'], { stdio: 'pipe' });
  const b = readFileSync('dist/pwa/icon-192.png');
  assert.ok(a.equals(b), 'byte-identical across runs');
});
