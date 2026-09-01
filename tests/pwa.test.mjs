import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

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

test('buildPwa emits dist/pwa/ derived from dist/kunji.html', () => {
  execFileSync('node', ['tools/build.mjs'], { stdio: 'pipe' });
  const single = readFileSync('dist/kunji.html', 'utf8');
  const idx = readFileSync('dist/pwa/index.html', 'utf8');

  // CSP: gains worker-src 'self', never gains connect-src
  const csp = idx.match(/Content-Security-Policy" content="([^"]+)"/)[1];
  assert.ok(csp.includes("worker-src 'self'"), 'worker-src added');
  assert.ok(!csp.includes('connect-src'), 'no connect-src');

  assert.ok(idx.includes('<link rel="manifest" href="manifest.webmanifest">'), 'manifest link');
  assert.ok(idx.includes("navigator.serviceWorker.register('./sw.js')"), 'sw registration');

  // <style> and app <script> are byte-identical to the single file
  const styleOf = (s) => s.match(/<style>[\s\S]*?<\/style>/)[0];
  const scriptOf = (s) => s.match(/<script>[\s\S]*?<\/script>\s*<\/body>/)[0];
  assert.equal(styleOf(idx), styleOf(single), 'style identical');
  assert.equal(scriptOf(idx), scriptOf(single), 'app script identical');

  const sw = readFileSync('dist/pwa/sw.js', 'utf8');
  const shellHash = createHash('sha256').update(readFileSync('dist/pwa/index.html')).digest('hex');
  assert.ok(sw.includes(`'${shellHash}'`), 'SHELL_VERSION == sha256(index.html)');
  for (const a of ['./', './index.html', './sw.js', './manifest.webmanifest', './icon-192.png', './icon-512.png', './icon-512-maskable.png', './apple-touch-icon.png']) {
    assert.ok(sw.includes(`"${a}"`), `SHELL_ASSETS has ${a}`);
  }
  assert.doesNotMatch(sw, /__SHELL_/, 'placeholders filled');

  const man = JSON.parse(readFileSync('dist/pwa/manifest.webmanifest', 'utf8'));
  assert.equal(man.start_url, './index.html');
  assert.ok(man.icons.every((i) => !/^https?:|^\//.test(i.src)), 'relative icon srcs');

  for (const f of ['index.html', 'sw.js', 'manifest.webmanifest']) {
    assert.doesNotMatch(readFileSync(`dist/pwa/${f}`, 'utf8'), /https?:\/\//, `${f} has no URLs`);
  }
});

test('build --no-pwa skips dist/pwa and leaves kunji.html identical', () => {
  execFileSync('node', ['tools/build.mjs'], { stdio: 'pipe' });
  const withPwa = readFileSync('dist/kunji.html');
  rmSync('dist/pwa', { recursive: true, force: true });
  execFileSync('node', ['tools/build.mjs', '--no-pwa'], { stdio: 'pipe' });
  assert.ok(!existsSync('dist/pwa'), 'no dist/pwa');
  assert.ok(withPwa.equals(readFileSync('dist/kunji.html')), 'kunji.html unchanged');
  execFileSync('node', ['tools/build.mjs'], { stdio: 'pipe' }); // restore for later tests
});

test('check-invariants passes with dist/pwa present and reports it', () => {
  execFileSync('node', ['tools/build.mjs'], { stdio: 'pipe' });
  const out = execFileSync('node', ['tools/check-invariants.mjs'], { encoding: 'utf8' });
  assert.match(out, /invariants ok/);
});

test('check-invariants fails if dist/pwa gains an external URL', () => {
  execFileSync('node', ['tools/build.mjs'], { stdio: 'pipe' });
  const p = 'dist/pwa/manifest.webmanifest';
  const orig = readFileSync(p, 'utf8');
  writeFileSync(p, orig.replace('"./index.html"', '"https://evil.example/x"'));
  let failed = false;
  try { execFileSync('node', ['tools/check-invariants.mjs'], { stdio: 'pipe' }); }
  catch { failed = true; }
  writeFileSync(p, orig);
  assert.ok(failed, 'external URL in dist/pwa must fail the scan');
});
