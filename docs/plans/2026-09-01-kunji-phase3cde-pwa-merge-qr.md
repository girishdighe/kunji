# Kunji Phase 3c + 3d + 3e — PWA, Sync Merge, QR Transfer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship (C) an installable offline PWA build derived from `dist/kunji.html`, (D) tombstone-based per-entry sync merge with a review screen, and (E) whole-vault QR transfer with a hand-rolled zero-dependency codec and an in-app camera scanner.

**Architecture:**
- **C** touches only `tools/`. `tools/build.mjs` keeps emitting the pure `dist/kunji.html`, then a `buildPwa()` step derives `dist/pwa/` (index.html + sw.js + manifest + icons). CSP adds only `worker-src 'self'`; no `connect-src`.
- **D** adds tombstones (`{id,deleted:true,updatedAt}`, additive, no `v` bump). `removeEntry` tombstones instead of splicing; a `visibleEntries` filter feeds every consumer. Pure `mergeVaults` (entry-level last-writer-wins) and `classifyIncoming` route an imported file to a merge summary screen.
- **E** adds three pure modules — `src/qr.js` (encoder), `src/qr-decode.js` (decoder), `src/qr-transfer.js` (`KQR1` framing) — plus a camera panel in the Vault tab. Import while unlocked reuses D's `classifyIncoming`.

**Tech Stack:** Node ≥ 20 (`node:test`, `node:zlib`, `globalThis.crypto`), browser Web Crypto + `getUserMedia` + `<canvas>`, plain HTML/CSS/JS, zero runtime dependencies. Build is concatenation via `tools/build.mjs`.

**Specs:**
- `docs/specs/2026-09-01-kunji-phase3c-pwa-service-worker-design.md`
- `docs/specs/2026-09-01-kunji-phase3d-sync-merge-design.md`
- `docs/specs/2026-09-01-kunji-phase3e-qr-transfer-design.md`
- Parent: `docs/specs/2026-09-01-kunji-design.md` §5.2, §7.2, §7.3, §7.4, §12.
- **Standard for Part E:** ISO/IEC 18004 (QR Code). Clause numbers below refer to the 2015 edition.

**Baseline:** Phase 2 + 2.1 on `main` (`971b57b` or later). Recommended: land the Phase 3a+3b plan first — Part E's import-while-unlocked route depends on Part D's `classifyIncoming`, and Part D's `visibleEntries` must also filter the account-picker bridge from 3a. This plan **assumes 3a+3b are merged**; if not, skip the bridge line in Task D4 and the `classifyIncoming` branch in Task E7 (they degrade to "open a different file").

Work from `the repository root`, directly on `main`, one commit per task. Trailers:

```
Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01E2FKUJXdFejXkG1iuXB83A
```

Use `git -c commit.gpgsign=false commit` if signing prompts. `node --test` prints `ℹ tests N` / `ℹ pass N` / `ℹ fail 0`; **`fail 0` is the gate**.

---

## File structure

| File | Change | Responsibility |
|---|---|---|
| `tools/build.mjs` | + `buildPwa()`, `--no-pwa` flag; `JS_ORDER` gets the three qr modules (Part E) | build |
| `tools/pwa/sw.js` | **new** — service-worker template with `__SHELL_VERSION__` / `__SHELL_ASSETS__` | C |
| `tools/pwa/manifest.webmanifest` | **new** | C |
| `tools/pwa/head-extra.html` | **new** — 2 `<link>` lines | C |
| `tools/pwa/register.html` | **new** — SW registration + update bar | C |
| `tools/gen-icons.mjs` | **new** — dependency-free PNG icon generator | C |
| `tools/check-invariants.mjs` | + a `dist/pwa/` relaxed pass | C |
| `src/vault.js` | `removeEntry` → tombstone; + `visibleEntries`, `mergeVaults`, `classifyIncoming` | D |
| `src/vault-ui.js` | consumers use `visibleEntries`; import routing; merge summary screen; `Merge another copy…`; camera panels (E) | D, E |
| `src/qr.js` | **new** — QR byte-mode encoder → module grid | E |
| `src/qr-decode.js` | **new** — `ImageData` → payload bytes | E |
| `src/qr-transfer.js` | **new** — `KQR1` split/join | E |
| `src/style.css` | `.v-merge-*` (D), `.qr-*` (E) | D, E |
| `tools/gen-qr-fixtures.mjs` | **new** — frozen encoder outputs | E |
| `tests/*` | new/extended per task | — |
| `docs/specs/2026-09-01-kunji-design.md` | §5.2, §7.2, §7.3, §7.4, §12 | C, D, E |

---

# PART C — PWA + service worker (Tasks C1–C5)

## Task C1: Icon generator

**Files:**
- Create: `tools/gen-icons.mjs`
- Test: `tests/pwa.test.mjs` (new)

- [ ] **Step 1: Write the failing test**

Create `tests/pwa.test.mjs`:

```js
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/pwa.test.mjs`
Expected: FAIL — `Cannot find module 'tools/gen-icons.mjs'`.

- [ ] **Step 3: Implement `tools/gen-icons.mjs`**

```js
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/pwa.test.mjs` — PASS (2).
Run: `node --test` — `fail 0`.

- [ ] **Step 5: Commit**

```bash
git add tools/gen-icons.mjs tests/pwa.test.mjs
git -c commit.gpgsign=false commit -m "feat: dependency-free PWA icon generator"
```

---

## Task C2: PWA build inputs

**Files:**
- Create: `tools/pwa/manifest.webmanifest`, `tools/pwa/head-extra.html`, `tools/pwa/register.html`, `tools/pwa/sw.js`
- Test: none yet (wired in C3)

- [ ] **Step 1: Create `tools/pwa/manifest.webmanifest`**

```json
{
  "name": "Kunji",
  "short_name": "Kunji",
  "description": "Offline password tool. Nothing stored or sent.",
  "start_url": "./index.html",
  "scope": "./",
  "display": "standalone",
  "background_color": "#000000",
  "theme_color": "#000000",
  "icons": [
    { "src": "icon-192.png", "sizes": "192x192", "type": "image/png" },
    { "src": "icon-512.png", "sizes": "512x512", "type": "image/png" },
    { "src": "icon-512-maskable.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable" }
  ]
}
```

- [ ] **Step 2: Create `tools/pwa/head-extra.html`**

```html
<link rel="manifest" href="manifest.webmanifest">
<link rel="apple-touch-icon" href="apple-touch-icon.png">
```

- [ ] **Step 3: Create `tools/pwa/register.html`**

```html
<div id="swUpdateBar" hidden style="position:fixed;left:0;right:0;bottom:0;background:#16181C;border-top:1px solid #2F3336;color:#E7E9EA;font:600 13px -apple-system,BlinkMacSystemFont,sans-serif;padding:12px 16px;display:flex;justify-content:space-between;align-items:center;z-index:9999">
  <span>New version available</span>
  <button id="swReload" type="button" style="background:#1D9BF0;border:none;color:#fff;border-radius:9999px;padding:8px 16px;font:inherit;cursor:pointer">Reload</button>
</div>
<script>
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('./sw.js').then(function (reg) {
    reg.addEventListener('updatefound', function () {
      var w = reg.installing;
      if (!w) return;
      w.addEventListener('statechange', function () {
        if (w.state === 'installed' && navigator.serviceWorker.controller) {
          var bar = document.getElementById('swUpdateBar');
          bar.hidden = false;
          document.getElementById('swReload').addEventListener('click', function () {
            w.postMessage({ type: 'SKIP_WAITING' });
          });
        }
      });
    });
  });
  var reloaded = false;
  navigator.serviceWorker.addEventListener('controllerchange', function () {
    if (reloaded) return; reloaded = true; location.reload();
  });
}
</script>
```

- [ ] **Step 4: Create `tools/pwa/sw.js`**

```js
const SHELL_VERSION = '__SHELL_VERSION__';
const SHELL_ASSETS = __SHELL_ASSETS__;
const CACHE = 'kunji-' + SHELL_VERSION;

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL_ASSETS)));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith('kunji-') && k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET') return;
  e.respondWith(caches.match(e.request).then((r) => r || fetch(e.request)));
});

self.addEventListener('message', (e) => {
  if (e.data && e.data.type === 'SKIP_WAITING') self.skipWaiting();
});
```

- [ ] **Step 5: Commit**

```bash
git add tools/pwa
git -c commit.gpgsign=false commit -m "feat: PWA build inputs (manifest, sw template, head/register snippets)"
```

---

## Task C3: `buildPwa()` in `tools/build.mjs`

**Files:**
- Modify: `tools/build.mjs`
- Test: `tests/pwa.test.mjs` (append), `tests/build.test.mjs` (append)

- [ ] **Step 1: Append the failing tests**

To `tests/pwa.test.mjs`:

```js
import { createHash } from 'node:crypto';

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
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/pwa.test.mjs`
Expected: FAIL — `dist/pwa/index.html` does not exist.

- [ ] **Step 3: Implement — append to `tools/build.mjs`**

After the existing `console.log(...)` line at the end, add:

```js
import { createHash } from 'node:crypto';
import { cpSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

function buildPwa(shellHtml) {
  const headExtra = readFileSync('tools/pwa/head-extra.html', 'utf8').trim();
  const register = readFileSync('tools/pwa/register.html', 'utf8').trim();

  let idx = shellHtml.replace(
    /(<meta http-equiv="Content-Security-Policy" content="[^"]*?)(">)/,
    (_m, a, b) => `${a}; worker-src 'self'${b}`,
  );
  idx = idx.replace('</head>', `${headExtra}\n</head>`);
  idx = idx.replace('</body>', `${register}\n</body>`);

  mkdirSync('dist/pwa', { recursive: true });
  writeFileSync('dist/pwa/index.html', idx);

  const shellVersion = createHash('sha256').update(readFileSync('dist/pwa/index.html')).digest('hex');
  const assets = ['./', './index.html', './sw.js', './manifest.webmanifest',
    './icon-192.png', './icon-512.png', './icon-512-maskable.png', './apple-touch-icon.png'];
  const sw = readFileSync('tools/pwa/sw.js', 'utf8')
    .replace('__SHELL_VERSION__', shellVersion)
    .replace('__SHELL_ASSETS__', JSON.stringify(assets));
  writeFileSync('dist/pwa/sw.js', sw);

  cpSync('tools/pwa/manifest.webmanifest', 'dist/pwa/manifest.webmanifest');
  execFileSync('node', ['tools/gen-icons.mjs', 'dist/pwa'], { stdio: 'pipe' });
  console.log('dist/pwa/ written');
}

if (!process.argv.includes('--no-pwa')) {
  buildPwa(html);
}
```

(Move the three `import` lines to the top of the file with the others if your
linter prefers; Node accepts `import` only at module top level, so **put them at
the very top** next to `import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';`
and delete the inline `import` lines above.)

Final import block at the top of `tools/build.mjs`:

```js
import { readFileSync, writeFileSync, mkdirSync, cpSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/pwa.test.mjs` — PASS.
Run: `node --test` — `fail 0`.
Run: `node tools/build.mjs` — prints `dist/kunji.html written …` then `dist/pwa/ written`.

- [ ] **Step 5: Commit**

```bash
git add tools/build.mjs tests/pwa.test.mjs tests/build.test.mjs
git -c commit.gpgsign=false commit -m "feat: buildPwa() emits dist/pwa from the single-file shell"
```

---

## Task C4: `check-invariants.mjs` — `dist/pwa/` relaxed pass

**Files:**
- Modify: `tools/check-invariants.mjs`
- Test: `tests/pwa.test.mjs` (append)

- [ ] **Step 1: Append the failing test**

```js
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
```

(Needs `import { writeFileSync } from 'node:fs';` at the top of `tests/pwa.test.mjs`
— add it.)

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/pwa.test.mjs`
Expected: the second new test FAILS (the scanner doesn't look at `dist/pwa/`).

- [ ] **Step 3: Implement — replace `tools/check-invariants.mjs`**

```js
import { readFileSync, existsSync, readdirSync } from 'node:fs';

// Strict pass: shipped single-file output and every source file.
const STRICT = [
  /\bfetch\s*\(/,
  /XMLHttpRequest/,
  /\bWebSocket\b/,
  /sendBeacon/,
  /<script[^>]+\bsrc=/i,
  /<link\b/i,
  /@import\b/,
  /https?:\/\//,
];

const strictTargets = [];
for (const f of readdirSync('src')) strictTargets.push(`src/${f}`);
if (existsSync('dist/kunji.html')) strictTargets.push('dist/kunji.html');

let failed = false;
for (const path of strictTargets) {
  const text = readFileSync(path, 'utf8');
  for (const rx of STRICT) {
    if (rx.test(text)) { console.error(`INVARIANT VIOLATION in ${path}: ${rx}`); failed = true; }
  }
}

// Relaxed pass: the PWA build. Still no external origins, still no connect-src.
// The manifest <link>, the same-origin serviceWorker.register, and (only in
// sw.js) caches/fetch are allowed.
if (existsSync('dist/pwa')) {
  for (const f of readdirSync('dist/pwa')) {
    if (!/\.(html|js|webmanifest)$/.test(f)) continue; // skip PNGs
    const path = `dist/pwa/${f}`;
    const text = readFileSync(path, 'utf8');
    if (/https?:\/\//.test(text)) { console.error(`INVARIANT VIOLATION in ${path}: external URL`); failed = true; }
    if (/connect-src/.test(text)) { console.error(`INVARIANT VIOLATION in ${path}: connect-src`); failed = true; }
    if (f !== 'sw.js') {
      if (/\bfetch\s*\(/.test(text)) { console.error(`INVARIANT VIOLATION in ${path}: fetch() outside sw.js`); failed = true; }
      if (/XMLHttpRequest|\bWebSocket\b|sendBeacon/.test(text)) { console.error(`INVARIANT VIOLATION in ${path}: network API`); failed = true; }
    }
  }
}

if (failed) process.exit(1);
const count = strictTargets.length + (existsSync('dist/pwa') ? readdirSync('dist/pwa').filter((f) => /\.(html|js|webmanifest)$/.test(f)).length : 0);
console.log(`invariants ok (${count} files)`);
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/pwa.test.mjs` — PASS.
Run: `npm run verify` — all pass; `dist/kunji.html written`; `dist/pwa/ written`;
`invariants ok (N files)` with N ≥ 14.

- [ ] **Step 5: Commit**

```bash
git add tools/check-invariants.mjs tests/pwa.test.mjs
git -c commit.gpgsign=false commit -m "feat: check-invariants relaxed pass for dist/pwa"
```

---

## Task C5: Docs + manual PWA verification

**Files:**
- Modify: `docs/specs/2026-09-01-kunji-design.md`, `README.md`
- Manual test: Chrome

- [ ] **Step 1: Parent spec §7.2** — add after the "Self-hosted PWA" bullet:

```
- **Update model.** A new deploy shows a "New version available — Reload" bar in
  the running app. Nothing changes until the user clicks; then the new shell
  activates and the page reloads once.
```

- [ ] **Step 2: Parent spec §12** — phase-3 bullet: append
`3c PWA + service worker (…phase3c-pwa-service-worker-design.md)` to the list.

- [ ] **Step 3: README** — under `## Build`, add:

```
`node tools/build.mjs` also writes `dist/pwa/` — an installable copy (service
worker + manifest + icons) whose CSP still blocks all network from the page.
`node tools/build.mjs --no-pwa` writes only the single file.
```

- [ ] **Step 4: Manual (Chrome DevTools → Application)**

```bash
cd dist/pwa && python3 -m http.server 8802
```
Open `http://localhost:8802/`.
- Install is offered; install it. Application → Service Workers: one activated
  worker. Cache Storage: `kunji-<hash>` with all 8 assets.
- Network → Offline → reload: app opens; Generate works; Vault "open a file"
  works.
- Edit any `src/` file → `npm run build` → hard-reload the served page: the
  "New version available — Reload" bar appears; click it → new hash loads; the
  old `kunji-*` cache is gone after activate.
- `dist/kunji.html` opened from `file://` is unchanged and works.
- DevTools Network: only same-origin shell requests, ever.

- [ ] **Step 5: Commit**

```bash
git add docs/specs/2026-09-01-kunji-design.md README.md
git -c commit.gpgsign=false commit -m "docs: PWA build — readme and parent-spec sync"
```

---

# PART D — Sync merge (Tasks D1–D6)

## Task D1: `removeEntry` tombstones; `visibleEntries`

**Files:**
- Modify: `src/vault.js`
- Test: `tests/vault.test.mjs` (rewrite one test, append others)

- [ ] **Step 1: Rewrite the `removeEntry` test and add `visibleEntries` tests**

In `tests/vault.test.mjs`, replace the existing test
`test('removeEntry drops by id', () => { … })` with:

```js
test('removeEntry replaces the entry with a tombstone, in place', () => {
  let v = addEntry(createVault(), { name: 'A', site: 's', account: 'a' });
  v = addEntry(v, { name: 'B', site: 's2', account: 'b' });
  const id = v.entries[0].id;
  v = removeEntry(v, id);
  assert.equal(v.entries.length, 2, 'array length unchanged');
  const t = v.entries.find((e) => e.id === id);
  assert.deepEqual(Object.keys(t).sort(), ['deleted', 'id', 'updatedAt']);
  assert.equal(t.deleted, true);
  // idempotent
  const again = removeEntry(v, id).entries.find((e) => e.id === id);
  assert.equal(again.deleted, true);
});
```

Append:

```js
import { visibleEntries } from '../src/vault.js';

test('visibleEntries filters tombstones, preserves order, does not mutate', () => {
  let v = addEntry(createVault(), { name: 'A', site: 's', account: 'a' });
  v = addEntry(v, { name: 'B', site: 's2', account: 'b' });
  v = addEntry(v, { name: 'C', site: 's3', account: 'c' });
  v = removeEntry(v, v.entries[1].id);
  const vis = visibleEntries(v);
  assert.deepEqual(vis.map((e) => e.name), ['A', 'C']);
  assert.equal(v.entries.length, 3, 'source untouched');
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/vault.test.mjs`
Expected: FAIL — `removeEntry` still splices; `visibleEntries` not exported.

- [ ] **Step 3: Implement in `src/vault.js`**

Replace `removeEntry`:

```js
// Phase 3d: a delete is a tombstone kept in `entries[]` forever, so it survives
// a later merge with a device that still has the entry.
export function removeEntry(vault, id) {
  const now = new Date().toISOString();
  return {
    ...vault,
    entries: vault.entries.map((e) => (e.id === id ? { id, deleted: true, updatedAt: now } : e)),
  };
}

export function visibleEntries(vault) {
  return vault.entries.filter((e) => e && !e.deleted);
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/vault.test.mjs` — PASS.
Run: `node --test` — `fail 0`. (If the 3a `entriesForSite` tests are present,
note they will still pass — tombstones have no `site`, so `typeof e.site === 'string'`
already excludes them; if 3a is not merged, ignore.)
Run: `node tools/build.mjs && node tools/check-invariants.mjs` — green.

- [ ] **Step 5: Commit**

```bash
git add src/vault.js tests/vault.test.mjs
git -c commit.gpgsign=false commit -m "feat: tombstone deletes; visibleEntries filter"
```

---

## Task D2: `mergeVaults`

**Files:**
- Modify: `src/vault.js`
- Test: `tests/vault.test.mjs` (append)

- [ ] **Step 1: Append the failing tests**

```js
import { mergeVaults } from '../src/vault.js';

const at = (s) => new Date(s).toISOString();
const ent = (over) => ({ id: 'x', type: 'password', name: 'n', site: 's', account: 'a', counter: 1, length: 20, rules: 'standard', profile: 'v1', totp: null, recoveryCodes: [], notes: '', updatedAt: at('2026-01-01'), ...over });
const vault = (entries, revision = 1, lastWriter = 'A') => ({ entries, settings: { autoLockMinutes: 5 }, revision, lastWriter });

test('mergeVaults: incoming-only id is added', () => {
  const local = vault([ent({ id: '1' })]);
  const incoming = vault([ent({ id: '1' }), ent({ id: '2', name: 'new' })], 2, 'B');
  const { vault: m, summary } = mergeVaults(local, incoming);
  assert.deepEqual(m.entries.map((e) => e.id), ['1', '2']);
  assert.deepEqual(summary.added, ['2']);
});

test('mergeVaults: shared entry — newer updatedAt wins both directions', () => {
  const l1 = mergeVaults(
    vault([ent({ id: '1', name: 'old', updatedAt: at('2026-01-01') })]),
    vault([ent({ id: '1', name: 'NEW', updatedAt: at('2026-02-01') })], 2, 'B'),
  );
  assert.equal(l1.vault.entries[0].name, 'NEW');
  assert.deepEqual(l1.summary.updated, ['1']);
  const l2 = mergeVaults(
    vault([ent({ id: '1', name: 'LOCAL', updatedAt: at('2026-03-01') })]),
    vault([ent({ id: '1', name: 'old', updatedAt: at('2026-02-01') })], 2, 'B'),
  );
  assert.equal(l2.vault.entries[0].name, 'LOCAL');
});

test('mergeVaults: incoming tombstone newer than local live entry -> deleted', () => {
  const { vault: m, summary } = mergeVaults(
    vault([ent({ id: '1', updatedAt: at('2026-01-01') })]),
    vault([{ id: '1', deleted: true, updatedAt: at('2026-02-01') }], 2, 'B'),
  );
  assert.equal(m.entries[0].deleted, true);
  assert.deepEqual(summary.deletedByRemote, ['1']);
});

test('mergeVaults: local tombstone older than incoming live entry -> resurrected', () => {
  const { vault: m, summary } = mergeVaults(
    vault([{ id: '1', deleted: true, updatedAt: at('2026-01-01') }]),
    vault([ent({ id: '1', name: 'back', updatedAt: at('2026-02-01') })], 2, 'B'),
  );
  assert.equal(m.entries[0].name, 'back');
  assert.deepEqual(summary.updated, ['1']);
});

test('mergeVaults: equal entries -> unchanged count, no buckets', () => {
  const e = ent({ id: '1' });
  const { summary } = mergeVaults(vault([e]), vault([{ ...e }], 2, 'B'));
  assert.equal(summary.unchanged, 1);
  assert.deepEqual([summary.added, summary.updated, summary.deletedByRemote, summary.deletedByLocal], [[], [], [], []]);
});

test('mergeVaults: updatedAt tie broken by lastWriter, then local; deterministic both ways', () => {
  const l = vault([ent({ id: '1', name: 'L', updatedAt: at('2026-01-01') })], 1, 'A');
  const r = vault([ent({ id: '1', name: 'R', updatedAt: at('2026-01-01') })], 1, 'B');
  const ab = mergeVaults(l, r).vault.entries[0].name;
  const ba = mergeVaults(r, l).vault.entries[0].name;
  assert.equal(ab, ba, 'commutative outcome');
});

test('mergeVaults: settings follow the higher revision', () => {
  const l = { entries: [], settings: { autoLockMinutes: 5 }, revision: 1, lastWriter: 'A' };
  const r = { entries: [], settings: { autoLockMinutes: 1 }, revision: 9, lastWriter: 'B' };
  assert.equal(mergeVaults(l, r).vault.settings.autoLockMinutes, 1);
  assert.equal(mergeVaults(r, l).vault.settings.autoLockMinutes, 1);
});

test('mergeVaults: order = local order then incoming-only appended', () => {
  const l = vault([ent({ id: '1' }), ent({ id: '2' })]);
  const r = vault([ent({ id: '2' }), ent({ id: '3' }), ent({ id: '1' })], 2, 'B');
  assert.deepEqual(mergeVaults(l, r).vault.entries.map((e) => e.id), ['1', '2', '3']);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/vault.test.mjs`
Expected: FAIL — `mergeVaults` not exported.

- [ ] **Step 3: Implement — append to `src/vault.js`**

```js
// Phase 3d: entry-level last-writer-wins merge. `local`/`incoming` are decrypted
// vaults plus their envelope `revision` and `lastWriter`. Deterministic; the
// resulting `vault` is the same for mergeVaults(a,b) and mergeVaults(b,a) (only
// the summary's *ByRemote/*ByLocal labels swap).
export function mergeVaults(local, incoming) {
  const li = new Map(local.entries.map((e) => [e.id, e]));
  const ri = new Map(incoming.entries.map((e) => [e.id, e]));
  const summary = { added: [], updated: [], deletedByRemote: [], deletedByLocal: [], unchanged: 0 };

  const pick = (a, b) => {
    // both defined; choose the winner
    const ta = a.updatedAt || '';
    const tb = b.updatedAt || '';
    if (ta > tb) return a;
    if (tb > ta) return b;
    // tie: lastWriter order, then local (a)
    const wa = local.lastWriter || '';
    const wb = incoming.lastWriter || '';
    return wb > wa ? b : a;
  };

  const out = [];
  for (const e of local.entries) {
    const other = ri.get(e.id);
    if (!other) { out.push(e); summary.unchanged += 1; continue; }
    if (JSON.stringify(e) === JSON.stringify(other)) { out.push(e); summary.unchanged += 1; continue; }
    const winner = pick(e, other);
    out.push(winner);
    const localDel = !!e.deleted;
    const remoteDel = !!other.deleted;
    if (winner === other && remoteDel && !localDel) summary.deletedByRemote.push(e.id);
    else if (winner === e && localDel && !remoteDel) summary.deletedByLocal.push(e.id);
    else summary.updated.push(e.id);
  }
  for (const e of incoming.entries) {
    if (!li.has(e.id)) { out.push(e); summary.added.push(e.id); }
  }

  const settings = (incoming.revision || 0) > (local.revision || 0) ? incoming.settings : local.settings;
  return { vault: { entries: out, settings }, summary };
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/vault.test.mjs` — PASS.
Run: `node --test` — `fail 0`.

- [ ] **Step 5: Commit**

```bash
git add src/vault.js tests/vault.test.mjs
git -c commit.gpgsign=false commit -m "feat: mergeVaults entry-level last-writer-wins"
```

---

## Task D3: `classifyIncoming`

**Files:**
- Modify: `src/vault.js`
- Test: `tests/vault.test.mjs` (append)

- [ ] **Step 1: Append the failing tests**

```js
import { classifyIncoming } from '../src/vault.js';

const envOf = (kcv, revision) => ({ kcv, revision });

test('classifyIncoming: wrong-passphrase when kcv differs', () => {
  assert.equal(
    classifyIncoming(envOf('AAAA', 1), vault([]), envOf('BBBB', 1), vault([])),
    'wrong-passphrase',
  );
});

test('classifyIncoming: same when merge equals local', () => {
  const e = ent({ id: '1' });
  assert.equal(
    classifyIncoming(envOf('K', 1), vault([e]), envOf('K', 1), vault([{ ...e }])),
    'same',
  );
});

test('classifyIncoming: fast-forward when merge equals incoming and revision >=', () => {
  const local = vault([ent({ id: '1' })], 3);
  const incoming = vault([ent({ id: '1' }), ent({ id: '2', name: 'new' })], 5);
  assert.equal(classifyIncoming(envOf('K', 3), local, envOf('K', 5), incoming), 'fast-forward');
});

test('classifyIncoming: diverged when each side has a unique change', () => {
  const local = vault([ent({ id: '1' }), ent({ id: 'L', name: 'local-only' })], 3);
  const incoming = vault([ent({ id: '1' }), ent({ id: 'R', name: 'remote-only' })], 4);
  assert.equal(classifyIncoming(envOf('K', 3), local, envOf('K', 4), incoming), 'diverged');
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/vault.test.mjs`
Expected: FAIL — `classifyIncoming` not exported.

- [ ] **Step 3: Implement — append to `src/vault.js`**

```js
export function classifyIncoming(localEnv, localVault, inEnv, inVault) {
  if (inEnv.kcv !== localEnv.kcv) return 'wrong-passphrase';
  const eq = (a, b) => JSON.stringify(a.entries) === JSON.stringify(b.entries)
    && JSON.stringify(a.settings) === JSON.stringify(b.settings);
  const localWithMeta = { ...localVault, revision: localEnv.revision, lastWriter: localEnv.lastWriter };
  const inWithMeta = { ...inVault, revision: inEnv.revision, lastWriter: inEnv.lastWriter };
  const merged = mergeVaults(localWithMeta, inWithMeta).vault;
  if (eq(merged, localVault)) return 'same';
  if (eq(merged, inVault) && (inEnv.revision || 0) >= (localEnv.revision || 0)) return 'fast-forward';
  return 'diverged';
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/vault.test.mjs` — PASS.
Run: `node --test` — `fail 0`.
Run: `node tools/build.mjs && node tools/check-invariants.mjs` — green.

- [ ] **Step 5: Commit**

```bash
git add src/vault.js tests/vault.test.mjs
git -c commit.gpgsign=false commit -m "feat: classifyIncoming same/fast-forward/diverged/wrong-passphrase"
```

---

## Task D4: Vault-tab consumers use `visibleEntries`

**Files:**
- Modify: `src/vault-ui.js`
- Manual test: browser

Context: `visibleEntries` is a bundle global in `vault-ui.js`. Every place that
iterates `vault.entries` for display must go through it; raw `vault.entries`
stays only where merge/save need the tombstones.

- [ ] **Step 1: Route the display paths through `visibleEntries`**

1. `renderList` → `rowsHtml()` (the `vault.entries.filter(...)` for search):
   change `const html = vault.entries` to `const html = visibleEntries(vault)`.
2. `renderList` → the count `Vault &middot; ${vault.entries.length}`:
   change to `Vault &middot; ${visibleEntries(vault).length}`.
3. `renderDetail` → `selectedEntry()` is `vault.entries.find(...)` — a selected id
   is always a visible entry, so leave as-is, but guard: at the top of
   `renderDetail`, after `const e = selectedEntry();`, keep the existing
   `if (!e) { … }` and also treat a tombstone as gone:
   change `if (!e)` to `if (!e || e.deleted)`.
4. `renderEditor` → `const dup = vault.entries.find(...)` duplicate check:
   change to `const dup = visibleEntries(vault).find(...)`.
5. The account-picker bridge (Task 3 of the 3a plan) — every
   `vaultBridge.publish(vault.entries)` becomes
   `vaultBridge.publish(visibleEntries(vault))`. (Skip this sub-step if 3a is
   not merged.)

- [ ] **Step 2: Build + suite**

Run: `node tools/build.mjs && node tools/check-invariants.mjs && node --test`
Expected: green; `fail 0`.

- [ ] **Step 3: Manual browser test**

Create a vault, add 3 entries, delete the middle one → list shows 2, count says
`Vault · 2`. Save → reopen → still 2 visible. Open the file in a text editor →
`entries` has 3 items, one `{id,deleted:true,updatedAt}`. Add a new entry with
the same site+account as the deleted one → allowed (dup check ignores
tombstones). No console errors.

- [ ] **Step 4: Commit**

```bash
git add src/vault-ui.js
git -c commit.gpgsign=false commit -m "feat: vault tab display paths use visibleEntries"
```

---

## Task D5: Import routing + merge summary screen

**Files:**
- Modify: `src/vault-ui.js`, `src/style.css`
- Manual test: browser

- [ ] **Step 1: Append merge CSS to `src/style.css`**

```css
/* Sync merge (Phase 3d) */
.v-merge-head { font-size: 13px; font-weight: 700; margin-bottom: 8px; }
.v-merge-row { display: flex; justify-content: space-between; padding: 9px 0; border-top: 1px solid #1a1c1f; cursor: pointer; }
.v-merge-row .n { color: var(--muted); }
.v-merge-detail { font-size: 12px; color: var(--muted); padding: 4px 0 8px 10px; }
```

- [ ] **Step 2: Add merge state + screen to `initVaultTab`**

Near the other `let`s:

```js
  let mergedFromRevision = null;   // set after Apply merge; base for the next save's revision
  let pendingImport = null;        // { env, vault } awaiting a merge/replace decision
```

Add a `renderMerge()` function (anywhere in `initVaultTab`):

```js
  function renderMerge(inEnv, inVault) {
    const localMeta = { ...vault, revision: loadedEnvelope ? loadedEnvelope.revision : 0, lastWriter: loadedEnvelope ? loadedEnvelope.lastWriter : '' };
    const inMeta = { ...inVault, revision: inEnv.revision, lastWriter: inEnv.lastWriter };
    const { vault: merged, summary } = mergeVaults(localMeta, inMeta);
    const nameOf = (id) => {
      const e = merged.entries.find((x) => x.id === id) || vault.entries.find((x) => x.id === id) || {};
      return e.name || `(${id.slice(0, 8)})`;
    };
    const bucket = (label, ids) => `
      <div class="v-merge-row" data-ids='${JSON.stringify(ids)}'>
        <span>${label}</span><span class="n">${ids.length} &rsaquo;</span>
      </div>
      <div class="v-merge-detail" hidden>${ids.map(nameOf).map(esc).join('<br>') || '—'}</div>`;
    panel.innerHTML = `
      <div class="v-bar"><button class="link-btn" id="mgCancel" type="button">&lsaquo; Cancel</button><button class="link-btn" id="mgApply" type="button">Apply merge</button></div>
      <div class="v-merge-head">Merging rev ${inEnv.revision} into your rev ${loadedEnvelope ? loadedEnvelope.revision : 0}</div>
      ${bucket('Added from that copy', summary.added)}
      ${bucket('Updated (newer wins)', summary.updated)}
      ${bucket('Deleted by that copy', summary.deletedByRemote)}
      ${bucket('Deleted here (kept deleted)', summary.deletedByLocal)}
      <div class="v-merge-row"><span>Unchanged</span><span class="n">${summary.unchanged}</span></div>
    `;
    panel.querySelectorAll('.v-merge-row[data-ids]').forEach((row) => {
      row.addEventListener('click', () => {
        const d = row.nextElementSibling;
        if (d && d.classList.contains('v-merge-detail')) d.hidden = !d.hidden;
      });
    });
    panel.querySelector('#mgCancel').addEventListener('click', () => { view = 'list'; render(); });
    panel.querySelector('#mgApply').addEventListener('click', () => {
      vault = { entries: merged.entries, settings: merged.settings };
      dirty = true;
      mergedFromRevision = Math.max(loadedEnvelope ? loadedEnvelope.revision : 0, inEnv.revision);
      vaultBridge && vaultBridge.publish && vaultBridge.publish(visibleEntries(vault));
      view = 'list';
      render();
    });
  }
```

- [ ] **Step 3: Route an opened file while UNLOCKED**

Find where the NO_VAULT screen's `#vFileInput` `change` handler is (`onFilePicked`),
and the LOCKED screen's "Open a different file". Add a single shared handler for
"a file was chosen while UNLOCKED". In `onFilePicked(ev)` replace the body with:

```js
  async function onFilePicked(ev) {
    const file = ev.target.files && ev.target.files[0];
    if (!file) return;
    const errEl = panel.querySelector('#vError') || panel.querySelector('#vlError');
    let env;
    try {
      env = parseEnvelope(await file.text());
    } catch (e) {
      if (errEl) errEl.textContent = e && e.name === 'BadEnvelopeError'
        ? 'That does not look like a Kunji vault file.' : 'Could not read that file.';
      return;
    }
    if (state !== 'UNLOCKED') {
      loadedEnvelope = env;
      identityHintOn = typeof env.identityHint === 'string';
      state = 'LOCKED';
      render();
      return;
    }
    // UNLOCKED: compare with the loaded vault using the current key
    let inVault;
    try {
      inVault = await unlockVault(env, { masterKey });
    } catch {
      if (!confirm('That file uses a different passphrase — replace the open vault and re-unlock it?')) return;
      loadedEnvelope = env; wipe(); state = 'LOCKED'; render();
      return;
    }
    const verdict = classifyIncoming(loadedEnvelope, vault, env, inVault);
    if (verdict === 'same') { alert('That copy has nothing new.'); return; }
    if (verdict === 'fast-forward') {
      if (!confirm(`That copy is newer (rev ${env.revision}) and already has everything you do. Use it?`)) return;
      loadedEnvelope = env; vault = { entries: inVault.entries, settings: inVault.settings };
      dirty = true; mergedFromRevision = env.revision;
      vaultBridge && vaultBridge.publish && vaultBridge.publish(visibleEntries(vault));
      view = 'list'; render();
      return;
    }
    // diverged
    const choice = prompt(`That copy (rev ${env.revision}) and yours (rev ${loadedEnvelope.revision}) both have changes.\nType "merge" to merge, "replace" to take that copy, anything else to cancel.`);
    if (choice === 'merge') { renderMerge(env, inVault); return; }
    if (choice === 'replace') {
      loadedEnvelope = env; vault = { entries: inVault.entries, settings: inVault.settings };
      dirty = true; mergedFromRevision = env.revision;
      vaultBridge && vaultBridge.publish && vaultBridge.publish(visibleEntries(vault));
      view = 'list'; render();
    }
  }
```

> **Design note:** the diverged decision uses `prompt()` here for minimum surface
> area; if a three-button dialog is wanted, replace the `prompt` with a small
> rendered panel that calls `renderMerge` / the replace branch. Keep the
> behaviour identical.

- [ ] **Step 4: `Merge another copy…` footer button**

In `renderList`, add to the footer line (after the Lock button / countdown span):

```js
      &middot; <button class="link-btn" id="vMerge" type="button">Merge another copy&hellip;</button>
      <input type="file" id="vMergeInput" accept=".json,application/json" hidden>
```

and wire it (end of `renderList`):

```js
    panel.querySelector('#vMerge').addEventListener('click', () => panel.querySelector('#vMergeInput').click());
    panel.querySelector('#vMergeInput').addEventListener('change', async (ev) => {
      const file = ev.target.files && ev.target.files[0];
      if (!file) return;
      let env, inVault;
      try {
        env = parseEnvelope(await file.text());
        inVault = await unlockVault(env, { masterKey });
      } catch {
        alert('Could not read that file, or it uses a different passphrase.');
        return;
      }
      renderMerge(env, inVault);
    });
```

- [ ] **Step 5: Build + suite**

Run: `node tools/build.mjs && node tools/check-invariants.mjs && node --test`
Expected: green; `fail 0`.

- [ ] **Step 6: Manual browser test**

- Create vault, add `Router`, Save → `a.json`. Reload, open `a.json`, unlock,
  add `NAS`, delete `Router`. `Merge another copy…` → pick the *original*
  `a.json` → summary: Added 0, Deleted here 1 (Router), Unchanged 1 → expand a
  bucket → Apply → list shows `NAS` only. Save → `b.json` (rev bumped).
- Reload, open `b.json`, unlock, then use the Vault **Open a file** control on a
  divergent `a.json` → the "both have changes" prompt → `merge` → summary →
  Apply. `fast-forward`: open a strictly-newer superset → "Use it". `same`: open
  an identical copy → "nothing new". Wrong passphrase file → the replace prompt.
- No console errors; `npm run verify` green.

- [ ] **Step 7: Commit**

```bash
git add src/vault-ui.js src/style.css
git -c commit.gpgsign=false commit -m "feat: vault tab — import routing and merge summary screen"
```

---

## Task D6: `saveVault` revision base; docs

**Files:**
- Modify: `src/vault-ui.js`, `docs/specs/2026-09-01-kunji-design.md`
- Manual test: browser

- [ ] **Step 1: Use `mergedFromRevision` as the save base**

In `saveVault`, change:

```js
    const prevRevision = loadedEnvelope ? (Number(loadedEnvelope.revision) || 0) : 0;
```

to:

```js
    const prevRevision = mergedFromRevision != null
      ? mergedFromRevision
      : (loadedEnvelope ? (Number(loadedEnvelope.revision) || 0) : 0);
```

and after `dirty = false;` (post-adopt), add:

```js
    mergedFromRevision = null;
```

Also clear it in `wipe()`:

```js
    mergedFromRevision = null;
    pendingImport = null;
```

- [ ] **Step 2: Parent-spec edits**

- **§5.2** — after the entry schema, add: *"An entry object is either a full
  entry or a tombstone `{ id, deleted: true, updatedAt }`. Tombstones are kept
  permanently and are filtered from every view by `visibleEntries`."*
- **§7.3** — change "field-level last-writer-wins" to *"entry-level
  last-writer-wins by `updatedAt`, ties broken by `lastWriter`"*; add *"Conflict
  handling is import-driven: Kunji compares a file the user opens against the
  loaded vault (`classifyIncoming`) and offers merge / replace / use-it."*
- **§12** — phase-3 bullet: append `3d sync merge (…phase3d-sync-merge-design.md)`.

- [ ] **Step 3: Build + full verify**

Run: `npm run verify` — all pass; `fail 0`; `invariants ok`.

- [ ] **Step 4: Manual regression**

Merge two divergent copies → Apply → Save → the saved `revision` is
`max(localRev, incomingRev) + 1`; `lastWriter` is this device. Reopen the merged
file → all merged entries present, tombstones still present in the raw JSON.

- [ ] **Step 5: Commit**

```bash
git add src/vault-ui.js docs/specs/2026-09-01-kunji-design.md
git -c commit.gpgsign=false commit -m "feat: save revision base after merge; sync-merge docs"
```

---

# PART E — QR transfer (Tasks E1–E9)

> **Fidelity note.** Parts C and D above give complete code. The two QR **codec**
> tasks (E1 encoder, E4 decoder) cannot be responsibly transcribed as finished
> code in a plan — a correct ISO/IEC 18004 byte-mode encoder is ~350–450 lines
> and a decoder ~600–900. Those two tasks are therefore specified as
> **build-to-contract**: the exact public signature, the exact frozen-fixture and
> round-trip test suite (which is the acceptance gate), and a clause-by-clause
> sub-step list referencing ISO/IEC 18004. Everything else in Part E (framing,
> camera UI, build wiring, docs) is complete code. Consider running E as its own
> `subagent-driven-development` pass with a capable model per task.

## Task E1: `src/qr.js` — byte-mode encoder

**Files:**
- Create: `src/qr.js`
- Create: `tools/gen-qr-fixtures.mjs`
- Test: `tests/qr.test.mjs` (new), `tests/fixtures/qr/*.json` (generated)

**Public contract (must match exactly):**

```js
// Smallest QR version (1..40) that fits `bytes` at ECC level `ecc` ('L'|'M'|'Q'|'H'),
// byte mode only. Returns the module matrix as row-major booleans (true = dark),
// side length 21 + 4*(version-1), NO quiet zone. Throws if bytes exceed v40 capacity.
export function qrMatrix(bytes /* Uint8Array */, { ecc = 'M' } = {}) // -> boolean[][]

// capacity[version][ecc] -> max byte-mode data bytes. Frozen table from ISO/IEC 18004 Table 7 / 9.
export const QR_CAPACITY
```

**Sub-steps (ISO/IEC 18004 clauses):**

- [ ] **E1.1** GF(256) arithmetic: exp/log tables, primitive polynomial `0x11d` (clause 7.5.2). Test: `gfMul(a,b)` against a few hand values; `gfMul(x,1)===x`.
- [ ] **E1.2** Reed–Solomon generator polynomials and `rsEncode(data, ecLen)` (clause 7.5.2). Test: RS parity for the ISO Annex I worked example (`data` = `0x10 0x20 0x0c 0x56 0x61 0x80 0xec 0x11 0xec 0x11 0xec 0x11 0xec 0x11 0xec 0x11`, v1-M, ecLen 10) → the Annex's `0xa5 0x24 0xd4 0xc1 0xed 0x36 0xc7 0x87 0x2c 0x55`.
- [ ] **E1.3** Data encoding: mode indicator `0100` + 8-bit char count (v1–9) / 16-bit (v10–40) + payload + terminator + pad `0xec 0x11` (clauses 7.4.3, 7.4.9, 7.4.10). Version pick from `QR_CAPACITY`.
- [ ] **E1.4** Block split + interleave data/EC codewords for the chosen version/ECC (clause 7.6, Table 9). Test: for v5-Q (4 blocks) the interleave order matches the ISO table.
- [ ] **E1.5** Function patterns on the matrix: finder + separators, timing, alignment-pattern centres (clause 6.3.6, Table E.1), dark module, and the reserved format/version areas (clauses 6.3.3–6.3.5).
- [ ] **E1.6** Place data bits in the zig-zag order, skipping function modules (clause 7.7.3).
- [ ] **E1.7** All 8 data masks + penalty scoring (rules N1–N4, clauses 7.8.2–7.8.3); pick the lowest-penalty mask; write format info (BCH(15,5) + mask `0x5412`, clause 7.9) and, for v≥7, version info (BCH(18,6), clause 7.10).

- [ ] **E1.8: Freeze fixtures — `tools/gen-qr-fixtures.mjs`**

```js
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
```

- [ ] **E1.9: `tests/qr.test.mjs`**

```js
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
```

- [ ] **E1.10** Run `node tools/gen-qr-fixtures.mjs` once implementation passes E1.2's Annex check, then `node --test tests/qr.test.mjs` — PASS. `node --test` — `fail 0`.

- [ ] **E1.11: Commit**

```bash
git add src/qr.js tools/gen-qr-fixtures.mjs tests/qr.test.mjs tests/fixtures/qr
git -c commit.gpgsign=false commit -m "feat: zero-dep QR byte-mode encoder"
```

---

## Task E2: `src/qr-transfer.js` — `KQR1` framing

**Files:**
- Create: `src/qr-transfer.js`
- Test: `tests/qr-transfer.test.mjs` (new)

- [ ] **Step 1: Write the failing tests**

```js
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/qr-transfer.test.mjs` — FAIL (module missing).

- [ ] **Step 3: Implement `src/qr-transfer.js`**

```js
import { utf8, fromUtf8, bytesToBase64, base64ToBytes } from './encoding.js';

const TAG = 'KQR1';

// text -> ['KQR1 <seq> <total> <nonce> <b64 slice>', ...] each <= frameBytes utf8 bytes.
export function splitTransfer(text, { frameBytes }) {
  const b64 = bytesToBase64(utf8(text));
  const nonce = Array.from(randomB64(6)).join('');
  // header without the slice, worst case seq/total width
  const headerLen = (seq, total) => `${TAG} ${seq} ${total} ${nonce} `.length;
  // provisional total from a conservative slice size
  let sliceLen = Math.max(1, frameBytes - headerLen(999, 999));
  let total = Math.ceil(b64.length / sliceLen);
  // recompute with the real digit widths
  sliceLen = Math.max(1, frameBytes - headerLen(total - 1, total));
  total = Math.ceil(b64.length / sliceLen);
  const frames = [];
  for (let seq = 0; seq < total; seq++) {
    frames.push(`${TAG} ${seq} ${total} ${nonce} ${b64.slice(seq * sliceLen, (seq + 1) * sliceLen)}`);
  }
  return frames;
}

// frames -> { text } | { need: number[] } | { error }
export function joinTransfer(frames) {
  const parsed = [];
  for (const f of frames) {
    const m = /^KQR1 (\d+) (\d+) (\S{6}) (.*)$/.exec(f);
    if (m) parsed.push({ seq: +m[1], total: +m[2], nonce: m[3], data: m[4] });
  }
  if (!parsed.length) return { error: 'no valid KQR1 frames' };
  const nonce = parsed[0].nonce;
  const total = parsed[0].total;
  const bySeq = new Map();
  for (const p of parsed) if (p.nonce === nonce && p.total === total) bySeq.set(p.seq, p.data);
  const need = [];
  for (let i = 0; i < total; i++) if (!bySeq.has(i)) need.push(i);
  if (need.length) return { need };
  let b64 = '';
  for (let i = 0; i < total; i++) b64 += bySeq.get(i);
  try {
    return { text: fromUtf8(base64ToBytes(b64)) };
  } catch {
    return { error: 'reassembled payload is not valid base64' };
  }
}

function randomB64(n) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const r = crypto.getRandomValues(new Uint8Array(n));
  return Array.from(r, (x) => A[x & 63]);
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/qr-transfer.test.mjs` — PASS.
Run: `node --test` — `fail 0`.

- [ ] **Step 5: Commit**

```bash
git add src/qr-transfer.js tests/qr-transfer.test.mjs
git -c commit.gpgsign=false commit -m "feat: KQR1 multi-frame transfer framing"
```

---

## Task E3: Build wiring for the qr modules

**Files:**
- Modify: `tools/build.mjs`
- Test: `tests/build.test.mjs` (append)

- [ ] **Step 1: Append the failing test**

```js
test('built html inlines the qr modules after encoding.js and before vault.js', () => {
  execFileSync('node', ['tools/build.mjs'], { stdio: 'pipe' });
  const html = readFileSync('dist/kunji.html', 'utf8');
  for (const m of ['src/qr.js', 'src/qr-transfer.js', 'src/qr-decode.js']) {
    assert.ok(html.includes(`==== ${m} ====`), `${m} concatenated`);
    assert.ok(html.indexOf('src/encoding.js') < html.indexOf(m), `${m} after encoding.js`);
    assert.ok(html.indexOf(m) < html.indexOf('src/vault.js'), `${m} before vault.js`);
  }
});
```

- [ ] **Step 2: Run to verify it fails** — `node --test tests/build.test.mjs` FAIL.

- [ ] **Step 3: Update `JS_ORDER` in `tools/build.mjs`**

```js
const JS_ORDER = [
  'src/encoding.js',
  'src/webcrypto.js',
  'src/qr.js',
  'src/qr-decode.js',
  'src/qr-transfer.js',
  'src/derive.js',
  'src/vault.js',
  // 'src/vault-bridge.js',  // present iff the 3a+3b plan was merged
  'src/app.js',
  'src/vault-ui.js',
];
```

(Keep `src/vault-bridge.js` in the list if it exists in the repo.)

- [ ] **Step 4: Create a placeholder `src/qr-decode.js` so the build succeeds now**

```js
// Filled in Task E4. Returns null until implemented.
export function decodeQr(_image) {
  return null;
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `node --test tests/build.test.mjs` — PASS.
Run: `node --test` — `fail 0`.
Run: `node tools/build.mjs && node tools/check-invariants.mjs` — green (the qr
modules contain no URLs / `fetch` / `<link>`).

- [ ] **Step 6: Commit**

```bash
git add tools/build.mjs src/qr-decode.js tests/build.test.mjs
git -c commit.gpgsign=false commit -m "build: wire qr modules; qr-decode stub"
```

---

## Task E4: `src/qr-decode.js` — decoder

**Files:**
- Modify: `src/qr-decode.js`
- Test: `tests/qr-decode.test.mjs` (new)

**Public contract:**

```js
// image: { data: Uint8ClampedArray|Uint8Array (RGBA or single-channel), width, height }
// -> Uint8Array payload, or null if no readable QR symbol is found. Never throws.
export function decodeQr(image) // -> Uint8Array | null
```

**Sub-steps (ISO/IEC 18004):**

- [ ] **E4.1** Luminance + local-mean adaptive threshold to a binary grid (clause "Reference decoding algorithm", Annex J.2).
- [ ] **E4.2** Finder-pattern search: scan rows/cols for the `1:1:3:1:1` dark/light run ratio (±50%); cluster centres into groups of 3 (Annex J.3).
- [ ] **E4.3** From the three finders, order them (top-left / top-right / bottom-left) by pairwise distances; estimate module size and provisional version; locate the bottom-right alignment pattern (clause 6.3.6) to refine.
- [ ] **E4.4** Homography from the 4 reference points; sample every module centre → module matrix (Annex J.5).
- [ ] **E4.5** Read both format-info copies; BCH(15,5) error-correct; recover ECC level + mask (clause 7.9). For a grid ≥ 45 modules read version info, BCH(18,6) correct (clause 7.10).
- [ ] **E4.6** Unmask; read data bits in the zig-zag order skipping function modules (inverse of E1.6).
- [ ] **E4.7** De-interleave into blocks; RS-correct each block over GF(256) (return `null` if any block's error count exceeds `ecLen/2`) (clause 7.6, 7.5.3).
- [ ] **E4.8** Parse the bit stream: expect byte mode (`0100`); read the char count (8 or 16 bits by version); return that many bytes. Ignore ECI / other modes → `null`.

- [ ] **E4.9: `tests/qr-decode.test.mjs`** — round-trip against the E1 encoder

```js
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
  // flip a handful of data modules
  for (const [y, x] of [[10, 10], [10, 11], [11, 10], [12, 12]]) m[y][x] = !m[y][x];
  assert.deepEqual([...decodeQr(render(m, { s: 5 }))], bytes);
  for (let y = 8; y < 20; y++) for (let x = 8; x < 20; x++) m[y][x] = !m[y][x]; // wreck it
  assert.equal(decodeQr(render(m, { s: 5 })), null);
});

test('blank / noise image -> null, never throws', () => {
  assert.equal(decodeQr({ data: new Uint8ClampedArray(200 * 200 * 4).fill(255), width: 200, height: 200 }), null);
  const noise = new Uint8ClampedArray(200 * 200 * 4);
  for (let i = 0; i < noise.length; i++) noise[i] = (i * 2654435761) & 0xff;
  assert.equal(decodeQr({ data: noise, width: 200, height: 200 }), null);
});
```

- [ ] **E4.10** Run `node --test tests/qr-decode.test.mjs` — PASS. `node --test` — `fail 0`. `node tools/build.mjs && node tools/check-invariants.mjs` — green.

- [ ] **E4.11: Commit**

```bash
git add src/qr-decode.js tests/qr-decode.test.mjs
git -c commit.gpgsign=false commit -m "feat: zero-dep QR decoder (image -> bytes)"
```

---

## Task E5: Camera scan panel — capture + decode loop

**Files:**
- Modify: `src/vault-ui.js`, `src/style.css`
- Manual test: browser over `https`/`localhost`

- [ ] **Step 1: Append CSS**

```css
/* QR transfer (Phase 3e) */
.qr-panel { text-align: center; }
.qr-cam { width: 100%; max-width: 320px; border-radius: 8px; background: #000; }
.qr-canvas { image-rendering: pixelated; }
.qr-progress { font-size: 12px; color: var(--muted); margin: 8px 0; }
```

- [ ] **Step 2: Add a `scanQr()` panel to `initVaultTab`**

```js
  let scanStream = null;
  function stopScan() {
    if (scanStream) { scanStream.getTracks().forEach((t) => t.stop()); scanStream = null; }
  }

  async function scanQr(onEnvelopeText) {
    panel.innerHTML = `
      <div class="v-bar"><button class="link-btn" id="scCancel" type="button">&lsaquo; Cancel</button></div>
      <div class="qr-panel">
        <video class="qr-cam" id="scVideo" playsinline muted></video>
        <div class="qr-progress" id="scProgress">point at the other device…</div>
      </div>
      <div class="error" id="scError"></div>
    `;
    panel.querySelector('#scCancel').addEventListener('click', () => { stopScan(); render(); });
    const video = panel.querySelector('#scVideo');
    const prog = panel.querySelector('#scProgress');
    const cv = document.createElement('canvas');
    const collected = [];
    try {
      scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    } catch {
      panel.querySelector('#scError').textContent = 'Camera unavailable — use Open vault file instead.';
      return;
    }
    video.srcObject = scanStream;
    await video.play().catch(() => {});
    const tick = () => {
      if (!scanStream) return;
      const w = 480, scale = video.videoWidth ? w / video.videoWidth : 1;
      cv.width = w; cv.height = Math.round(video.videoHeight * scale) || w;
      const ctx = cv.getContext('2d');
      ctx.drawImage(video, 0, 0, cv.width, cv.height);
      const bytes = decodeQr(ctx.getImageData(0, 0, cv.width, cv.height));
      if (bytes) {
        const frame = new TextDecoder().decode(bytes);
        if (!collected.includes(frame)) collected.push(frame);
        const res = joinTransfer(collected);
        if (res.text) { stopScan(); onEnvelopeText(res.text); return; }
        if (res.need) prog.textContent = `scanning… ${collected.length} of ${collected.length + res.need.length} frames`;
      }
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }
```

- [ ] **Step 3: Stop the camera on every teardown**

In `wipe()` add `stopScan();`. In the tab-switch handler (`initApp`'s `show`, or
wherever the Vault panel is hidden) call `stopScan()` when leaving the Vault tab
— add to `src/app.js` `show`: `if (!isGen) { /* entering vault */ } else if (window.__kunjiStopScan) window.__kunjiStopScan();` … **simpler:** in `vault-ui.js`,
add `window.addEventListener('beforeunload', stopScan);` next to the existing
`beforeunload` handler, and rely on `wipe()` + the panel Cancel for the rest.
Document that a tab switch mid-scan keeps the camera until Cancel/lock — or, if
that is unacceptable, have `initApp` call a `gen`-style hook. Keep the minimal
version: `wipe()` + Cancel + `beforeunload`.

- [ ] **Step 4: Build + suite**

Run: `node tools/build.mjs && node tools/check-invariants.mjs && node --test`
Expected: green; `fail 0` (no new unit tests — camera is manual; the decode path
is covered by E4).

- [ ] **Step 5: Commit**

```bash
git add src/vault-ui.js src/style.css
git -c commit.gpgsign=false commit -m "feat: vault tab — QR camera scan panel"
```

---

## Task E6: "Scan QR…" and "Show as QR" entry points

**Files:**
- Modify: `src/vault-ui.js`
- Manual test: browser

- [ ] **Step 1: NO_VAULT screen — add "Scan QR…"**

In `renderNoVault` (the NO_VAULT markup), next to the "Open vault file…" button,
add:

```html
<button class="btn-ghost" id="vScanBtn" type="button" style="margin-top:8px">Scan QR&hellip;</button>
```

and wire it:

```js
    panel.querySelector('#vScanBtn').addEventListener('click', () => scanQr((text) => {
      try {
        loadedEnvelope = parseEnvelope(text);
        identityHintOn = typeof loadedEnvelope.identityHint === 'string';
        state = 'LOCKED';
        render();
      } catch {
        panel.querySelector('#vError').textContent = 'Scanned data is not a Kunji vault.';
      }
    }));
```

- [ ] **Step 2: Unlocked footer — add "Show as QR"**

In `renderList`'s footer line add:

```js
      &middot; <button class="link-btn" id="vShowQr" type="button">Show as QR</button>
```

Add `showQr()` to `initVaultTab`:

```js
  async function showQr() {
    const prevRevision = mergedFromRevision != null ? mergedFromRevision
      : (loadedEnvelope ? (Number(loadedEnvelope.revision) || 0) : 0);
    const text = await encodeEnvelope(vault, {
      masterKey, identityHint: currentIdentityForHint(), prevRevision, writerId,
      decoy: (typeof decoyMasterKey !== 'undefined' && decoyMasterKey) ? { vault: decoyVault, masterKey: decoyMasterKey } : null,
    });
    // frameBytes: conservative for a phone scan (QR ~v10 / M)
    const frames = splitTransfer(text, { frameBytes: 180 });
    if (frames.length > 60) {
      alert('This vault is too large for a QR transfer — use Save vault (file) or Syncthing.');
      return;
    }
    let i = 0;
    panel.innerHTML = `
      <div class="v-bar"><button class="link-btn" id="qrDone" type="button">&lsaquo; Done</button></div>
      <div class="qr-panel">
        <canvas class="qr-canvas" id="qrCanvas"></canvas>
        <div class="qr-progress" id="qrCap"></div>
        <div class="v-foot">Scan this with the other device's camera.</div>
      </div>
    `;
    panel.querySelector('#qrDone').addEventListener('click', () => { clearInterval(timer); render(); });
    const canvas = panel.querySelector('#qrCanvas');
    const cap = panel.querySelector('#qrCap');
    const paint = () => {
      const m = qrMatrix(new TextEncoder().encode(frames[i]), { ecc: 'M' });
      const q = 4, s = 4, dim = (m.length + q * 2) * s;
      canvas.width = dim; canvas.height = dim;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#000'; ctx.fillRect(0, 0, dim, dim);
      ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, dim, dim);
      ctx.fillStyle = '#000';
      for (let y = 0; y < m.length; y++) for (let x = 0; x < m.length; x++) {
        if (m[y][x]) ctx.fillRect((q + x) * s, (q + y) * s, s, s);
      }
      cap.textContent = frames.length > 1 ? `frame ${i + 1} / ${frames.length}` : '';
      i = (i + 1) % frames.length;
    };
    paint();
    const timer = frames.length > 1 ? setInterval(paint, 250) : null;
  }
```

Wire the footer button (end of `renderList`):

```js
    panel.querySelector('#vShowQr').addEventListener('click', () => showQr().catch(() => {}));
```

- [ ] **Step 3: Unlocked "Scan QR…" for import (routes through merge)**

Also add to the footer: `&middot; <button class="link-btn" id="vScanMerge" type="button">Scan QR to merge</button>` and wire:

```js
    panel.querySelector('#vScanMerge').addEventListener('click', () => scanQr(async (text) => {
      let env, inVault;
      try { env = parseEnvelope(text); inVault = await unlockVault(env, { masterKey }); }
      catch { alert('Scanned data is not readable with this passphrase.'); return; }
      renderMerge(env, inVault);
    }));
```

- [ ] **Step 4: Build + suite**

Run: `node tools/build.mjs && node tools/check-invariants.mjs && node --test`
Expected: green; `fail 0`.

- [ ] **Step 5: Commit**

```bash
git add src/vault-ui.js
git -c commit.gpgsign=false commit -m "feat: vault tab — Show as QR / Scan QR entry points"
```

---

## Task E7: Docs + parent-spec sync

**Files:**
- Modify: `docs/specs/2026-09-01-kunji-design.md`, `README.md`

- [ ] **Step 1: §7.3** — replace "manual QR/file transfer" wording with:

```
Manual QR transfer is built in: **Show as QR** renders the encrypted envelope as
a QR code (an animated multi-frame sequence past ~180 bytes, `KQR1 seq total
nonce b64` framing, capped at 60 frames), and **Scan QR…** reads it with the
device camera, in-app, with no decoder dependency. Import while unlocked routes
through the same merge check as opening a file.
```

- [ ] **Step 2: §7.4** — add:

```
The QR codec (`src/qr.js`, `src/qr-decode.js`) is first-party, byte-mode only,
and auditable by reading. The camera path uses `getUserMedia`, which opens no
network connection; `<video>` is fed via `srcObject`, not a URL, so no CSP
directive is added. (If a browser is found to enforce `media-src` on `srcObject`,
add `media-src 'self' blob:` to both build CSPs — `connect-src` is still never
added.)
```

- [ ] **Step 3: §12** — phase-3 bullet: append `3e QR transfer (…phase3e-qr-transfer-design.md)`.

- [ ] **Step 4: README** — under `## The vault`, append:

```
Two devices with no shared file-sync can move a vault by QR: **Show as QR** on
one, **Scan QR…** on the other. Large vaults animate across several frames.
```

- [ ] **Step 5: Full verification**

Run: `npm run verify` — all pass; `fail 0`; `dist/kunji.html written`;
`dist/pwa/ written`; `invariants ok`.

- [ ] **Step 6: Manual end-to-end (two browsers / a phone, over `https`/`localhost`)**

- Small vault → **Show as QR** (one static code). Second device → **Scan QR…**
  → grant camera → LOCKED view → unlock → entries present. Matches a file open.
- Vault big enough for ~6 frames → animated loop; scanner shows `n of N`,
  completes out of order → unlock.
- **Scan QR to merge** while unlocked → the merge summary (Part D).
- Camera denied → the fallback message; "Open vault file" still works.
- Cancel mid-scan and lock → OS camera indicator goes off.
- DevTools Network: empty throughout. No console errors.

- [ ] **Step 7: Commit**

```bash
git add docs/specs/2026-09-01-kunji-design.md README.md
git -c commit.gpgsign=false commit -m "docs: QR transfer — readme and parent-spec sync"
```

---

## Self-review

**Spec coverage — C:**
- `dist/kunji.html` untouched; `dist/pwa/` from `buildPwa()` — Task C3; `--no-pwa`
  and byte-identity asserted — C3 test.
- CSP `worker-src 'self'`, never `connect-src` — C3 (regex insert) + C3/C4 tests.
- `sw.js` cache-first, `SHELL_VERSION = sha256(index.html)`, 8-asset shell list,
  stale-cache cleanup, `SKIP_WAITING` on message — Task C2 template + C3 fill.
- Update bar, `skipWaiting` only on Reload click — C2 `register.html`.
- Manifest with relative icon srcs — C2 + C3 test.
- Dependency-free deterministic PNG icons — Task C1 + tests.
- `check-invariants` strict for `src/`+`dist/kunji.html`, relaxed for `dist/pwa/`
  (no external URLs, no `connect-src`, `fetch` only in `sw.js`) — Task C4 + tests.
- §7.2 / §12 / README — Task C5. Out of scope respected (no push/sync/hosting;
  SW never caches vault data — the shell list has no vault path).

**Spec coverage — D:**
- Tombstones `{id,deleted:true,updatedAt}`, permanent, additive, no `v` bump —
  Task D1 (`removeEntry`) + rewritten test.
- `visibleEntries` filter wired into list, count, detail guard, dup-check, and
  the 3a bridge — Tasks D1, D4.
- `mergeVaults` entry-level LWW: add / update both directions / delete-wins /
  resurrect / equal-unchanged / tie→lastWriter→local / settings-by-revision /
  order stability / commutative outcome — Task D2 + 8 tests.
- `classifyIncoming`: wrong-passphrase / same / fast-forward / diverged — Task D3
  + 4 tests.
- Import-while-unlocked routing (same / fast-forward / diverged / wrong-pass) and
  `Merge another copy…`; review-then-apply summary with expandable buckets;
  `mergedFromRevision` → save `revision = max+1`, `lastWriter` = this device —
  Tasks D5, D6.
- §5.2 / §7.3 / §12 — Task D6. Out of scope respected (no per-field timestamps,
  no folder scan, no interactive per-entry resolution, no `v` bump, no
  compaction).
- **Deviation:** the diverged decision is a `prompt()` in D5, not a 3-button
  panel — flagged in a design note with an explicit "swap in a panel, keep the
  behaviour" instruction.

**Spec coverage — E:**
- `src/qr.js` byte-mode encoder, smallest fitting version, frozen fixtures +
  determinism + capacity throw — Task E1 (build-to-contract: exact signature +
  ISO clause sub-steps + fixture/round-trip tests as the gate).
- `src/qr-decode.js` `ImageData → bytes | null`, never throws — Task E4
  (build-to-contract: signature + ISO clause sub-steps + render-then-decode
  round-trips across versions/ECC, rotation, RS-budget bounds, blank/noise→null).
- `src/qr-transfer.js` `KQR1 seq total nonce b64` split/join, ≤ `frameBytes`,
  shuffled / missing / wrong-nonce / malformed / single-frame — Task E2 + 7 tests
  (complete code).
- Camera panel: `getUserMedia({facingMode:'environment'})`, downscaled
  `requestAnimationFrame` decode loop, `joinTransfer` accumulation with progress,
  stop on success / Cancel / `wipe()` / `beforeunload` — Task E5 (complete code).
- "Scan QR…" on NO_VAULT → LOCKED; "Show as QR" animated multi-frame, 60-frame
  cap; "Scan QR to merge" → `renderMerge` — Task E6 (complete code).
- No CSP change; verify `srcObject` vs `media-src` in browsers with a bounded
  fallback — Task E7 §7.4 wording + the manual step's Network check.
- §7.3 / §7.4 / §12 / README — Task E7. Out of scope respected (whole-envelope
  only, camera-only import, main-thread decode, no dependency, no `connect-src`).

**Placeholder scan:** Parts C and D contain complete code in every code step. Part
E's two codec tasks are *explicitly* build-to-contract (signature + standard
clause + acceptance tests) — this is a stated, bounded structure for units that
cannot be pre-written, not a "TODO". The `src/qr-decode.js` stub in Task E3
returns `null` for exactly one commit and is replaced in Task E4.

**Type / name consistency:** `qrMatrix(bytes, { ecc }) -> boolean[][]`,
`QR_CAPACITY`, `decodeQr(image) -> Uint8Array|null`,
`splitTransfer(text, { frameBytes }) -> string[]`,
`joinTransfer(frames) -> { text } | { need } | { error }`,
`visibleEntries(vault)`, `removeEntry(vault, id)` (tombstone),
`mergeVaults(local, incoming) -> { vault, summary }`,
`classifyIncoming(localEnv, localVault, inEnv, inVault) -> string`,
`buildPwa(shellHtml)`, `SHELL_VERSION` / `SHELL_ASSETS`,
and the vault-ui state `mergedFromRevision` / `pendingImport` / `scanStream`
are used identically across every task that references them.

**Scope:** three independent sub-projects in one plan, ordered C → D → E so E's
import routing can build on D's `classifyIncoming`. Every task boundary produces
a working `dist/kunji.html` (E3's one-commit `decodeQr` stub excepted, resolved
in E4). C is `tools/`-only; D and E are additive (no `v` bump, no crypto/profile
change, no dependency).

**Recommendation:** run Part E as its own `subagent-driven-development` pass with
a capable model, one task per subagent, because E1 and E4 are research-grade.
