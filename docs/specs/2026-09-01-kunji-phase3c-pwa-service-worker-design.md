# Kunji Phase 3c — PWA + service worker

**Date:** 2026-09-01
**Status:** Draft for review
**Authors:** grd + friend
**Parent spec:** `docs/specs/2026-09-01-kunji-design.md` (§7.2 "App onto a device", §7.4 "Self-imposed CSP")
**Depends on:** the Phase 1/2 single-file build (`tools/build.mjs` → `dist/kunji.html`).

---

## 1. Purpose

Make Kunji installable as an offline app (Add to Home Screen / Install) with a
service worker that serves the cached shell, a web manifest, and home-screen
icons — **without** disturbing `dist/kunji.html`, which remains the pure,
network-incapable single file.

One of five independent Phase 3 sub-projects; its own spec.

## 2. Principles

- `dist/kunji.html` is unchanged, byte-for-byte, by this phase.
- The PWA build still cannot reach the network from page code: its CSP adds only
  `worker-src 'self'` and still omits `connect-src`, so `fetch` / XHR / WebSocket
  from the page are blocked. The service worker's `fetch` only ever serves
  same-origin shell assets it cached at install.
- Everything is byte-reproducible: `dist/pwa/` is a deterministic transform of
  `dist/kunji.html` plus static inputs.
- The service worker caches the **app shell only** — never the user's vault file
  (that is opened via `<input type=file>`, never requested).

## 3. Build

### 3.1 Inputs (`tools/pwa/`)

| File | Role |
|---|---|
| `tools/pwa/sw.js` | Service-worker source template. Contains `__SHELL_VERSION__` and `__SHELL_ASSETS__` placeholders the build fills. |
| `tools/pwa/manifest.webmanifest` | Static manifest (see §3.4). |
| `tools/pwa/head-extra.html` | The `<link rel="manifest">` + `<link rel="apple-touch-icon">` lines injected into `<head>`. |
| `tools/pwa/register.html` | The `<script>` block appended before `</body>` (registration + update bar). |
| `tools/gen-icons.mjs` | Dependency-free PNG generator (see §3.5). |

`src/` is untouched, so its strict invariant scan (§5) is unaffected.

### 3.2 `tools/build.mjs`

After writing `dist/kunji.html`, run `buildPwa()`:

1. Read the just-built `dist/kunji.html` string.
2. **CSP:** replace the `Content-Security-Policy` meta content with the same
   directives **plus** `worker-src 'self'`. No other directive changes; no
   `connect-src` is added.
3. **Head:** insert `tools/pwa/head-extra.html` immediately before `</head>`.
4. **Body:** insert `tools/pwa/register.html` immediately before `</body>`.
5. Write the result to `dist/pwa/index.html`. The `<style>` and the app
   `<script>` are byte-identical to `dist/kunji.html`.
6. Compute `SHELL_VERSION = sha256(dist/pwa/index.html)` (hex).
7. Render `tools/pwa/sw.js` with `__SHELL_VERSION__` = that hash and
   `__SHELL_ASSETS__` = the JSON array of shell paths (§3.3). Write `dist/pwa/sw.js`.
8. Copy `tools/pwa/manifest.webmanifest` → `dist/pwa/manifest.webmanifest`.
9. Run `gen-icons.mjs` → `dist/pwa/icon-192.png`, `icon-512.png`,
   `icon-512-maskable.png`, `apple-touch-icon.png` (180×180).

`npm run build` produces both `dist/kunji.html` and `dist/pwa/`. A `--no-pwa`
flag skips step `buildPwa()` for the pure single-file case.

### 3.3 Shell asset list

```
['./', './index.html', './sw.js', './manifest.webmanifest',
 './icon-192.png', './icon-512.png', './icon-512-maskable.png', './apple-touch-icon.png']
```

### 3.4 `manifest.webmanifest`

```jsonc
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

### 3.5 Icons (`tools/gen-icons.mjs`)

Dependency-free. Builds a raw RGBA pixel buffer for a flat mark (brand ground
`#0F1419`, a centred `#1D9BF0` square at ~45% side), encodes a valid PNG with
`node:zlib.deflateSync` (IHDR + single IDAT + IEND, no filtering / filter type 0).
Deterministic byte output for a given size. The mark is intentionally minimal;
the implementation plan may refine it (still deterministic, still dependency-free).

### 3.6 Service worker (`sw.js`)

```js
const SHELL_VERSION = '__SHELL_VERSION__';
const SHELL_ASSETS  = __SHELL_ASSETS__;
const CACHE = 'kunji-' + SHELL_VERSION;

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL_ASSETS)));
  // no skipWaiting here — see update flow
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k.startsWith('kunji-') && k !== CACHE).map((k) => caches.delete(k))),
    ).then(() => self.clients.claim()),
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

Cache-first. The network fallback exists only for completeness; offline, every
shell asset is cached, and the page makes no other requests (CSP).

### 3.7 Registration + update bar (`register.html`)

```html
<div id="swUpdateBar" hidden style="…">New version available <button id="swReload" type="button">Reload</button></div>
<script>
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('./sw.js').then((reg) => {
    reg.addEventListener('updatefound', () => {
      const w = reg.installing;
      w.addEventListener('statechange', () => {
        if (w.state === 'installed' && navigator.serviceWorker.controller) {
          const bar = document.getElementById('swUpdateBar');
          bar.hidden = false;
          document.getElementById('swReload').addEventListener('click', () => {
            w.postMessage({ type: 'SKIP_WAITING' });
          });
        }
      });
    });
  });
  let reloaded = false;
  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if (reloaded) return; reloaded = true; location.reload();
  });
}
</script>
```

`skipWaiting()` fires only when the user clicks Reload. Until then the running
app is unchanged.

## 4. Parent-spec updates

- **§7.2** — under "Single file" / "Self-hosted PWA", note the update model:
  a new deploy shows a "New version available — Reload" bar; nothing changes
  until the user acts.
- **§12**, phase 3 bullet — service worker + manifest are specified in
  `2026-09-01-kunji-phase3c-pwa-service-worker-design.md`.

## 5. Invariants (`tools/check-invariants.mjs`)

Unchanged strict pass for every file in `src/` and for `dist/kunji.html`:
forbids `fetch(`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, `<script … src=`,
`<link`, `@import`, `https?://`.

**New pass for `dist/pwa/`:**
- Forbid `https?://` and `http://` anywhere (no external origins).
- Forbid `connect-src` appearing in any CSP.
- Allow, in `index.html`: `<link rel="manifest">`, `<link rel="apple-touch-icon">`,
  `navigator.serviceWorker.register('./sw.js')`.
- Allow, in `sw.js` only: `caches`, `fetch(` (the same-origin fallback),
  `self.skipWaiting`, `self.clients`.
- `manifest.webmanifest`: must be valid JSON; `start_url` and every `icons[].src`
  must be relative.

## 6. Files changed

| File | Change |
|---|---|
| `tools/build.mjs` | + `buildPwa()` (steps §3.2); `--no-pwa` flag. |
| `tools/pwa/sw.js` | **new** (template, §3.6). |
| `tools/pwa/manifest.webmanifest` | **new** (§3.4). |
| `tools/pwa/head-extra.html` | **new** (2 `<link>` lines). |
| `tools/pwa/register.html` | **new** (§3.7). |
| `tools/gen-icons.mjs` | **new** (§3.5). |
| `tools/check-invariants.mjs` | + the `dist/pwa/` pass (§5). |
| `tests/build.test.mjs` / `tests/pwa.test.mjs` | + PWA build assertions (§7). |
| `docs/specs/2026-09-01-kunji-design.md` | §7.2 + §12 edits. |
| `package.json` | `build` / `verify` unchanged (they already call `tools/build.mjs`, which now also emits `dist/pwa/`); optionally add `build:single` = `node tools/build.mjs --no-pwa`. |

`src/` : **no changes.**

## 7. Testing

**Unit — `tests/pwa.test.mjs` (new)**
- `buildPwa` runs; `dist/pwa/index.html` exists.
- Its CSP meta contains `worker-src 'self'` and does **not** contain
  `connect-src`.
- It contains `<link rel="manifest" href="manifest.webmanifest">`,
  an `apple-touch-icon` link, and `navigator.serviceWorker.register('./sw.js')`.
- The `<style>…</style>` and the app `<script>…</script>` in `index.html` are
  byte-equal to those in `dist/kunji.html`.
- `dist/pwa/sw.js` exists; `SHELL_VERSION` equals `sha256(index.html)`;
  `SHELL_ASSETS` equals the §3.3 list.
- `dist/pwa/manifest.webmanifest` parses; has `name`, `start_url`, `scope`,
  `display`, ≥ 1 `icons` entry with a relative `src`.
- The four icon files exist and start with the PNG magic `89 50 4E 47`.
- No file under `dist/pwa/` contains `https://` or `http://`.
- `node tools/check-invariants.mjs` still exits 0 with `dist/pwa/` present.

**Unit — `tests/build.test.mjs`**
- `node tools/build.mjs --no-pwa` produces `dist/kunji.html` and **no**
  `dist/pwa/`; `dist/kunji.html` is byte-identical to the full build's.

**Manual (Chrome DevTools → Application)**
- Serve `dist/pwa/` over `http://localhost`. "Install" is offered; install it.
- DevTools → Service Workers shows an activated worker; Cache Storage has
  `kunji-<hash>` with all 8 assets.
- Toggle "Offline": reload — the app still opens; Generate works; Vault "open a
  file" works (local file, no network).
- Change a source file, `npm run build`, redeploy: the running installed app
  shows "New version available — Reload"; clicking it loads the new hash; the old
  `kunji-*` cache is deleted on activate.
- `dist/kunji.html` opened directly (file://) is unchanged and still works.
- `npm run verify` green; DevTools Network tab: only same-origin shell requests,
  ever.

## 8. Out of scope

- No push notifications, background sync, or periodic background sync (all need
  network and/or permissions; CSP forbids network from the page anyway).
- No hosting, GitHub Pages deploy, CI, or release signing — that is Phase 4.
- The service worker never caches, inspects, or transmits vault data.
- No change to `dist/kunji.html`, `src/`, the `v1` profile, or any vector.
- No offline "app update" that changes behaviour without the user clicking Reload.

## 9. Self-review

- **Placeholders:** `sw.js`, `register.html`, `manifest.webmanifest`, and the
  `buildPwa()` steps are given concretely; the icon *mark* is explicitly a
  refine-later placeholder but the *encoder* and output contract are fixed. No
  TBDs in the build or test contract.
- **Consistency:** §2's "page still cannot reach the network" holds — §3.2 step 2
  adds only `worker-src 'self'`; §5 forbids `connect-src` in `dist/pwa/`; §3.6's
  only `fetch` is the SW same-origin fallback, allowed by §5 in `sw.js` alone.
  §2's "shell only, never vault data" holds — §3.3's asset list has no vault
  path and the SW has no code that could see `<input type=file>` data.
- **Scope:** all new code is under `tools/`; `src/` is untouched; `dist/kunji.html`
  is untouched. One plan.
- **Ambiguity:** the update flow pins `skipWaiting` to the Reload click (§3.6,
  §3.7); reproducibility is pinned to "deterministic transform + static inputs +
  deterministic icon encoder" (§2, §3).
- **Risk noted:** `gen-icons.mjs` hand-rolling PNG is the fiddliest piece; the
  plan should land it first with its own byte-frozen test.
