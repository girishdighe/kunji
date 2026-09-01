# Building and testing Kunji

Kunji has **no dependencies** and **no bundler**. "Building" is concatenating a
handful of files into one HTML document. Anyone with Node can reproduce the
released file byte-for-byte.

## Requirements

- **Node.js 20 or newer** (CI runs on 24). Nothing else. `npm install` does
  nothing useful here — there is no `node_modules`.

## Commands

```sh
node tools/build.mjs            # -> dist/kunji.html  and  dist/pwa/
node tools/build.mjs --no-pwa   # -> dist/kunji.html only

npm test        # node --test: unit tests + crypto KATs + frozen v1 vectors
npm run check   # tools/check-invariants.mjs: the no-network / single-file scan
npm run verify  # test + build + check, in that order
```

`npm run verify` is the gate. If it passes, the change is shippable.

## What the build does

`tools/build.mjs`:

1. Reads `src/head.html` (the `<head>`, the CSP, and the DOM skeleton) and
   `src/tail.html` (the closing `<script>` tag and `</body></html>`).
2. Reads `src/style.css` and inlines it where `head.html` has `/*STYLE*/`.
3. Reads every JavaScript module listed in `JS_ORDER`, in that exact order,
   strips the `import`/`export` keywords (the modules are written as normal ES
   modules so editors and tests understand them, but the shipped file is one
   plain script), and concatenates them where `tail.html` has `/*SCRIPT*/`. Each
   module is preceded by a `// ==== src/<name>.js ====` marker.
4. Writes `dist/kunji.html`.
5. Unless `--no-pwa`, also writes `dist/pwa/` — the same HTML with a service
   worker, a web manifest, generated icons, and `worker-src 'self'` added to the
   CSP. `dist/pwa/sw.js` is the only file in the project allowed to call
   `fetch`/`caches` (it serves the app shell offline); the page itself still
   cannot make a network request.

The build is **deterministic**: same source in, byte-identical `dist/kunji.html`
out. CI proves this by building twice and comparing SHA-256.

`dist/` is git-ignored. The file in a GitHub Release is built by the release
process (see [RELEASING.md](RELEASING.md)) and signed.

## The no-network invariant scan

`tools/check-invariants.mjs` is what lets Kunji claim "sends nothing". It reads
every file in `src/` and the built `dist/kunji.html` and **fails** if any of
these appear:

- `fetch(`
- `XMLHttpRequest`, `WebSocket`, `sendBeacon`
- `<script ... src=`, `<link`, `@import`
- any `http://` or `https://`

A relaxed pass covers `dist/pwa/`: still no external origins, still no
`connect-src`; `fetch`/`caches` are tolerated **only** in `sw.js`.

Practical consequence for contributors: you cannot add a CDN font, an analytics
snippet, a telemetry ping, or a "check for updates" call. That is deliberate. If
you think you need one, open an issue first — the answer is almost certainly a
different design.

## Repository layout

```
src/
  head.html          <head> + CSP + DOM skeleton; contains /*STYLE*/
  tail.html          closing <script>/*SCRIPT*/</script> + </body></html>
  style.css          all styles (X-inspired dark theme, CSS variables)

  encoding.js        utf8 / base64 / byte helpers          (no deps)
  webcrypto.js       PBKDF2 / HKDF / HMAC over crypto.subtle
  totp.js            RFC 6238 TOTP (HMAC-SHA1)
  passkey-store.js   in-memory passkey record handling
  webauthn.js        WebAuthn PRF wrapper for passkey unlock
  qr.js              QR encode/render
  qr-decode.js       QR decode from camera frames
  qr-transfer.js     multi-frame whole-vault QR protocol
  derive.js          THE generator: profile registry, master key, entry seed,
                     password shaping. v1 is frozen.
  vault.js           vault model: entries, tombstones, merge, envelope encrypt
  vault-bridge.js    glue between the generator and vault entries
  app.js             Generate tab UI + clipboard handling
  vault-ui.js        Vault tab UI (unlock, entries, decoy, QR, passkey, TOTP)
  readout.js         the header split-flap display (decorative)

tools/
  build.mjs              the build
  check-invariants.mjs   the no-network scan
  gen-icons.mjs          PWA icon generation
  pwa/                    service worker, manifest, register snippet, head-extra

tests/
  *.test.mjs        node:test suites
  vectors/v1.json   frozen derivation outputs (see below)
  vectors/qr/       QR round-trip fixtures
  fixtures/         sample vault files

docs/
  USAGE.md              end-user guide
  BUILD.md             this file
  ARCHITECTURE.md      how it fits together
  sync.md              moving a vault between devices
  RELEASING.md         cutting a signed release
  specs/               one design doc per feature
  plans/               implementation plans

.github/workflows/
  ci.yml               test + check + deterministic-build + clean-tree, on every push/PR
  verify-release.yml   independent rebuild + signature check for each tag
```

The module order in `JS_ORDER` (in `tools/build.mjs`) is the dependency order.
`build.test.mjs` asserts key ordering constraints, so if you add a module, add it
to `JS_ORDER` and keep those assertions true.

## The frozen v1 profile

`tests/vectors/v1.json` records the exact password output for a set of inputs.
`tests/vectors.test.mjs` re-derives them and fails on any difference.

**You cannot change what a `v1` password comes out to.** Not the KDF, not the
iteration count (`PBKDF2_ITERATIONS = 600000`), not the charset, not the shaping.
A better KDF ships as profile `v2` — a new object in the `PROFILES` registry in
`derive.js` — and users opt in per entry. See
[`docs/specs/2026-09-01-kunji-v2-profile-requirements.md`](specs/2026-09-01-kunji-v2-profile-requirements.md).

Crypto changes also need known-answer tests: the primitives in `webcrypto.js` are
checked against the published RFC test vectors in `tests/webcrypto.test.mjs`.
