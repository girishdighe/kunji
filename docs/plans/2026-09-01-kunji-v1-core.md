# Kunji v1 core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a single auditable `kunji.html` that turns identity + master passphrase + site + account into a deterministic v1 password, with the X.com-style UI, a live key-check indicator, reveal toggle, and copy-with-auto-clear. No persistence yet.

**Architecture:** Vanilla JavaScript, no framework, no bundler, no runtime dependencies. Cryptography uses the platform `crypto.subtle` (PBKDF2-SHA512, HKDF-SHA256, HMAC-SHA256). Source is split into small focused files under `src/`; `tools/build.mjs` concatenates them into one `dist/kunji.html` by stripping `import`/`export` lines and inlining CSS. Unit tests run on Node's built-in test runner (`node --test`), which also has `crypto.subtle`. A committed `tests/vectors/v1.json` locks the v1 algorithm: any change to its output fails CI.

**Tech Stack:** Node.js >= 20 (built-in `node:test`, `globalThis.crypto`, `btoa`/`atob`), browser Web Crypto API, plain HTML/CSS/JS.

**Scope note:** This plan covers spec Phase 1 only (spec section 12). Phases 2 (encrypted vault), 3 (QR/sync/PWA), and 4 (distribution/CI hardening) get their own plans after this one lands. This plan produces working, testable software on its own.

**Spec:** `docs/specs/2026-09-01-kunji-design.md`. Section 4 (the v1 profile) is the source of truth for every derivation detail below.

---

## File structure

| File | Responsibility |
|---|---|
| `package.json` | `"type": "module"`, test/build/check scripts. Zero dependencies. |
| `.gitignore` | Ignores `dist/` and `node_modules/`. |
| `src/encoding.js` | Byte helpers: `utf8`, `fromUtf8`, `uint32be`, `concatBytes`, `bytesToHex`, `hexToBytes`, `bytesToBase64`, `base64ToBytes`. |
| `src/webcrypto.js` | Thin typed wrappers over `crypto.subtle`: `pbkdf2Sha512`, `hkdfSha256`, `hmacSha256`. |
| `src/derive.js` | The v1 profile. Constants, `normaliseInput`, `requiredClasses`, `classChars`, `makeKeystream`, `sampleIndex`, `deriveEntrySeed`, `generateChars`, `enforceClasses`, `deriveMasterKey`, `computeKcv`, `derivePassword`. No DOM. |
| `src/app.js` | UI: pure helpers (`estimateEntropyBits`, `groupInFours`) plus DOM wiring (event listeners, render, reveal timer, clipboard clear). |
| `src/head.html` | `<!doctype html>` through the opening of `<body>` and the card markup, with the CSP meta. Contains the token `/*STYLE*/` where CSS is inlined. |
| `src/tail.html` | Closing `</body></html>`. Contains the token `/*SCRIPT*/` where JS is inlined. |
| `src/style.css` | The X.com-style CSS, ported from `scratchpad/kunji-mockup.html` with the AA contrast fix. |
| `tools/build.mjs` | Concatenate `src/` into `dist/kunji.html`. |
| `tools/check-invariants.mjs` | Fail if `src/` or `dist/` contain any network primitive or external resource reference. |
| `tools/gen-vectors.mjs` | One-off: generate `tests/vectors/v1.json` from `derive.js`. Committed output is the freeze. |
| `tests/*.test.mjs` | Unit tests, one file per `src/` module, plus `build.test.mjs` and `vectors.test.mjs`. |
| `tests/vectors/v1.json` | Frozen v1 test vectors. Changing any value here is a deliberate profile change. |
| `README.md` | What Kunji is, how to build, how to run tests, the "open the file" instructions. |

---

## Task 1: Project scaffold

**Files:**
- Create: `package.json`
- Create: `.gitignore`
- Create: `src/head.html`, `src/tail.html`, `src/style.css`, `src/app.js` (stubs so the build always has inputs)
- Test: `tests/sanity.test.mjs`

- [ ] **Step 1: Write the sanity test**

Create `tests/sanity.test.mjs`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';

test('node test runner works', () => {
  assert.equal(1 + 1, 2);
});

test('crypto.subtle is available', () => {
  assert.ok(globalThis.crypto && globalThis.crypto.subtle, 'crypto.subtle missing; need Node >= 20');
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `node --test tests/sanity.test.mjs`
Expected: FAIL with `Cannot find module` for `tests/sanity.test.mjs`'s siblings? No — it will actually PASS once the file exists. First create `package.json` below, then this step's expectation is: `node --test` errors with "no such file" until the file is saved. Save the file, then it passes. (This task has no red phase; it establishes the harness.)

- [ ] **Step 3: Create `package.json`**

```json
{
  "name": "kunji",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "scripts": {
    "test": "node --test",
    "build": "node tools/build.mjs",
    "check": "node tools/check-invariants.mjs"
  }
}
```

- [ ] **Step 4: Create `.gitignore`**

```
node_modules/
dist/
```

- [ ] **Step 5: Create stub source files**

`src/head.html`:

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'">
<title>Kunji</title>
<style>/*STYLE*/</style>
</head>
<body>
<main class="card"><p>stub</p></main>
```

`src/tail.html`:

```html
<script>/*SCRIPT*/</script>
</body>
</html>
```

`src/style.css`:

```css
/* filled in Task 13 */
```

`src/app.js`:

```js
// filled in Task 12 and Task 14
```

- [ ] **Step 6: Run the sanity test**

Run: `node --test`
Expected: PASS, 2 tests passing.

- [ ] **Step 7: Commit**

```bash
git add package.json .gitignore src/ tests/sanity.test.mjs docs/
git commit -m "chore: scaffold kunji project"
```

---

## Task 2: Encoding helpers

**Files:**
- Create: `src/encoding.js`
- Test: `tests/encoding.test.mjs`

- [ ] **Step 1: Write the failing tests**

Create `tests/encoding.test.mjs`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  utf8, fromUtf8, uint32be, concatBytes,
  bytesToHex, hexToBytes, bytesToBase64, base64ToBytes,
} from '../src/encoding.js';

test('utf8 / fromUtf8 round-trip incl. non-ASCII', () => {
  const s = 'héllo · 世界';
  assert.equal(fromUtf8(utf8(s)), s);
});

test('utf8 of "abc" is 0x61 0x62 0x63', () => {
  assert.deepEqual([...utf8('abc')], [0x61, 0x62, 0x63]);
});

test('uint32be encodes big-endian', () => {
  assert.deepEqual([...uint32be(0)], [0, 0, 0, 0]);
  assert.deepEqual([...uint32be(1)], [0, 0, 0, 1]);
  assert.deepEqual([...uint32be(0x01020304)], [1, 2, 3, 4]);
  assert.deepEqual([...uint32be(0xffffffff)], [255, 255, 255, 255]);
});

test('concatBytes joins in order', () => {
  const out = concatBytes(Uint8Array.of(1, 2), Uint8Array.of(), Uint8Array.of(3));
  assert.deepEqual([...out], [1, 2, 3]);
});

test('hex round-trip', () => {
  const bytes = Uint8Array.of(0, 15, 16, 255);
  assert.equal(bytesToHex(bytes), '000f10ff');
  assert.deepEqual([...hexToBytes('000f10ff')], [0, 15, 16, 255]);
});

test('hexToBytes rejects odd length', () => {
  assert.throws(() => hexToBytes('abc'));
});

test('base64 round-trip and known value', () => {
  assert.equal(bytesToBase64(utf8('hello')), 'aGVsbG8=');
  assert.equal(fromUtf8(base64ToBytes('aGVsbG8=')), 'hello');
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/encoding.test.mjs`
Expected: FAIL with `Cannot find module '../src/encoding.js'`.

- [ ] **Step 3: Write `src/encoding.js`**

```js
const _enc = new TextEncoder();
const _dec = new TextDecoder();

export function utf8(str) {
  return _enc.encode(str);
}

export function fromUtf8(bytes) {
  return _dec.decode(bytes);
}

export function uint32be(n) {
  const b = new Uint8Array(4);
  b[0] = (n >>> 24) & 0xff;
  b[1] = (n >>> 16) & 0xff;
  b[2] = (n >>> 8) & 0xff;
  b[3] = n & 0xff;
  return b;
}

export function concatBytes(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

export function bytesToHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error('hex length must be even');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToBase64(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/encoding.test.mjs`
Expected: PASS, 7 tests.

- [ ] **Step 5: Commit**

```bash
git add src/encoding.js tests/encoding.test.mjs
git commit -m "feat: byte encoding helpers"
```

---

## Task 3: Web Crypto wrappers

**Files:**
- Create: `src/webcrypto.js`
- Test: `tests/webcrypto.test.mjs`

- [ ] **Step 1: Write the failing tests**

Create `tests/webcrypto.test.mjs`. Anchored to RFC 5869 Test Case 1 (HKDF-SHA256), RFC 4231 Test Case 1 (HMAC-SHA256), and a cross-check of PBKDF2-SHA512 against Node's `node:crypto`.

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pbkdf2Sync } from 'node:crypto';
import { pbkdf2Sha512, hkdfSha256, hmacSha256 } from '../src/webcrypto.js';
import { bytesToHex, hexToBytes, utf8 } from '../src/encoding.js';

test('HKDF-SHA256 matches RFC 5869 test case 1', async () => {
  const ikm = hexToBytes('0b'.repeat(22));
  const salt = hexToBytes('000102030405060708090a0b0c');
  const info = hexToBytes('f0f1f2f3f4f5f6f7f8f9');
  const okm = await hkdfSha256(ikm, salt, info, 42);
  assert.equal(
    bytesToHex(okm),
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
  );
});

test('HMAC-SHA256 matches RFC 4231 test case 1', async () => {
  const key = hexToBytes('0b'.repeat(20));
  const data = utf8('Hi There');
  const mac = await hmacSha256(key, data);
  assert.equal(
    bytesToHex(mac),
    'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
  );
});

test('PBKDF2-SHA512 matches node:crypto', async () => {
  const ours = await pbkdf2Sha512(utf8('password'), utf8('salt'), 1000, 32);
  const nodes = pbkdf2Sync(Buffer.from('password'), Buffer.from('salt'), 1000, 32, 'sha512');
  assert.equal(bytesToHex(ours), nodes.toString('hex'));
});

test('PBKDF2-SHA512 is deterministic', async () => {
  const a = await pbkdf2Sha512(utf8('pw'), utf8('id'), 500, 32);
  const b = await pbkdf2Sha512(utf8('pw'), utf8('id'), 500, 32);
  assert.equal(bytesToHex(a), bytesToHex(b));
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/webcrypto.test.mjs`
Expected: FAIL with `Cannot find module '../src/webcrypto.js'`.

- [ ] **Step 3: Write `src/webcrypto.js`**

```js
export async function pbkdf2Sha512(passphraseBytes, saltBytes, iterations, dkLenBytes) {
  const key = await crypto.subtle.importKey(
    'raw', passphraseBytes, 'PBKDF2', false, ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-512', salt: saltBytes, iterations },
    key, dkLenBytes * 8,
  );
  return new Uint8Array(bits);
}

export async function hkdfSha256(ikmBytes, saltBytes, infoBytes, lenBytes) {
  const key = await crypto.subtle.importKey(
    'raw', ikmBytes, 'HKDF', false, ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info: infoBytes },
    key, lenBytes * 8,
  );
  return new Uint8Array(bits);
}

export async function hmacSha256(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, msgBytes);
  return new Uint8Array(sig);
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/webcrypto.test.mjs`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add src/webcrypto.js tests/webcrypto.test.mjs
git commit -m "feat: web crypto wrappers (pbkdf2, hkdf, hmac)"
```

---

## Task 4: Build tool and invariant check

**Files:**
- Create: `tools/build.mjs`
- Create: `tools/check-invariants.mjs`
- Test: `tests/build.test.mjs`

- [ ] **Step 1: Write the failing test**

Create `tests/build.test.mjs`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

test('build produces dist/kunji.html with no module keywords or network refs', () => {
  execFileSync('node', ['tools/build.mjs'], { stdio: 'pipe' });
  const html = readFileSync('dist/kunji.html', 'utf8');

  assert.ok(html.startsWith('<!doctype html>'), 'must start with doctype');
  assert.ok(html.includes('<style>'), 'css must be inlined');
  assert.ok(html.includes('<script>'), 'js must be inlined');
  assert.doesNotMatch(html, /^\s*import\s/m, 'no bare import statements');
  assert.doesNotMatch(html, /^\s*export\s/m, 'no bare export statements');
  assert.doesNotMatch(html, /\bfetch\s*\(/, 'no fetch');
  assert.doesNotMatch(html, /XMLHttpRequest|WebSocket|sendBeacon/, 'no network APIs');
  assert.doesNotMatch(html, /https?:\/\//, 'no absolute URLs');
  assert.doesNotMatch(html, /\/STYLE\/|\/SCRIPT\//, 'placeholders replaced');
});

test('check-invariants exits 0 on clean tree', () => {
  execFileSync('node', ['tools/check-invariants.mjs'], { stdio: 'pipe' });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/build.test.mjs`
Expected: FAIL with `Cannot find module` / `ENOENT` for `tools/build.mjs`.

- [ ] **Step 3: Write `tools/build.mjs`**

```js
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';

// Explicit dependency order. encoding -> webcrypto -> derive -> app.
const JS_ORDER = [
  'src/encoding.js',
  'src/webcrypto.js',
  'src/derive.js',
  'src/app.js',
];

function stripModuleSyntax(js) {
  return js
    .split('\n')
    .filter((line) => !/^\s*import\s.*from\s.*;?\s*$/.test(line))
    .map((line) => line.replace(/^\s*export\s+(function|const|class|async)\b/, '$1'))
    .map((line) => line.replace(/^\s*export\s*\{[^}]*\};?\s*$/, ''))
    .join('\n');
}

const head = readFileSync('src/head.html', 'utf8');
const tail = readFileSync('src/tail.html', 'utf8');
const css = readFileSync('src/style.css', 'utf8');
const js = JS_ORDER.map((f) => `// ==== ${f} ====\n${stripModuleSyntax(readFileSync(f, 'utf8'))}`).join('\n\n');

const html = head.replace('/*STYLE*/', () => css) + '\n' + tail.replace('/*SCRIPT*/', () => js);

mkdirSync('dist', { recursive: true });
writeFileSync('dist/kunji.html', html);
console.log(`dist/kunji.html written (${html.length} bytes)`);
```

- [ ] **Step 4: Write `tools/check-invariants.mjs`**

```js
import { readFileSync, existsSync } from 'node:fs';
import { readdirSync } from 'node:fs';

const FORBIDDEN = [
  /\bfetch\s*\(/,
  /XMLHttpRequest/,
  /\bWebSocket\b/,
  /sendBeacon/,
  /<script[^>]+\bsrc=/i,
  /<link\b/i,
  /@import\b/,
  /https?:\/\//,
];
// URLs are allowed nowhere in shipped output. The CSP meta uses no URLs.

const targets = [];
for (const f of readdirSync('src')) targets.push(`src/${f}`);
if (existsSync('dist/kunji.html')) targets.push('dist/kunji.html');

let failed = false;
for (const path of targets) {
  const text = readFileSync(path, 'utf8');
  for (const rx of FORBIDDEN) {
    if (rx.test(text)) {
      console.error(`INVARIANT VIOLATION in ${path}: ${rx}`);
      failed = true;
    }
  }
}
if (failed) process.exit(1);
console.log(`invariants ok (${targets.length} files)`);
```

- [ ] **Step 5: Run to verify it passes**

Run: `node --test tests/build.test.mjs`
Expected: PASS, 2 tests. `dist/kunji.html` now exists (gitignored).

- [ ] **Step 6: Commit**

```bash
git add tools/build.mjs tools/check-invariants.mjs tests/build.test.mjs
git commit -m "build: single-file concatenation and invariant gate"
```

---

## Task 5: Derive constants and normalisation

**Files:**
- Create: `src/derive.js`
- Test: `tests/derive.test.mjs`

- [ ] **Step 1: Write the failing tests**

Create `tests/derive.test.mjs`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CHARSETS, DEFAULT_LENGTH, MIN_LENGTH, MAX_LENGTH, DEFAULT_RULES, PROFILE,
  normaliseInput, requiredClasses, classChars,
} from '../src/derive.js';

test('profile id is v1', () => {
  assert.equal(PROFILE, 'v1');
});

test('charsets are the exact frozen strings', () => {
  assert.equal(
    CHARSETS.standard,
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*+-=?@_',
  );
  assert.equal(
    CHARSETS['letters-digits'],
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
  );
  assert.equal(
    CHARSETS['max-symbols'],
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*()-_=+[]{};:,.?@',
  );
});

test('charset lengths', () => {
  assert.equal(CHARSETS.standard.length, 72);
  assert.equal(CHARSETS['letters-digits'].length, 62);
  assert.equal(CHARSETS['max-symbols'].length, 83);
});

test('defaults', () => {
  assert.equal(DEFAULT_LENGTH, 20);
  assert.equal(MIN_LENGTH, 8);
  assert.equal(MAX_LENGTH, 64);
  assert.equal(DEFAULT_RULES, 'standard');
});

test('normaliseInput: NFKC, trim, lowercase', () => {
  assert.equal(normaliseInput('  GitHub.com  '), 'github.com');
  assert.equal(normaliseInput('ﬁle'), 'file');        // fi ligature -> "fi"
  assert.equal(normaliseInput('ＦＵＬＬ'), 'full');           // full-width -> ascii
  assert.equal(normaliseInput('Ä'), 'ä');
});

test('requiredClasses', () => {
  assert.deepEqual(requiredClasses('standard'), ['lower', 'upper', 'digit', 'symbol']);
  assert.deepEqual(requiredClasses('max-symbols'), ['lower', 'upper', 'digit', 'symbol']);
  assert.deepEqual(requiredClasses('letters-digits'), ['lower', 'upper', 'digit']);
});

test('classChars: symbol pool is the non-alnum chars of the active charset', () => {
  assert.equal(classChars('lower', CHARSETS.standard), 'abcdefghijklmnopqrstuvwxyz');
  assert.equal(classChars('upper', CHARSETS.standard), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  assert.equal(classChars('digit', CHARSETS.standard), '0123456789');
  assert.equal(classChars('symbol', CHARSETS.standard), '!#$%&*+-=?@_');
  assert.equal(classChars('symbol', CHARSETS['letters-digits']), '');
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/derive.test.mjs`
Expected: FAIL with `Cannot find module '../src/derive.js'`.

- [ ] **Step 3: Write the first part of `src/derive.js`**

```js
import { utf8, uint32be, concatBytes, bytesToBase64 } from './encoding.js';
import { pbkdf2Sha512, hkdfSha256, hmacSha256 } from './webcrypto.js';

export const PROFILE = 'v1';

// OPEN DECISION (spec s13): confirm on the slowest target device before freezing v1.
export const PBKDF2_ITERATIONS = 600000;

export const MASTER_KEY_BYTES = 32;
export const DEFAULT_LENGTH = 20;
export const MIN_LENGTH = 8;
export const MAX_LENGTH = 64;
export const DEFAULT_RULES = 'standard';

export const CHARSETS = {
  'standard':
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*+-=?@_',
  'letters-digits':
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
  'max-symbols':
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*()-_=+[]{};:,.?@',
};

const _LOWER = 'abcdefghijklmnopqrstuvwxyz';
const _UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const _DIGIT = '0123456789';

export function normaliseInput(str) {
  return str.normalize('NFKC').trim().toLowerCase();
}

export function requiredClasses(rules) {
  if (rules === 'letters-digits') return ['lower', 'upper', 'digit'];
  return ['lower', 'upper', 'digit', 'symbol'];
}

export function classChars(cls, charset) {
  if (cls === 'lower') return _LOWER;
  if (cls === 'upper') return _UPPER;
  if (cls === 'digit') return _DIGIT;
  let out = '';
  for (const ch of charset) {
    if (!/[A-Za-z0-9]/.test(ch)) out += ch;
  }
  return out;
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/derive.test.mjs`
Expected: PASS, 8 tests. If the length assertions fail, do not change the test to match; the charset strings above are the frozen spec values, so a mismatch means a typo in the string literal.

- [ ] **Step 5: Commit**

```bash
git add src/derive.js tests/derive.test.mjs
git commit -m "feat: v1 derive constants and input normalisation"
```

---

## Task 6: Keystream and unbiased index sampling

**Files:**
- Modify: `src/derive.js`
- Test: `tests/derive.test.mjs` (append)

- [ ] **Step 1: Append failing tests**

Add to `tests/derive.test.mjs`:

```js
import { makeKeystream, sampleIndex } from '../src/derive.js';
import { hexToBytes, bytesToHex } from '../src/encoding.js';

test('makeKeystream block 0 equals HMAC-SHA256(seed, "gen" || uint32be(0))', async () => {
  const seed = hexToBytes('00'.repeat(64));
  const ks = makeKeystream(seed, 'gen');
  // Pull 32 bytes, which is exactly block 0.
  const collected = [];
  for (let i = 0; i < 32; i++) collected.push(await ks.next());
  // Independently compute block 0.
  const { hmacSha256 } = await import('../src/webcrypto.js');
  const { concatBytes, utf8, uint32be } = await import('../src/encoding.js');
  const expected = await hmacSha256(seed, concatBytes(utf8('gen'), uint32be(0)));
  assert.equal(bytesToHex(Uint8Array.from(collected)), bytesToHex(expected));
});

test('makeKeystream rolls into block 1 after 32 bytes', async () => {
  const seed = hexToBytes('11'.repeat(64));
  const ks = makeKeystream(seed, 'gen');
  for (let i = 0; i < 32; i++) await ks.next();
  const first = await ks.next();
  const { hmacSha256 } = await import('../src/webcrypto.js');
  const { concatBytes, utf8, uint32be } = await import('../src/encoding.js');
  const block1 = await hmacSha256(seed, concatBytes(utf8('gen'), uint32be(1)));
  assert.equal(first, block1[0]);
});

test('sampleIndex only returns values in range and rejects biased bytes', async () => {
  // Fake keystream: 250, 251, ..., then 3. n = 10 -> limit = 250, so 250 and 251 are rejected.
  const queue = [250, 251, 3];
  const fake = { next: async () => queue.shift() };
  const idx = await sampleIndex(fake, 10);
  assert.equal(idx, 3);
  assert.equal(queue.length, 0);
});

test('sampleIndex maps within [0, n)', async () => {
  const fake = { next: async () => 0 };
  assert.equal(await sampleIndex(fake, 62), 0);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/derive.test.mjs`
Expected: FAIL with `makeKeystream is not exported` / `undefined`.

- [ ] **Step 3: Append to `src/derive.js`**

```js
export function makeKeystream(entrySeed, label) {
  const labelBytes = utf8(label);
  let block = new Uint8Array(0);
  let blockIndex = 0;
  let pos = 0;
  return {
    async next() {
      if (pos >= block.length) {
        block = await hmacSha256(entrySeed, concatBytes(labelBytes, uint32be(blockIndex)));
        blockIndex += 1;
        pos = 0;
      }
      const value = block[pos];
      pos += 1;
      return value;
    },
  };
}

export async function sampleIndex(keystream, n) {
  const limit = 256 - (256 % n);
  for (;;) {
    const b = await keystream.next();
    if (b < limit) return b % n;
  }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/derive.test.mjs`
Expected: PASS, 12 tests.

- [ ] **Step 5: Commit**

```bash
git add src/derive.js tests/derive.test.mjs
git commit -m "feat: hmac keystream and unbiased index sampling"
```

---

## Task 7: Entry seed derivation

**Files:**
- Modify: `src/derive.js`
- Test: `tests/derive.test.mjs` (append)

- [ ] **Step 1: Append failing tests**

```js
import { deriveEntrySeed } from '../src/derive.js';

test('deriveEntrySeed returns 64 bytes and is deterministic', async () => {
  const masterKey = hexToBytes('22'.repeat(32));
  const params = { site: 'github.com', account: 'alex', counter: 1, rules: 'standard', length: 20 };
  const a = await deriveEntrySeed(masterKey, params);
  const b = await deriveEntrySeed(masterKey, params);
  assert.equal(a.length, 64);
  assert.equal(bytesToHex(a), bytesToHex(b));
});

test('deriveEntrySeed uses the exact info string "gen|site|account|counter|rules|length"', async () => {
  const masterKey = hexToBytes('22'.repeat(32));
  const fromApi = await deriveEntrySeed(masterKey, {
    site: 'github.com', account: 'alex', counter: 3, rules: 'standard', length: 24,
  });
  const { hkdfSha256 } = await import('../src/webcrypto.js');
  const { utf8 } = await import('../src/encoding.js');
  const manual = await hkdfSha256(
    masterKey, utf8('kunji/v1'), utf8('gen|github.com|alex|3|standard|24'), 64,
  );
  assert.equal(bytesToHex(fromApi), bytesToHex(manual));
});

test('deriveEntrySeed changes when any field changes', async () => {
  const mk = hexToBytes('22'.repeat(32));
  const base = { site: 'a', account: 'b', counter: 1, rules: 'standard', length: 20 };
  const baseSeed = bytesToHex(await deriveEntrySeed(mk, base));
  for (const mut of [
    { ...base, site: 'a2' },
    { ...base, account: 'b2' },
    { ...base, counter: 2 },
    { ...base, rules: 'letters-digits' },
    { ...base, length: 21 },
  ]) {
    assert.notEqual(bytesToHex(await deriveEntrySeed(mk, mut)), baseSeed);
  }
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/derive.test.mjs`
Expected: FAIL with `deriveEntrySeed is not exported`.

- [ ] **Step 3: Append to `src/derive.js`**

```js
export async function deriveEntrySeed(masterKey, { site, account, counter, rules, length }) {
  const info = utf8(`gen|${site}|${account}|${counter}|${rules}|${length}`);
  return hkdfSha256(masterKey, utf8('kunji/v1'), info, 64);
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/derive.test.mjs`
Expected: PASS, 15 tests.

- [ ] **Step 5: Commit**

```bash
git add src/derive.js tests/derive.test.mjs
git commit -m "feat: v1 entry seed via hkdf"
```

---

## Task 8: Character generation (steps 3 and 4)

**Files:**
- Modify: `src/derive.js`
- Test: `tests/derive.test.mjs` (append)

- [ ] **Step 1: Append failing tests**

```js
import { generateChars } from '../src/derive.js';

test('generateChars: correct length, all chars from the charset, deterministic', async () => {
  const seed = hexToBytes('33'.repeat(64));
  const out1 = await generateChars(seed, CHARSETS.standard, 20);
  const out2 = await generateChars(seed, CHARSETS.standard, 20);
  assert.equal(out1.length, 20);
  assert.equal(out1.join(''), out2.join(''));
  for (const ch of out1) assert.ok(CHARSETS.standard.includes(ch), `char ${ch} not in charset`);
});

test('generateChars: length 64 works and does not repeat blockwise', async () => {
  const seed = hexToBytes('44'.repeat(64));
  const out = await generateChars(seed, CHARSETS['letters-digits'], 64);
  assert.equal(out.length, 64);
  // First 32 chars should not equal the next 32 (would indicate a repeating hash bug).
  assert.notEqual(out.slice(0, 32).join(''), out.slice(32).join(''));
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/derive.test.mjs`
Expected: FAIL with `generateChars is not exported`.

- [ ] **Step 3: Append to `src/derive.js`**

```js
export async function generateChars(entrySeed, charset, length) {
  const keystream = makeKeystream(entrySeed, 'gen');
  const n = charset.length;
  const out = new Array(length);
  for (let i = 0; i < length; i++) {
    out[i] = charset[await sampleIndex(keystream, n)];
  }
  return out;
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/derive.test.mjs`
Expected: PASS, 17 tests.

- [ ] **Step 5: Commit**

```bash
git add src/derive.js tests/derive.test.mjs
git commit -m "feat: v1 character generation via rejection sampling"
```

---

## Task 9: Class enforcement (step 5)

**Files:**
- Modify: `src/derive.js`
- Test: `tests/derive.test.mjs` (append)

- [ ] **Step 1: Append failing tests**

```js
import { enforceClasses } from '../src/derive.js';

function classesPresent(str) {
  const set = new Set();
  for (const ch of str) {
    if (/[a-z]/.test(ch)) set.add('lower');
    else if (/[A-Z]/.test(ch)) set.add('upper');
    else if (/[0-9]/.test(ch)) set.add('digit');
    else set.add('symbol');
  }
  return set;
}

test('enforceClasses is a no-op when all required classes already present', async () => {
  const seed = hexToBytes('55'.repeat(64));
  const chars = 'aB3!aB3!aB3!aB3!aB3!'.split('');
  const out = await enforceClasses(chars, seed, 'standard', CHARSETS.standard);
  assert.equal(out.join(''), chars.join(''));
});

test('enforceClasses injects every missing required class', async () => {
  const seed = hexToBytes('66'.repeat(64));
  const chars = 'aaaaaaaaaaaaaaaaaaaa'.split(''); // only lowercase
  const out = await enforceClasses(chars, seed, 'standard', CHARSETS.standard);
  const present = classesPresent(out.join(''));
  for (const c of ['lower', 'upper', 'digit', 'symbol']) assert.ok(present.has(c), `missing ${c}`);
});

test('enforceClasses changes at most (number of missing classes) positions', async () => {
  const seed = hexToBytes('77'.repeat(64));
  const chars = 'aaaaaaaaaaaaaaaaaaaa'.split('');
  const out = await enforceClasses(chars, seed, 'standard', CHARSETS.standard);
  let changed = 0;
  for (let i = 0; i < chars.length; i++) if (chars[i] !== out[i]) changed += 1;
  assert.ok(changed <= 3, `changed ${changed} positions, expected <= 3 (upper, digit, symbol)`);
});

test('enforceClasses is deterministic', async () => {
  const seed = hexToBytes('88'.repeat(64));
  const chars = 'aaaaaaaaaaaaaaaaaaaa'.split('');
  const a = await enforceClasses(chars, seed, 'standard', CHARSETS.standard);
  const b = await enforceClasses(chars, seed, 'standard', CHARSETS.standard);
  assert.equal(a.join(''), b.join(''));
});

test('enforceClasses for letters-digits does not require a symbol', async () => {
  const seed = hexToBytes('99'.repeat(64));
  const chars = 'aA1aA1aA1aA1aA1aA1aA'.split('');
  const out = await enforceClasses(chars, seed, 'letters-digits', CHARSETS['letters-digits']);
  assert.equal(out.join(''), chars.join(''));
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/derive.test.mjs`
Expected: FAIL with `enforceClasses is not exported`.

- [ ] **Step 3: Append to `src/derive.js`**

```js
function _classOf(ch) {
  if (/[a-z]/.test(ch)) return 'lower';
  if (/[A-Z]/.test(ch)) return 'upper';
  if (/[0-9]/.test(ch)) return 'digit';
  return 'symbol';
}

export async function enforceClasses(chars, entrySeed, rules, charset) {
  const result = chars.slice();
  const length = result.length;
  const need = requiredClasses(rules);

  const present = new Set();
  for (const ch of result) present.add(_classOf(ch));
  const missing = need.filter((c) => !present.has(c));
  if (missing.length === 0) return result;

  const keystream = makeKeystream(entrySeed, 'fix');
  const used = new Set();
  for (const cls of missing) {
    let pos = await sampleIndex(keystream, length);
    while (used.has(pos)) pos = (pos + 1) % length;
    used.add(pos);
    const pool = classChars(cls, charset);
    result[pos] = pool[await sampleIndex(keystream, pool.length)];
  }
  return result;
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/derive.test.mjs`
Expected: PASS, 22 tests.

- [ ] **Step 5: Commit**

```bash
git add src/derive.js tests/derive.test.mjs
git commit -m "feat: v1 required-class enforcement"
```

---

## Task 10: Master key, KCV, and end-to-end `derivePassword`

**Files:**
- Modify: `src/derive.js`
- Test: `tests/derive.test.mjs` (append)

- [ ] **Step 1: Append failing tests**

```js
import { deriveMasterKey, computeKcv, derivePassword } from '../src/derive.js';

const FIXED_MK = hexToBytes('abababababababababababababababababababababababababababababababab12');

test('deriveMasterKey is PBKDF2-SHA512 over passphrase with normalised identity as salt', async () => {
  const mk = await deriveMasterKey('correct horse battery staple', '  ALEX@example.com ', 1000);
  const { pbkdf2Sha512 } = await import('../src/webcrypto.js');
  const { utf8 } = await import('../src/encoding.js');
  const expected = await pbkdf2Sha512(
    utf8('correct horse battery staple'), utf8('alex@example.com'), 1000, 32,
  );
  assert.equal(bytesToHex(mk), bytesToHex(expected));
});

test('computeKcv returns a 4-byte base64 string, deterministic, key-sensitive', async () => {
  const a = await computeKcv(FIXED_MK);
  const b = await computeKcv(FIXED_MK);
  assert.equal(a, b);
  assert.match(a, /^[A-Za-z0-9+/]{5,8}={0,2}$/);
  const other = await computeKcv(hexToBytes('cd'.repeat(32)));
  assert.notEqual(a, other);
});

test('derivePassword with a fixed masterKey: deterministic, right length, all classes', async () => {
  const params = {
    masterKey: FIXED_MK, site: 'github.com', account: 'alex',
    counter: 1, rules: 'standard', length: 20,
  };
  const p1 = await derivePassword(params);
  const p2 = await derivePassword(params);
  assert.equal(p1, p2);
  assert.equal(p1.length, 20);
  const present = classesPresent(p1);
  for (const c of ['lower', 'upper', 'digit', 'symbol']) assert.ok(present.has(c));
  for (const ch of p1) assert.ok(CHARSETS.standard.includes(ch));
});

test('derivePassword: counter bump changes the password', async () => {
  const base = { masterKey: FIXED_MK, site: 'x', account: 'y', counter: 1, rules: 'standard', length: 16 };
  assert.notEqual(await derivePassword(base), await derivePassword({ ...base, counter: 2 }));
});

test('derivePassword: validates length and counter', async () => {
  await assert.rejects(() => derivePassword({ masterKey: FIXED_MK, site: 'x', account: 'y', length: 7 }));
  await assert.rejects(() => derivePassword({ masterKey: FIXED_MK, site: 'x', account: 'y', length: 65 }));
  await assert.rejects(() => derivePassword({ masterKey: FIXED_MK, site: 'x', account: 'y', counter: 0 }));
  await assert.rejects(() => derivePassword({ masterKey: FIXED_MK, site: 'x', account: 'y', rules: 'nope' }));
});

test('derivePassword: normalises site and account before deriving', async () => {
  const a = await derivePassword({ masterKey: FIXED_MK, site: 'GitHub.com', account: 'Alex', length: 16 });
  const b = await derivePassword({ masterKey: FIXED_MK, site: 'github.com', account: 'alex', length: 16 });
  assert.equal(a, b);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/derive.test.mjs`
Expected: FAIL with `deriveMasterKey is not exported`.

- [ ] **Step 3: Append to `src/derive.js`**

```js
export async function deriveMasterKey(passphrase, identity, iterations = PBKDF2_ITERATIONS) {
  return pbkdf2Sha512(
    utf8(passphrase), utf8(normaliseInput(identity)), iterations, MASTER_KEY_BYTES,
  );
}

export async function computeKcv(masterKey) {
  const mac = await hmacSha256(masterKey, utf8('kunji/kcv/v1'));
  return bytesToBase64(mac.slice(0, 4));
}

export async function derivePassword(params) {
  const site = normaliseInput(params.site ?? '');
  const account = normaliseInput(params.account ?? '');
  const counter = params.counter ?? 1;
  const rules = params.rules ?? DEFAULT_RULES;
  const length = params.length ?? DEFAULT_LENGTH;

  if (!Number.isInteger(counter) || counter < 1) {
    throw new Error('counter must be an integer >= 1');
  }
  if (!Number.isInteger(length) || length < MIN_LENGTH || length > MAX_LENGTH) {
    throw new Error(`length must be an integer in ${MIN_LENGTH}..${MAX_LENGTH}`);
  }
  const charset = CHARSETS[rules];
  if (!charset) throw new Error(`unknown rules: ${rules}`);

  const masterKey = params.masterKey
    ? params.masterKey
    : await deriveMasterKey(
        params.passphrase,
        normaliseInput(params.identity ?? ''),
        params.iterations ?? PBKDF2_ITERATIONS,
      );

  const entrySeed = await deriveEntrySeed(masterKey, { site, account, counter, rules, length });
  const raw = await generateChars(entrySeed, charset, length);
  const fixed = await enforceClasses(raw, entrySeed, rules, charset);
  return fixed.join('');
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/derive.test.mjs`
Expected: PASS, 28 tests.

- [ ] **Step 5: Commit**

```bash
git add src/derive.js tests/derive.test.mjs
git commit -m "feat: v1 master key, kcv, and end-to-end derivePassword"
```

---

## Task 11: Freeze the v1 vectors

**Files:**
- Create: `tools/gen-vectors.mjs`
- Create: `tests/vectors/v1.json` (generated, then committed)
- Create: `tests/vectors.test.mjs`

- [ ] **Step 1: Write `tools/gen-vectors.mjs`**

```js
import { writeFileSync, mkdirSync } from 'node:fs';
import { derivePassword, deriveMasterKey, computeKcv, PROFILE } from '../src/derive.js';
import { bytesToHex } from '../src/encoding.js';

// End-to-end cases use a small iteration count for speed. The shipping cost
// (PBKDF2_ITERATIONS) is a separate open decision and does not affect the
// pipeline shape that these vectors lock.
const ITER = 1000;

const cases = [
  { identity: 'alex@example.com', passphrase: 'correct horse battery staple',
    site: 'github.com', account: 'alex', counter: 1, rules: 'standard', length: 20 },
  { identity: 'alex@example.com', passphrase: 'correct horse battery staple',
    site: 'github.com', account: 'alex', counter: 2, rules: 'standard', length: 20 },
  { identity: 'family', passphrase: 'a long enough passphrase here',
    site: 'google.com', account: 'family@example.com', counter: 1, rules: 'max-symbols', length: 32 },
  { identity: 'family', passphrase: 'a long enough passphrase here',
    site: 'router.local', account: 'admin', counter: 1, rules: 'letters-digits', length: 12 },
  { identity: 'x', passphrase: 'y', site: 's', account: 'a', counter: 1, rules: 'standard', length: 8 },
  { identity: 'x', passphrase: 'y', site: 's', account: 'a', counter: 1, rules: 'standard', length: 64 },
];

const out = { profile: PROFILE, iterations: ITER, cases: [] };
for (const c of cases) {
  const mk = await deriveMasterKey(c.passphrase, c.identity, ITER);
  out.cases.push({
    input: c,
    masterKeyHex: bytesToHex(mk),
    kcv: await computeKcv(mk),
    password: await derivePassword({ ...c, iterations: ITER }),
  });
}

mkdirSync('tests/vectors', { recursive: true });
writeFileSync('tests/vectors/v1.json', JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${out.cases.length} vectors`);
```

- [ ] **Step 2: Generate, then verify determinism**

Run: `node tools/gen-vectors.mjs`
Then run it a second time: `node tools/gen-vectors.mjs`
Run: `git diff --stat tests/vectors/v1.json`
Expected: no diff between the two runs (byte-identical). If there is a diff, the pipeline is non-deterministic and must be fixed before continuing.

- [ ] **Step 3: Write `tests/vectors.test.mjs`**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { derivePassword, deriveMasterKey, computeKcv, PROFILE } from '../src/derive.js';
import { bytesToHex } from '../src/encoding.js';

const vectors = JSON.parse(readFileSync('tests/vectors/v1.json', 'utf8'));

test('committed vectors are for the current profile', () => {
  assert.equal(vectors.profile, PROFILE);
});

for (const [i, v] of vectors.cases.entries()) {
  test(`v1 vector ${i} still reproduces (${v.input.site} #${v.input.counter} ${v.input.rules}/${v.input.length})`, async () => {
    const mk = await deriveMasterKey(v.input.passphrase, v.input.identity, vectors.iterations);
    assert.equal(bytesToHex(mk), v.masterKeyHex, 'master key drifted');
    assert.equal(await computeKcv(mk), v.kcv, 'kcv drifted');
    assert.equal(
      await derivePassword({ ...v.input, iterations: vectors.iterations }),
      v.password,
      'PASSWORD DRIFTED: a v1 profile change would break every existing password',
    );
  });
}
```

- [ ] **Step 4: Run the vector lock test**

Run: `node --test tests/vectors.test.mjs`
Expected: PASS, 7 tests.

- [ ] **Step 5: Commit the freeze**

```bash
git add tools/gen-vectors.mjs tests/vectors/v1.json tests/vectors.test.mjs
git commit -m "test: freeze v1 profile with committed vectors"
```

---

## Task 12: UI pure helpers

**Files:**
- Modify: `src/app.js`
- Test: `tests/app.test.mjs`

- [ ] **Step 1: Write the failing tests**

Create `tests/app.test.mjs`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { estimateEntropyBits, groupInFours } from '../src/app.js';

test('estimateEntropyBits = floor(length * log2(charsetSize))', () => {
  assert.equal(estimateEntropyBits(20, 72), Math.floor(20 * Math.log2(72)));
  assert.equal(estimateEntropyBits(16, 62), 95); // 16 * 5.954... = 95.27 -> 95
  assert.equal(estimateEntropyBits(0, 72), 0);
});

test('groupInFours inserts a space every 4 chars, no trailing space', () => {
  assert.equal(groupInFours('abcdefghij'), 'abcd efgh ij');
  assert.equal(groupInFours('abcd'), 'abcd');
  assert.equal(groupInFours(''), '');
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/app.test.mjs`
Expected: FAIL with `estimateEntropyBits is not exported` (the stub `src/app.js` has none).

- [ ] **Step 3: Replace `src/app.js` with the helpers plus a DOM guard**

```js
export function estimateEntropyBits(length, charsetSize) {
  if (length <= 0) return 0;
  return Math.floor(length * Math.log2(charsetSize));
}

export function groupInFours(str) {
  return str.replace(/(.{4})/g, '$1 ').trim();
}

// DOM wiring is added in Task 14. Guard so this module is import-safe in Node.
if (typeof document !== 'undefined') {
  // initUI() is defined in Task 14 and called here.
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/app.test.mjs`
Expected: PASS, 2 tests.

- [ ] **Step 5: Full test run and build**

Run: `node --test` then `node tools/build.mjs` then `node tools/check-invariants.mjs`
Expected: all tests pass; build writes `dist/kunji.html`; invariants ok.

- [ ] **Step 6: Commit**

```bash
git add src/app.js tests/app.test.mjs
git commit -m "feat: ui pure helpers (entropy estimate, grouping)"
```

---

## Task 13: X.com-style stylesheet

**Files:**
- Modify: `src/style.css`
- Reference: `scratchpad/kunji-mockup.html`, and the approved mockup screenshot

- [ ] **Step 1: Write `src/style.css`**

Ported from the mockup, with muted text raised to `#8B98A5` for AA contrast and a `--fs-base` hook for a later larger-text pass.

```css
:root {
  --bg: #000000;
  --surface: #16181C;
  --border: #2F3336;
  --border-strong: #536471;
  --text: #E7E9EA;
  --muted: #8B98A5;
  --blue: #1D9BF0;
  --green: #00BA7C;
  --white: #FFFFFF;
  --fs-base: 15px;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body { height: 100%; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  font-size: var(--fs-base);
  -webkit-font-smoothing: antialiased;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
}
.card {
  width: min(400px, 100%);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 32px;
}
header { margin-bottom: 28px; }
.title { font-size: 23px; font-weight: 800; letter-spacing: -0.01em; }
.subtitle { font-size: 13px; color: var(--muted); margin-top: 4px; }
.fields { display: flex; flex-direction: column; gap: 16px; }
.field { position: relative; }
.field input, .field select {
  width: 100%;
  font: inherit;
  color: var(--text);
  background: transparent;
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 22px 12px 8px;
  appearance: none;
  outline: none;
}
.field input:focus, .field select:focus { border-color: var(--blue); }
.field label {
  position: absolute;
  left: 13px;
  top: 15px;
  font-size: var(--fs-base);
  color: var(--muted);
  pointer-events: none;
  transition: top .12s ease, font-size .12s ease, color .12s ease;
}
.field input:focus + label,
.field input:not(:placeholder-shown) + label,
.field.filled label { top: 7px; font-size: 12px; }
.field input:focus + label { color: var(--blue); }
.reveal {
  position: absolute;
  right: 12px;
  top: 50%;
  transform: translateY(-50%);
  background: none;
  border: none;
  color: var(--blue);
  font: 600 13px inherit;
  cursor: pointer;
  min-height: 44px;
  padding: 0 4px;
}
.kcv { display: flex; align-items: center; gap: 6px; margin-top: 8px; font-size: 12px; color: var(--muted); }
.kcv .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--border-strong); }
.kcv[data-state="ok"] .dot { background: var(--green); }
.kcv[data-state="bad"] .dot { background: #F4212E; }
.row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.select-wrap::after {
  content: "";
  position: absolute;
  right: 14px;
  top: 22px;
  width: 7px;
  height: 7px;
  border-right: 2px solid var(--muted);
  border-bottom: 2px solid var(--muted);
  transform: rotate(45deg);
  pointer-events: none;
}
select option { background: var(--surface); color: var(--text); }
.divider { height: 1px; background: var(--border); margin: 24px 0; }
.result-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
.result-head .label { font-size: 13px; color: var(--muted); }
.copy-btn {
  background: none; border: none; color: var(--blue);
  font: 600 13px inherit; cursor: pointer; min-height: 44px; padding: 0 4px;
}
.result-value {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 19px;
  letter-spacing: 1px;
  line-height: 1.5;
  word-break: break-all;
  min-height: 1.5em;
  color: var(--text);
}
.result-value.empty { color: var(--muted); }
.entropy { font-size: 13px; color: var(--muted); margin-top: 10px; min-height: 1em; }
.btn-primary {
  width: 100%;
  margin-top: 24px;
  padding: 13px;
  border: none;
  border-radius: 9999px;
  background: var(--white);
  color: #0F1419;
  font: 700 var(--fs-base) inherit;
  cursor: pointer;
  min-height: 44px;
}
.btn-primary:hover { background: #E6E6E6; }
.btn-primary:disabled { opacity: .5; cursor: default; }
.foot { margin-top: 18px; text-align: center; font-size: 12px; color: var(--muted); }
.error { color: #F4212E; font-size: 13px; margin-top: 12px; min-height: 1em; }
```

- [ ] **Step 2: Build and eyeball against the mockup**

Run: `node tools/build.mjs`
Open `dist/kunji.html` in a browser (it still shows the Task 1 stub body; layout classes are exercised in Task 14). Confirm no console errors and the page is black. Full visual comparison happens at the end of Task 14.

- [ ] **Step 3: Commit**

```bash
git add src/style.css
git commit -m "feat: x.com-style stylesheet with AA contrast fix"
```

---

## Task 14: Markup and DOM wiring

**Files:**
- Modify: `src/head.html`
- Modify: `src/tail.html`
- Modify: `src/app.js` (append `initUI` and call it)
- Manual test: `dist/kunji.html` in a browser

- [ ] **Step 1: Replace `src/head.html`**

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'">
<title>Kunji</title>
<style>/*STYLE*/</style>
</head>
<body>
<main class="card">
  <header>
    <div class="title">Kunji</div>
    <div class="subtitle">Offline. Nothing is stored or sent.</div>
  </header>

  <div class="fields">
    <div>
      <div class="field">
        <input id="identity" type="text" autocomplete="off" spellcheck="false" placeholder=" ">
        <label for="identity">Identity</label>
      </div>
    </div>

    <div>
      <div class="field">
        <input id="master" type="password" autocomplete="off" spellcheck="false" placeholder=" ">
        <label for="master">Master passphrase</label>
        <button class="reveal" type="button" id="toggleMaster">Show</button>
      </div>
      <div class="kcv" id="kcv" data-state="none"><span class="dot"></span> <span id="kcvText">enter identity and passphrase</span></div>
    </div>

    <div class="field">
      <input id="site" type="text" autocomplete="off" spellcheck="false" placeholder=" ">
      <label for="site">Site or app</label>
    </div>

    <div class="field">
      <input id="account" type="text" autocomplete="off" spellcheck="false" placeholder=" ">
      <label for="account">Account</label>
    </div>

    <div class="row">
      <div class="field">
        <input id="length" type="text" inputmode="numeric" value="20" placeholder=" ">
        <label for="length">Length</label>
      </div>
      <div class="field select-wrap">
        <select id="rules">
          <option value="standard">Standard</option>
          <option value="letters-digits">Letters and digits</option>
          <option value="max-symbols">Maximum symbols</option>
        </select>
        <label for="rules">Rules</label>
      </div>
    </div>
  </div>

  <div class="divider"></div>

  <div class="result">
    <div class="result-head">
      <span class="label" id="resultLabel">Password</span>
      <button class="copy-btn" type="button" id="copyBtn">Copy</button>
    </div>
    <div class="result-value empty" id="output">not generated</div>
    <div class="entropy" id="entropy"></div>
    <div class="error" id="error"></div>
  </div>

  <button class="btn-primary" type="button" id="generateBtn">Generate</button>

  <div class="foot">Clipboard clears after 25 seconds. Passphrase is cleared after you generate.</div>
</main>
```

- [ ] **Step 2: Replace `src/tail.html`**

```html
<script>/*SCRIPT*/</script>
</body>
</html>
```

- [ ] **Step 3: Append `initUI` to `src/app.js` and wire the guard**

Replace the guard block at the bottom of `src/app.js` with:

```js
async function _revealFor(el, seconds, timerBox) {
  el.dataset.revealed = '1';
  if (timerBox.t) clearTimeout(timerBox.t);
  timerBox.t = setTimeout(() => { el.dataset.revealed = '0'; el.textContent = el.dataset.masked || ''; }, seconds * 1000);
}

function initUI() {
  const $ = (id) => document.getElementById(id);
  const identity = $('identity');
  const master = $('master');
  const site = $('site');
  const account = $('account');
  const lengthEl = $('length');
  const rulesEl = $('rules');
  const kcv = $('kcv');
  const kcvText = $('kcvText');
  const output = $('output');
  const entropyEl = $('entropy');
  const errorEl = $('error');
  const resultLabel = $('resultLabel');
  const generateBtn = $('generateBtn');
  const copyBtn = $('copyBtn');
  const toggleMaster = $('toggleMaster');

  const REVEAL_SECONDS = 20;
  const CLIPBOARD_SECONDS = 25;
  const revealTimer = {};
  let clipboardTimer = null;
  let plaintext = '';

  toggleMaster.addEventListener('click', () => {
    const showing = master.type === 'text';
    master.type = showing ? 'password' : 'text';
    toggleMaster.textContent = showing ? 'Show' : 'Hide';
  });

  async function refreshKcv() {
    const id = identity.value.trim();
    const pw = master.value;
    if (!id || !pw) { kcv.dataset.state = 'none'; kcvText.textContent = 'enter identity and passphrase'; return; }
    kcv.dataset.state = 'none';
    kcvText.textContent = 'checking...';
    try {
      const mk = await deriveMasterKey(pw, id);
      const value = await computeKcv(mk);
      kcv.dataset.state = 'ok';
      kcvText.textContent = 'key verified (' + value + ')';
    } catch (e) {
      kcv.dataset.state = 'bad';
      kcvText.textContent = 'could not derive key';
    }
  }
  identity.addEventListener('change', refreshKcv);
  master.addEventListener('change', refreshKcv);

  async function generate() {
    errorEl.textContent = '';
    const length = parseInt(lengthEl.value, 10);
    const rules = rulesEl.value;
    if (!identity.value.trim() || !master.value || !site.value.trim() || !account.value.trim()) {
      errorEl.textContent = 'Identity, passphrase, site, and account are all required.';
      return;
    }
    generateBtn.disabled = true;
    generateBtn.textContent = 'Generating...';
    try {
      plaintext = await derivePassword({
        identity: identity.value,
        passphrase: master.value,
        site: site.value,
        account: account.value,
        counter: 1,
        rules,
        length,
      });
      const masked = '•'.repeat(plaintext.length);
      output.dataset.masked = groupInFours(masked);
      output.dataset.plain = groupInFours(plaintext);
      output.dataset.revealed = '0';
      output.classList.remove('empty');
      output.textContent = output.dataset.masked;
      resultLabel.textContent = 'Password for ' + site.value.trim().toLowerCase();
      const size = ({ 'standard': 72, 'letters-digits': 62, 'max-symbols': 83 })[rules];
      entropyEl.textContent = estimateEntropyBits(length, size) + ' bits of entropy. Unique to this site and counter 1.';
      master.value = '';
      master.type = 'password';
      toggleMaster.textContent = 'Show';
      kcv.dataset.state = 'none';
      kcvText.textContent = 'passphrase cleared';
    } catch (e) {
      errorEl.textContent = e.message;
    } finally {
      generateBtn.disabled = false;
      generateBtn.textContent = 'Generate';
    }
  }
  generateBtn.addEventListener('click', generate);

  output.addEventListener('click', () => {
    if (output.classList.contains('empty') || !output.dataset.plain) return;
    if (output.dataset.revealed === '1') {
      output.dataset.revealed = '0';
      output.textContent = output.dataset.masked;
    } else {
      output.dataset.revealed = '1';
      output.textContent = output.dataset.plain;
      if (revealTimer.t) clearTimeout(revealTimer.t);
      revealTimer.t = setTimeout(() => {
        output.dataset.revealed = '0';
        output.textContent = output.dataset.masked || '';
      }, REVEAL_SECONDS * 1000);
    }
  });

  copyBtn.addEventListener('click', async () => {
    if (!plaintext) return;
    try {
      await navigator.clipboard.writeText(plaintext);
    } catch (e) {
      const ta = document.createElement('textarea');
      ta.value = plaintext;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch (_) {}
      document.body.removeChild(ta);
    }
    copyBtn.textContent = 'Copied';
    setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
    if (clipboardTimer) clearTimeout(clipboardTimer);
    clipboardTimer = setTimeout(async () => {
      try { await navigator.clipboard.writeText(''); } catch (_) {}
    }, CLIPBOARD_SECONDS * 1000);
  });
}

if (typeof document !== 'undefined') {
  initUI();
}
```

Note: `initUI` references `deriveMasterKey`, `computeKcv`, `derivePassword` (from `derive.js`) and `estimateEntropyBits`, `groupInFours` (defined above in this file). After the build strips module syntax and concatenates in `JS_ORDER`, all are in scope in `dist/kunji.html`. For dev serving of raw `src/` files this file would need an `import`; that path is out of scope for Phase 1, which ships only the built file.

- [ ] **Step 4: Build**

Run: `node tools/build.mjs && node tools/check-invariants.mjs`
Expected: build writes `dist/kunji.html`; invariants ok.

- [ ] **Step 5: Manual browser test**

Open `dist/kunji.html` directly (double-click, `file://`) in Chrome, and separately in Safari. Run this checklist:

- [ ] Page is pure black, single centred card, matches `scratchpad/kunji-mockup.html` layout.
- [ ] No entries in the browser console. No network requests in the Network tab (reload with it open).
- [ ] Type an identity, then a passphrase, then click elsewhere: KCV row shows "checking..." then a green dot and "key verified (XXXX)".
- [ ] Fill site `github.com`, account `alex`, length `20`, rules `Standard`. Click Generate.
- [ ] Output shows 20 masked dots grouped in fours; entropy line reads a bits figure; label becomes "Password for github.com".
- [ ] The passphrase field is now empty and the KCV row says "passphrase cleared".
- [ ] Click the output: it reveals the real password (mono, grouped). Click again: re-masks. Wait 20s after a reveal: it re-masks on its own.
- [ ] Click Copy: button flashes "Copied"; paste into a text editor and confirm it matches the revealed value.
- [ ] Re-enter the same identity + passphrase, generate again with the same site/account/length/rules: identical password (determinism).
- [ ] Change length to `7`: Generate shows the error "length must be an integer in 8..64" and no output change.
- [ ] On a phone (open the file via a local share or host it on `python3 -m http.server` on your machine and browse from the phone): the card is full width with 44px tap targets, inputs do not zoom the viewport awkwardly.

- [ ] **Step 6: Commit**

```bash
git add src/head.html src/tail.html src/app.js
git commit -m "feat: kunji v1 UI markup and DOM wiring"
```

---

## Task 15: Deliverable wrap-up

**Files:**
- Create: `README.md`
- Modify: `package.json` (add a `dist` convenience script)

- [ ] **Step 1: Add a combined script to `package.json`**

Change the `scripts` block to:

```json
  "scripts": {
    "test": "node --test",
    "build": "node tools/build.mjs",
    "check": "node tools/check-invariants.mjs",
    "verify": "node --test && node tools/build.mjs && node tools/check-invariants.mjs"
  }
```

- [ ] **Step 2: Run the full verification**

Run: `npm run verify`
Expected: all test files pass (sanity 2, encoding 7, webcrypto 4, build 2, derive 28, vectors 7, app 2), `dist/kunji.html` is written, invariants ok.

- [ ] **Step 3: Write `README.md`**

```markdown
# Kunji

Offline, in-house password tool. One memorised master passphrase plus a site and
account name produce a unique strong password, recomputed on demand. Nothing is
stored or sent. See `docs/specs/2026-09-01-kunji-design.md` for the design and
`docs/plans/` for implementation plans.

## Status

Phase 1: deterministic v1 derivation and the UI, shipped as a single file. No
saved vault yet (Phase 2).

## Build

    node tools/build.mjs

Produces `dist/kunji.html`, a single self-contained file. Open it directly in any
modern browser (Chrome, Safari, Firefox, Edge) on any OS, or add it to your home
screen. It makes no network requests.

## Test

    npm test          # unit tests
    npm run check     # no-network invariant scan
    npm run verify    # both, plus a build

## The v1 profile is frozen

`tests/vectors/v1.json` locks the derivation output. Any code change that alters a
generated password fails `tests/vectors.test.mjs`. Improvements ship as a new
profile id, never by changing v1.

## Crypto

Standard primitives via the platform `crypto.subtle` (PBKDF2-SHA512, HKDF-SHA256,
HMAC-SHA256). No third-party libraries, no build step beyond file concatenation.
```

- [ ] **Step 4: Final build and invariant check on the committed tree**

Run: `npm run verify`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add README.md package.json
git commit -m "docs: readme and verify script for kunji v1 core"
```

---

## Self-review

**Spec coverage (spec section in parentheses):**

- v1 input normalisation NFKC/trim/lowercase (4.1) - Task 5.
- counter/length bounds and defaults (4.2) - Task 5 constants, Task 10 validation.
- exact charset strings and required classes (4.3) - Task 5.
- derivation pipeline steps 1-6 (4.4): master key - Task 10; entry seed - Task 7; keystream - Task 6; rejection sampling - Task 6/8; class fix - Task 9; output - Task 10.
- KCV (4.5) - Task 10.
- vault encryption (4.6), decoy (4.7), data model (5), sync (7.3), recovery flows (6) - **deferred to the Phase 2 and Phase 3 plans by design** (see scope note). Phase 1 has no persistence.
- distribution single file + CSP + no-network invariant + reproducible build (7.2, 7.4) - Tasks 4, 14, 15. Signed tags and release checksums are Phase 4.
- versioning: per-profile freeze, immutable v1 (8) - Task 11.
- crypto policy: Web Crypto only, no libraries, Argon2id deferred to v2 (9) - Tasks 3, 10; `PBKDF2_ITERATIONS` constant carries the spec s13 open decision.
- UI spec: palette, type, layout, hygiene, a11y, offline (10) - Tasks 12, 13, 14. Service worker / installable PWA is Phase 3; Phase 1 ships the openable file.
- platform support matrix (11) - Task 14 manual checklist covers Chrome/Safari/desktop/phone.

**Placeholder scan:** No "TBD"/"TODO"/"handle edge cases" in steps. `src/style.css` and `src/app.js` are created as explicit stubs in Task 1 with a one-line comment pointing at the task that fills them; both are fully written later (Tasks 12-14). `dist/` files are generated, not authored.

**Type/name consistency:** `deriveMasterKey`, `computeKcv`, `derivePassword`, `deriveEntrySeed`, `generateChars`, `enforceClasses`, `makeKeystream`, `sampleIndex`, `normaliseInput`, `requiredClasses`, `classChars`, `estimateEntropyBits`, `groupInFours` are named identically in every task that references them. `makeKeystream(seed, label)` label values are the string literals `'gen'` and `'fix'` throughout. Info string `gen|site|account|counter|rules|length` is identical in Task 7 code, Task 7 test, and the spec. `CHARSETS` keys (`standard`, `letters-digits`, `max-symbols`) are consistent across Tasks 5, 10, 14. KCV domain strings `kunji/v1`, `kunji/kcv/v1` match the spec.

**Scope:** Phase 1 only, produces a working testable single file. Phases 2-4 are separate plans.
