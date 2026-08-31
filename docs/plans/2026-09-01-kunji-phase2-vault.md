# Kunji Phase 2 — Vault Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional encrypted `kunji-data.json` vault — a `Vault` tab beside the untouched Phase 1 `Generate` tab — that stores password entries, SSO pointers, notes, TOTP secrets and 2FA recovery codes, encrypted with a key derived from the same master passphrase.

**Architecture:** Two new source files. `src/vault.js` is pure, no-DOM domain logic (envelope encode/decode, AES-256-GCM via `crypto.subtle`, in-memory vault model, entry CRUD) — unit-tested in Node exactly like `derive.js`. `src/vault-ui.js` owns the Vault tab: file open/save (manual download model), the six view states, and a 5-minute idle auto-lock. `src/app.js` is refactored into a tab shell plus the Phase 1 generator, whose behaviour and DOM ids are preserved byte-for-byte. The build stays a plain concatenation into one `dist/kunji.html`.

**Tech Stack:** Node.js >= 20 (`node:test`, `globalThis.crypto`), browser Web Crypto (`crypto.subtle` AES-256-GCM, HKDF), plain HTML/CSS/JS, zero dependencies.

**Scope note:** This plan covers spec Phase 2 only — `docs/specs/2026-09-01-kunji-phase2-vault-design.md`. Decoy *authoring* (Phase 3), the Generate-tab account picker (Phase 3), QR / sync-merge / PWA (Phase 3), signed releases (Phase 4), and Argon2id / WebAuthn / live TOTP (Phase 5) are out of scope. The `decoy` envelope section IS written (random bytes) so files stay indistinguishable.

**Spec:** `docs/specs/2026-09-01-kunji-phase2-vault-design.md`. The parent spec `docs/specs/2026-09-01-kunji-design.md` sections 4.6, 4.7, 5 are the frozen source of truth for the crypto and data model.

**Baseline:** Phase 1 is complete on `main` (commit `e2fab66` or later). `npm run verify` passes with 53 tests. Work from `the repository root`, directly on `main`, one commit per task, commit-message trailers:

```
Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01E2FKUJXdFejXkG1iuXB83A
```

Use `git -c commit.gpgsign=false commit` if signing prompts or fails.

---

## File structure

| File | Change | Responsibility |
|---|---|---|
| `src/webcrypto.js` | add `aesGcmEncrypt`, `aesGcmDecrypt` | thin `crypto.subtle` wrappers, no app logic |
| `src/derive.js` | add `deriveVaultKey` | one HKDF; a frozen v1 detail |
| `src/vault.js` | **new** | typed errors, envelope constants, `randomBytes`, `newDecoyBytes`, `createVault`, `makeEntry`/`addEntry`/`updateEntry`/`removeEntry`, `encodeEnvelope`, `parseEnvelope`, `unlockVault` |
| `src/app.js` | refactor | `initGenerateTab` (the old `initUI` body, unchanged logic) + `initApp` (tab switching); bottom bootstrap calls `initApp()` then `initVaultTab()` |
| `src/vault-ui.js` | **new** | Vault tab only: state machine, file open (`<input type=file>`), save (Blob download), the six views, idle timer, dirty bar, `beforeunload` |
| `src/head.html` | edit | tab strip + `#tab-generate` wrapper + empty `#tab-vault` container |
| `src/style.css` | edit | tab strip, list rows, detail sections, editor fields, unsaved-changes bar — reuse the Phase 1 palette and `.kcv` component |
| `tools/build.mjs` | edit | extend `JS_ORDER` to include `vault.js` (before `app.js`) and `vault-ui.js` (last) |
| `tools/check-invariants.mjs` | none | already scans all of `src/` and `dist/` |
| `tests/webcrypto.test.mjs` | extend | AES-256-GCM against McGrew GCM Test Case 14; round-trip; tamper + wrong-AAD reject |
| `tests/derive.test.mjs` | extend | `deriveVaultKey` exact HKDF params + frozen fixed-input vector |
| `tests/vault.test.mjs` | **new** | round-trip, wrong passphrase, frozen decrypt vector, decoy presence, entry CRUD, typed errors |
| `tests/build.test.mjs` | extend | built HTML contains the vault module markers |
| `README.md` | edit | mention the vault, Phase 2 status |
| `docs/specs/2026-09-01-kunji-design.md` | edit | section 12 wording: decoy is "envelope only" in Phase 2 |

---

## Task 1: AES-256-GCM wrappers

**Files:**
- Modify: `src/webcrypto.js`
- Test: `tests/webcrypto.test.mjs` (append)

- [ ] **Step 1: Append the failing tests**

Add to `tests/webcrypto.test.mjs`:

```js
import { aesGcmEncrypt, aesGcmDecrypt } from '../src/webcrypto.js';

test('AES-256-GCM matches McGrew GCM test case 14', async () => {
  const key = hexToBytes('00'.repeat(32));
  const iv = hexToBytes('00'.repeat(12));
  const pt = hexToBytes('00'.repeat(16));
  const out = await aesGcmEncrypt(key, iv, pt, new Uint8Array(0));
  // Web Crypto returns ciphertext || 16-byte tag.
  assert.equal(
    bytesToHex(out),
    'cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919',
  );
});

test('AES-256-GCM round-trips with AAD', async () => {
  const key = hexToBytes('11'.repeat(32));
  const iv = hexToBytes('22'.repeat(12));
  const aad = utf8('kunji-vault-v1');
  const msg = utf8('{"entries":[],"settings":{}}');
  const ct = await aesGcmEncrypt(key, iv, msg, aad);
  const back = await aesGcmDecrypt(key, iv, ct, aad);
  assert.equal(bytesToHex(back), bytesToHex(msg));
});

test('AES-256-GCM rejects a tampered ciphertext', async () => {
  const key = hexToBytes('33'.repeat(32));
  const iv = hexToBytes('44'.repeat(12));
  const ct = await aesGcmEncrypt(key, iv, utf8('hello'), new Uint8Array(0));
  ct[0] ^= 0x01;
  await assert.rejects(() => aesGcmDecrypt(key, iv, ct, new Uint8Array(0)));
});

test('AES-256-GCM rejects a wrong AAD', async () => {
  const key = hexToBytes('55'.repeat(32));
  const iv = hexToBytes('66'.repeat(12));
  const ct = await aesGcmEncrypt(key, iv, utf8('hello'), utf8('aad-one'));
  await assert.rejects(() => aesGcmDecrypt(key, iv, ct, utf8('aad-two')));
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/webcrypto.test.mjs`
Expected: FAIL — `aesGcmEncrypt` / `aesGcmDecrypt` not exported.

- [ ] **Step 3: Append to `src/webcrypto.js`**

```js
export async function aesGcmEncrypt(keyBytes, ivBytes, plaintextBytes, aadBytes) {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt'],
  );
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: ivBytes, additionalData: aadBytes, tagLength: 128 },
    key, plaintextBytes,
  );
  return new Uint8Array(ct);
}

export async function aesGcmDecrypt(keyBytes, ivBytes, ciphertextBytes, aadBytes) {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt'],
  );
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBytes, additionalData: aadBytes, tagLength: 128 },
    key, ciphertextBytes,
  );
  return new Uint8Array(pt);
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/webcrypto.test.mjs`
Expected: PASS. Then `node --test` for the full suite: expect 57 tests (53 prior + 4), all green. Then `node tools/build.mjs && node tools/check-invariants.mjs` — both green.

- [ ] **Step 5: Commit**

```bash
git add src/webcrypto.js tests/webcrypto.test.mjs
git commit -m "feat: aes-256-gcm wrappers"
```

---

## Task 2: `deriveVaultKey`

**Files:**
- Modify: `src/derive.js`
- Test: `tests/derive.test.mjs` (append)

- [ ] **Step 1: Append the failing tests**

Add to `tests/derive.test.mjs`. `hexToBytes`, `bytesToHex`, `FIXED_MK` are already imported/defined in this file from Phase 1.

```js
import { deriveVaultKey } from '../src/derive.js';

test('deriveVaultKey is HKDF-SHA256(masterKey, "kunji/v1", "vault-key", 32)', async () => {
  const fromApi = await deriveVaultKey(FIXED_MK);
  const { hkdfSha256 } = await import('../src/webcrypto.js');
  const { utf8 } = await import('../src/encoding.js');
  const manual = await hkdfSha256(FIXED_MK, utf8('kunji/v1'), utf8('vault-key'), 32);
  assert.equal(bytesToHex(fromApi), bytesToHex(manual));
  assert.equal(fromApi.length, 32);
});

test('deriveVaultKey is deterministic and differs from the master key', async () => {
  const a = await deriveVaultKey(FIXED_MK);
  const b = await deriveVaultKey(FIXED_MK);
  assert.equal(bytesToHex(a), bytesToHex(b));
  assert.notEqual(bytesToHex(a), bytesToHex(FIXED_MK));
});

test('deriveVaultKey frozen vector', async () => {
  // Frozen v1 value. If this changes, every existing vault file stops decrypting.
  const vk = await deriveVaultKey(FIXED_MK);
  assert.equal(bytesToHex(vk), '__FILL_IN_STEP_4__');
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/derive.test.mjs`
Expected: FAIL — `deriveVaultKey` not exported.

- [ ] **Step 3: Append to `src/derive.js`** (after `deriveEntrySeed`)

```js
export async function deriveVaultKey(masterKey) {
  return hkdfSha256(masterKey, utf8('kunji/v1'), utf8('vault-key'), 32);
}
```

- [ ] **Step 4: Freeze the vector**

Run this one-liner and copy the hex it prints into the `__FILL_IN_STEP_4__` placeholder in the test from Step 1:

```bash
node -e "import('./src/derive.js').then(async m => { const { hexToBytes, bytesToHex } = await import('./src/encoding.js'); const mk = hexToBytes('ab'.repeat(31)+'12'); console.log(bytesToHex(await m.deriveVaultKey(mk))); })"
```

Run it a second time and confirm it prints the identical value (determinism).

- [ ] **Step 5: Run to verify it passes**

Run: `node --test tests/derive.test.mjs`
Expected: PASS. Full `node --test`: expect 60 tests, all green. `node tools/build.mjs && node tools/check-invariants.mjs` green.

- [ ] **Step 6: Commit**

```bash
git add src/derive.js tests/derive.test.mjs
git commit -m "feat: v1 vault key derivation (hkdf)"
```

---

## Task 3: `vault.js` — errors, constants, random helpers, decoy bytes

**Files:**
- Create: `src/vault.js`
- Test: `tests/vault.test.mjs`

- [ ] **Step 1: Write the failing tests**

Create `tests/vault.test.mjs`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  BadEnvelopeError, WrongPassphraseError, CorruptVaultError,
  VAULT_FORMAT, VAULT_V, VAULT_AAD,
  randomBytes, newDecoyBytes,
} from '../src/vault.js';
import { base64ToBytes, fromUtf8 } from '../src/encoding.js';

test('typed errors have distinct names and are Error subclasses', () => {
  for (const E of [BadEnvelopeError, WrongPassphraseError, CorruptVaultError]) {
    const e = new E('x');
    assert.ok(e instanceof Error);
    assert.equal(e.message, 'x');
  }
  assert.equal(new BadEnvelopeError().name, 'BadEnvelopeError');
  assert.equal(new WrongPassphraseError().name, 'WrongPassphraseError');
  assert.equal(new CorruptVaultError().name, 'CorruptVaultError');
});

test('envelope constants are the frozen values', () => {
  assert.equal(VAULT_FORMAT, 'kunji-data');
  assert.equal(VAULT_V, 1);
  assert.equal(fromUtf8(VAULT_AAD), 'kunji-vault-v1');
});

test('randomBytes returns n fresh bytes', () => {
  const a = randomBytes(16);
  const b = randomBytes(16);
  assert.equal(a.length, 16);
  assert.notEqual(
    Buffer.from(a).toString('hex'),
    Buffer.from(b).toString('hex'),
    'two calls should almost never collide',
  );
});

test('newDecoyBytes(ctLen) has 4-byte kcv, 12-byte iv, ctLen-byte ct, all base64', () => {
  const d = newDecoyBytes(320);
  assert.equal(base64ToBytes(d.kcv).length, 4);
  assert.equal(base64ToBytes(d.iv).length, 12);
  assert.equal(base64ToBytes(d.ct).length, 320);
  const d2 = newDecoyBytes(320);
  assert.notEqual(d.ct, d2.ct, 'decoy ct is random per call');
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/vault.test.mjs`
Expected: FAIL — `Cannot find module '../src/vault.js'`.

- [ ] **Step 3: Create `src/vault.js`**

```js
import { utf8, bytesToBase64 } from './encoding.js';

export const VAULT_FORMAT = 'kunji-data';
export const VAULT_V = 1;
export const VAULT_AAD = utf8('kunji-vault-v1');

export class BadEnvelopeError extends Error {
  constructor(msg) { super(msg); this.name = 'BadEnvelopeError'; }
}
export class WrongPassphraseError extends Error {
  constructor(msg) { super(msg); this.name = 'WrongPassphraseError'; }
}
export class CorruptVaultError extends Error {
  constructor(msg) { super(msg); this.name = 'CorruptVaultError'; }
}

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

// Until real decoys ship (Phase 3) the decoy slot is random bytes. `ctLen` is
// passed the real ciphertext length so the decoy blob matches the real vault's
// size and the file leaks nothing about whether a decoy exists.
export function newDecoyBytes(ctLen) {
  return {
    kcv: bytesToBase64(randomBytes(4)),
    iv: bytesToBase64(randomBytes(12)),
    ct: bytesToBase64(randomBytes(ctLen)),
  };
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/vault.test.mjs`
Expected: PASS, 4 tests. Full `node --test`: 64 tests green. `node tools/build.mjs && node tools/check-invariants.mjs` — the new `src/vault.js` must not trip an invariant; both green.

- [ ] **Step 5: Commit**

```bash
git add src/vault.js tests/vault.test.mjs
git commit -m "feat: vault module scaffold (errors, constants, decoy bytes)"
```

---

## Task 4: `vault.js` — vault model and entry CRUD

**Files:**
- Modify: `src/vault.js`
- Test: `tests/vault.test.mjs` (append)

- [ ] **Step 1: Append the failing tests**

```js
import {
  createVault, makeEntry, addEntry, updateEntry, removeEntry,
} from '../src/vault.js';

test('createVault is empty with the default settings', () => {
  const v = createVault();
  assert.deepEqual(v.entries, []);
  assert.equal(v.settings.autoLockMinutes, 5);
  assert.equal(v.settings.clipboardClearSeconds, 25);
  assert.equal(v.settings.revealSeconds, 20);
  assert.equal(v.settings.defaultRules, 'standard');
  assert.equal(v.settings.defaultLength, 20);
});

test('makeEntry: password defaults', () => {
  const e = makeEntry({ name: 'GitHub', site: 'github.com', account: 'me' });
  assert.equal(e.type, 'password');
  assert.equal(e.profile, 'v1');
  assert.equal(e.counter, 1);
  assert.equal(e.length, 20);
  assert.equal(e.rules, 'standard');
  assert.equal(e.totp, null);
  assert.deepEqual(e.recoveryCodes, []);
  assert.match(e.id, /^[0-9a-f-]{36}$/);
  assert.ok(e.updatedAt);
});

test('makeEntry: sso shape, no derivation fields', () => {
  const e = makeEntry({ type: 'sso', name: 'News', site: 'news.example.com', account: 'me', via: { site: 'google.com', account: 'me' } });
  assert.equal(e.type, 'sso');
  assert.deepEqual(e.via, { site: 'google.com', account: 'me' });
  assert.equal(e.counter, undefined);
  assert.equal(e.rules, undefined);
});

test('makeEntry: caller cannot override id via partial', () => {
  const e = makeEntry({ id: 'attacker', name: 'x' });
  assert.notEqual(e.id, 'attacker');
});

test('addEntry appends a new entry without mutating the input', () => {
  const v0 = createVault();
  const v1 = addEntry(v0, { name: 'A', site: 's', account: 'a' });
  assert.equal(v0.entries.length, 0);
  assert.equal(v1.entries.length, 1);
  assert.equal(v1.entries[0].name, 'A');
});

test('updateEntry patches by id, bumps updatedAt, keeps id', async () => {
  let v = addEntry(createVault(), { name: 'A', site: 's', account: 'a' });
  const id = v.entries[0].id;
  const before = v.entries[0].updatedAt;
  await new Promise((r) => setTimeout(r, 2));
  v = updateEntry(v, id, { name: 'A2', id: 'nope' });
  assert.equal(v.entries[0].name, 'A2');
  assert.equal(v.entries[0].id, id);
  assert.notEqual(v.entries[0].updatedAt, before);
});

test('removeEntry drops by id', () => {
  let v = addEntry(createVault(), { name: 'A', site: 's', account: 'a' });
  const id = v.entries[0].id;
  v = removeEntry(v, id);
  assert.equal(v.entries.length, 0);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/vault.test.mjs`
Expected: FAIL — `createVault` etc. not exported.

- [ ] **Step 3: Append to `src/vault.js`**

```js
export function createVault() {
  return {
    entries: [],
    settings: {
      clipboardClearSeconds: 25,
      revealSeconds: 20,
      defaultRules: 'standard',
      defaultLength: 20,
      autoLockMinutes: 5,
    },
  };
}

export function makeEntry(partial) {
  const now = new Date().toISOString();
  const common = {
    name: '', site: '', account: '', notes: '',
    ...partial,
    id: crypto.randomUUID(),
    updatedAt: now,
  };
  if (partial.type === 'sso') {
    return {
      ...common,
      type: 'sso',
      via: partial.via ? { site: partial.via.site ?? '', account: partial.via.account ?? '' } : { site: '', account: '' },
    };
  }
  return {
    ...common,
    type: 'password',
    profile: 'v1',
    counter: partial.counter ?? 1,
    length: partial.length ?? 20,
    rules: partial.rules ?? 'standard',
    totp: partial.totp ?? null,
    recoveryCodes: partial.recoveryCodes ?? [],
  };
}

export function addEntry(vault, partial) {
  return { ...vault, entries: [...vault.entries, makeEntry(partial)] };
}

export function updateEntry(vault, id, patch) {
  return {
    ...vault,
    entries: vault.entries.map((e) =>
      e.id === id ? { ...e, ...patch, id: e.id, updatedAt: new Date().toISOString() } : e,
    ),
  };
}

export function removeEntry(vault, id) {
  return { ...vault, entries: vault.entries.filter((e) => e.id !== id) };
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/vault.test.mjs`
Expected: PASS, 11 tests. Full `node --test`: 71 tests green.

- [ ] **Step 5: Commit**

```bash
git add src/vault.js tests/vault.test.mjs
git commit -m "feat: vault in-memory model and entry crud"
```

---

## Task 5: `vault.js` — `encodeEnvelope`

**Files:**
- Modify: `src/vault.js`
- Test: `tests/vault.test.mjs` (append)

- [ ] **Step 1: Append the failing tests**

```js
import { encodeEnvelope } from '../src/vault.js';
import { deriveVaultKey, computeKcv, PBKDF2_ITERATIONS } from '../src/derive.js';
import { hexToBytes, base64ToBytes as b64 } from '../src/encoding.js';

const MK = hexToBytes('ab'.repeat(31) + '12');

test('encodeEnvelope produces a valid, complete envelope string', async () => {
  const vault = addEntry(createVault(), { name: 'A', site: 's', account: 'a' });
  const text = await encodeEnvelope(vault, { masterKey: MK, prevRevision: 41, writerId: 'w-1' });
  const env = JSON.parse(text);
  assert.equal(env.format, 'kunji-data');
  assert.equal(env.v, 1);
  assert.equal(env.kdf, `pbkdf2-sha512-${PBKDF2_ITERATIONS}`);
  assert.equal(env.identityHint, null);
  assert.equal(env.kcv, await computeKcv(MK));
  assert.equal(b64(env.iv).length, 12);
  assert.ok(b64(env.ct).length > 16);
  assert.equal(b64(env.decoy.kcv).length, 4);
  assert.equal(b64(env.decoy.iv).length, 12);
  assert.equal(b64(env.decoy.ct).length, b64(env.ct).length, 'decoy ct matches real ct length');
  assert.equal(env.revision, 42);
  assert.equal(env.lastWriter, 'w-1');
  assert.match(env.updatedAt, /^\d{4}-\d\d-\d\dT/);
  assert.ok(text.endsWith('\n'));
});

test('encodeEnvelope writes identityHint only when given', async () => {
  const v = createVault();
  const withHint = JSON.parse(await encodeEnvelope(v, { masterKey: MK, identityHint: 'me@x.com', writerId: 'w' }));
  assert.equal(withHint.identityHint, 'me@x.com');
});

test('encodeEnvelope uses a fresh IV each call', async () => {
  const v = createVault();
  const a = JSON.parse(await encodeEnvelope(v, { masterKey: MK, writerId: 'w' }));
  const b = JSON.parse(await encodeEnvelope(v, { masterKey: MK, writerId: 'w' }));
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(a.ct, b.ct);
});

test('encodeEnvelope defaults prevRevision to 0 -> revision 1', async () => {
  const env = JSON.parse(await encodeEnvelope(createVault(), { masterKey: MK, writerId: 'w' }));
  assert.equal(env.revision, 1);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/vault.test.mjs`
Expected: FAIL — `encodeEnvelope` not exported.

- [ ] **Step 3: Append to `src/vault.js`**

Add these imports to the top of `src/vault.js` (next to the existing `encoding.js` import):

```js
import { aesGcmEncrypt } from './webcrypto.js';
import { deriveVaultKey, computeKcv, PBKDF2_ITERATIONS } from './derive.js';
```

Then append:

```js
export async function encodeEnvelope(vault, { masterKey, identityHint = null, prevRevision = 0, writerId }) {
  const plainBytes = utf8(JSON.stringify({ entries: vault.entries, settings: vault.settings }));
  const vaultKey = await deriveVaultKey(masterKey);
  const iv = randomBytes(12);
  const ct = await aesGcmEncrypt(vaultKey, iv, plainBytes, VAULT_AAD);
  const envelope = {
    format: VAULT_FORMAT,
    v: VAULT_V,
    kdf: `pbkdf2-sha512-${PBKDF2_ITERATIONS}`,
    identityHint: identityHint || null,
    kcv: await computeKcv(masterKey),
    iv: bytesToBase64(iv),
    ct: bytesToBase64(ct),
    decoy: newDecoyBytes(ct.length),
    revision: prevRevision + 1,
    lastWriter: writerId,
    updatedAt: new Date().toISOString(),
  };
  return JSON.stringify(envelope, null, 2) + '\n';
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/vault.test.mjs`
Expected: PASS, 15 tests. Full `node --test`: 75 tests green. `node tools/build.mjs && node tools/check-invariants.mjs` green.

- [ ] **Step 5: Commit**

```bash
git add src/vault.js tests/vault.test.mjs
git commit -m "feat: vault envelope encode (aes-gcm + decoy)"
```

---

## Task 6: `vault.js` — `parseEnvelope` and `unlockVault` + frozen decrypt vector

**Files:**
- Modify: `src/vault.js`
- Test: `tests/vault.test.mjs` (append)

- [ ] **Step 1: Append the failing tests**

```js
import { parseEnvelope, unlockVault } from '../src/vault.js';

const OTHER_MK = hexToBytes('cd'.repeat(32));

test('parseEnvelope accepts a well-formed envelope', async () => {
  const text = await encodeEnvelope(createVault(), { masterKey: MK, writerId: 'w' });
  const env = parseEnvelope(text);
  assert.equal(env.format, 'kunji-data');
});

test('parseEnvelope rejects non-JSON, wrong format, wrong version, missing fields', () => {
  assert.throws(() => parseEnvelope('not json'), BadEnvelopeError);
  assert.throws(() => parseEnvelope(JSON.stringify({ format: 'other', v: 1 })), BadEnvelopeError);
  assert.throws(() => parseEnvelope(JSON.stringify({ format: 'kunji-data', v: 2 })), BadEnvelopeError);
  assert.throws(() => parseEnvelope(JSON.stringify({ format: 'kunji-data', v: 1 })), BadEnvelopeError);
});

test('unlockVault round-trips entries and settings', async () => {
  const v = addEntry(createVault(), { name: 'GitHub', site: 'github.com', account: 'me', notes: 'hi' });
  const env = parseEnvelope(await encodeEnvelope(v, { masterKey: MK, writerId: 'w' }));
  const out = await unlockVault(env, { masterKey: MK });
  assert.equal(out.entries.length, 1);
  assert.equal(out.entries[0].name, 'GitHub');
  assert.equal(out.entries[0].notes, 'hi');
  assert.equal(out.settings.autoLockMinutes, 5);
});

test('unlockVault throws WrongPassphraseError on KCV mismatch', async () => {
  const env = parseEnvelope(await encodeEnvelope(createVault(), { masterKey: MK, writerId: 'w' }));
  await assert.rejects(() => unlockVault(env, { masterKey: OTHER_MK }), WrongPassphraseError);
});

test('unlockVault throws CorruptVaultError when the ciphertext is damaged', async () => {
  const env = parseEnvelope(await encodeEnvelope(createVault(), { masterKey: MK, writerId: 'w' }));
  const bad = { ...env, ct: bytesToBase64Local(flipFirstByte(b64(env.ct))) };
  await assert.rejects(() => unlockVault(bad, { masterKey: MK }), CorruptVaultError);
});

function flipFirstByte(bytes) { const c = bytes.slice(); c[0] ^= 1; return c; }
function bytesToBase64Local(bytes) { return Buffer.from(bytes).toString('base64'); }

test('frozen decrypt vector: fixed vaultKey/iv/ct/aad -> known plaintext', async () => {
  const { aesGcmDecrypt } = await import('../src/webcrypto.js');
  const { utf8: u, hexToBytes: h, fromUtf8: f } = await import('../src/encoding.js');
  const vaultKey = h('__FILL_VK__');
  const iv = h('__FILL_IV__');
  const ct = h('__FILL_CT__');
  const plain = await aesGcmDecrypt(vaultKey, iv, ct, u('kunji-vault-v1'));
  assert.equal(f(plain), '{"entries":[],"settings":{}}');
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/vault.test.mjs`
Expected: FAIL — `parseEnvelope` / `unlockVault` not exported.

- [ ] **Step 3: Append to `src/vault.js`**

Add `base64ToBytes`, `fromUtf8` to the `encoding.js` import, and `aesGcmDecrypt` to the `webcrypto.js` import. Then append:

```js
export function parseEnvelope(text) {
  let env;
  try {
    env = JSON.parse(text);
  } catch {
    throw new BadEnvelopeError('not valid JSON');
  }
  if (!env || typeof env !== 'object') throw new BadEnvelopeError('not an object');
  if (env.format !== VAULT_FORMAT) throw new BadEnvelopeError('not a Kunji vault file');
  if (env.v !== VAULT_V) throw new BadEnvelopeError(`unsupported version ${env.v}`);
  for (const k of ['kcv', 'iv', 'ct']) {
    if (typeof env[k] !== 'string') throw new BadEnvelopeError(`missing ${k}`);
  }
  const d = env.decoy;
  if (!d || typeof d.kcv !== 'string' || typeof d.iv !== 'string' || typeof d.ct !== 'string') {
    throw new BadEnvelopeError('missing decoy section');
  }
  return env;
}

export async function unlockVault(envelope, { masterKey }) {
  if (await computeKcv(masterKey) !== envelope.kcv) {
    throw new WrongPassphraseError('that is not the passphrase for this vault');
  }
  const vaultKey = await deriveVaultKey(masterKey);
  let plainBytes;
  try {
    plainBytes = await aesGcmDecrypt(
      vaultKey, base64ToBytes(envelope.iv), base64ToBytes(envelope.ct), VAULT_AAD,
    );
  } catch {
    throw new CorruptVaultError('the file could not be decrypted');
  }
  let plain;
  try {
    plain = JSON.parse(fromUtf8(plainBytes));
  } catch {
    throw new CorruptVaultError('the vault contents could not be read');
  }
  if (!plain || !Array.isArray(plain.entries) || typeof plain.settings !== 'object') {
    throw new CorruptVaultError('the vault contents are not in the expected shape');
  }
  return { entries: plain.entries, settings: plain.settings };
}
```

- [ ] **Step 4: Freeze the decrypt vector**

Run this to produce the three hex strings, then paste them into `__FILL_VK__`, `__FILL_IV__`, `__FILL_CT__` in the test from Step 1:

```bash
node -e "Promise.all([import('./src/webcrypto.js'),import('./src/encoding.js')]).then(async ([w,e])=>{ const vk=e.hexToBytes('00'.repeat(32)); const iv=e.hexToBytes('00'.repeat(12)); const ct=await w.aesGcmEncrypt(vk,iv,e.utf8('{\"entries\":[],\"settings\":{}}'),e.utf8('kunji-vault-v1')); console.log('VK',e.bytesToHex(vk)); console.log('IV',e.bytesToHex(iv)); console.log('CT',e.bytesToHex(ct)); })"
```

Run it twice; the CT must be byte-identical both times (AES-GCM is deterministic for a fixed key+iv+aad+plaintext).

- [ ] **Step 5: Run to verify it passes**

Run: `node --test tests/vault.test.mjs`
Expected: PASS, 22 tests. Full `node --test`: 82 tests green. `node tools/build.mjs && node tools/check-invariants.mjs` green.

- [ ] **Step 6: Commit**

```bash
git add src/vault.js tests/vault.test.mjs
git commit -m "feat: vault envelope parse + unlock, frozen decrypt vector"
```

---

## Task 7: Build wiring — `JS_ORDER`, `vault-ui.js` stub

**Files:**
- Modify: `tools/build.mjs`
- Create: `src/vault-ui.js`
- Test: `tests/build.test.mjs` (append)

- [ ] **Step 1: Append the failing test**

Add to `tests/build.test.mjs`:

```js
test('built html inlines the vault modules', () => {
  execFileSync('node', ['tools/build.mjs'], { stdio: 'pipe' });
  const html = readFileSync('dist/kunji.html', 'utf8');
  assert.ok(html.includes('==== src/vault.js ===='), 'vault.js concatenated');
  assert.ok(html.includes('==== src/vault-ui.js ===='), 'vault-ui.js concatenated');
  assert.ok(html.indexOf('src/vault.js') < html.indexOf('src/app.js'), 'vault.js before app.js');
  assert.ok(html.indexOf('src/app.js') < html.indexOf('src/vault-ui.js'), 'vault-ui.js last');
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/build.test.mjs`
Expected: FAIL — the markers are not present.

- [ ] **Step 3: Update `JS_ORDER` in `tools/build.mjs`**

Replace the `JS_ORDER` block:

```js
// Explicit dependency order. encoding -> webcrypto -> derive -> vault -> app -> vault-ui.
const JS_ORDER = [
  'src/encoding.js',
  'src/webcrypto.js',
  'src/derive.js',
  'src/vault.js',
  'src/app.js',
  'src/vault-ui.js',
];
```

- [ ] **Step 4: Create `src/vault-ui.js` stub**

```js
// The Vault tab. Built up across Tasks 9-14. References bundle-global functions
// from vault.js / derive.js after concatenation; never imported by tests.
function initVaultTab() {
  // filled in Task 9
}

if (typeof document !== 'undefined') {
  initVaultTab();
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `node --test tests/build.test.mjs`
Expected: PASS. Full `node --test`: 83 tests green (82 + 1). `node tools/build.mjs && node tools/check-invariants.mjs` green. Open `dist/kunji.html` in a browser: the Phase 1 generator still works exactly as before (nothing visible changed yet), no console errors.

- [ ] **Step 6: Commit**

```bash
git add tools/build.mjs src/vault-ui.js tests/build.test.mjs
git commit -m "build: wire vault.js and vault-ui.js into the bundle"
```

---

## Task 8: Tab shell — markup, styles, `app.js` refactor

**Files:**
- Modify: `src/head.html`
- Modify: `src/style.css`
- Modify: `src/app.js`
- Manual test: `dist/kunji.html` in a browser

- [ ] **Step 1: Replace `src/head.html`**

Wrap the existing card body in a `#tab-generate` div, add the tab strip and an empty `#tab-vault` div. The `<main class="card">` open tag, `<header>`, and all field markup are unchanged from Phase 1 except for the two wrapper divs and the tab strip.

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

  <div class="tabstrip" role="tablist">
    <button class="tab" id="tabBtnGenerate" role="tab" aria-selected="true" type="button">Generate</button>
    <button class="tab" id="tabBtnVault" role="tab" aria-selected="false" type="button">Vault</button>
  </div>

  <section id="tab-generate" role="tabpanel">
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
  </section>

  <section id="tab-vault" role="tabpanel" hidden></section>
</main>
```

- [ ] **Step 2: Append to `src/style.css`**

```css
.tabstrip { display: flex; gap: 24px; border-bottom: 1px solid var(--border); margin-bottom: 24px; }
.tab {
  background: none; border: none; color: var(--muted);
  font: 700 13px inherit; cursor: pointer; padding: 0 0 10px;
  min-height: 44px;
}
.tab[aria-selected="true"] { color: var(--text); box-shadow: inset 0 -2px 0 var(--blue); }

/* Vault tab */
.v-explain { font-size: 13px; color: var(--muted); margin-bottom: 16px; line-height: 1.5; }
.v-loaded { font-size: 12px; color: var(--muted); margin-bottom: 14px; }
.btn-ghost {
  width: 100%; padding: 12px; border: 1px solid var(--border-strong);
  border-radius: 9999px; background: transparent; color: var(--text);
  font: 700 var(--fs-base) inherit; cursor: pointer; min-height: 44px;
}
.v-center-link { text-align: center; margin-top: 10px; }
.link-btn {
  background: none; border: none; color: var(--blue);
  font: 600 13px inherit; cursor: pointer; min-height: 44px; padding: 0 4px;
}
.v-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
.v-count { font-size: 13px; font-weight: 700; }
.v-search {
  width: 100%; font: inherit; color: var(--text); background: transparent;
  border: 1px solid var(--border); border-radius: 4px; padding: 8px 10px;
  outline: none; margin-bottom: 10px;
}
.v-search:focus { border-color: var(--blue); }
.v-row { border-bottom: 1px solid #1a1c1f; padding: 11px 0; cursor: pointer; }
.v-row .v-name { font-size: 13px; font-weight: 700; }
.v-row .v-meta { font-size: 11px; color: var(--muted); margin-top: 2px; }
.v-chip {
  display: inline-block; font-size: 10px; color: var(--muted);
  border: 1px solid var(--border); border-radius: 4px; padding: 1px 5px; margin: 0 4px 4px 0;
}
.v-foot { margin-top: 12px; font-size: 12px; color: var(--muted); }
.v-dirty {
  background: #2a1a00; border: 1px solid #5c4300; color: #f5c518;
  font-size: 12px; padding: 8px 10px; border-radius: 6px; margin: 10px 0;
  display: flex; justify-content: space-between; align-items: center;
}
.v-sec { border-top: 1px solid #1a1c1f; margin-top: 12px; padding-top: 10px; }
.v-sec .v-h { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; margin-bottom: 4px; }
.v-editrow { display: flex; gap: 8px; }
.v-editrow .field { flex: 1; }
.v-danger { color: #F4212E; }
```

- [ ] **Step 3: Refactor `src/app.js`**

Two changes, nothing else:

1. Rename `function initUI()` to `function initGenerateTab()`. The entire body is unchanged.
2. Replace the bottom bootstrap block:

```js
if (typeof document !== 'undefined') {
  initUI();
}
```

with:

```js
function initApp() {
  const genBtn = document.getElementById('tabBtnGenerate');
  const vaultBtn = document.getElementById('tabBtnVault');
  const genPanel = document.getElementById('tab-generate');
  const vaultPanel = document.getElementById('tab-vault');

  function show(which) {
    const gen = which === 'generate';
    genPanel.hidden = !gen;
    vaultPanel.hidden = gen;
    genBtn.setAttribute('aria-selected', String(gen));
    vaultBtn.setAttribute('aria-selected', String(!gen));
  }
  genBtn.addEventListener('click', () => show('generate'));
  vaultBtn.addEventListener('click', () => show('vault'));

  initGenerateTab();
}

if (typeof document !== 'undefined') {
  initApp();
}
```

Note: `initVaultTab()` is still called by the guard at the bottom of `src/vault-ui.js` (unchanged from Task 7). After concatenation both run once on load.

- [ ] **Step 4: Build**

Run: `node tools/build.mjs && node tools/check-invariants.mjs`
Expected: both green.

- [ ] **Step 5: Verify Phase 1 is intact**

Run: `node --test`
Expected: 83 tests green — in particular every `v1 vector` test and every `tests/app.test.mjs` test still pass (the Generate-tab refactor changed no derivation code and no exported helper).

- [ ] **Step 6: Manual browser test**

Serve and open (the extension blocks `file://`, so use a local server):
```bash
cd dist && python3 -m http.server 8801
```
Open `http://localhost:8801/kunji.html`. Checklist:
- [ ] Two tabs "Generate" / "Vault" under the title. Generate is selected, its underline is blue.
- [ ] The Generate tab looks and behaves exactly as Phase 1: fill identity + passphrase → KCV goes green; fill site + account → Generate → a 20-char password, grouped in fours; reveal, copy, length-7 error all still work.
- [ ] Click "Vault" → the generator disappears, an empty panel shows. Click "Generate" → it comes back with its state intact.
- [ ] No console errors. No network requests.
Stop the server (`Ctrl-C`).

- [ ] **Step 7: Commit**

```bash
git add src/head.html src/style.css src/app.js
git commit -m "feat: generate/vault tab shell; generate tab unchanged"
```

---

## Task 9: Vault tab — NO_VAULT and CREATE states

**Files:**
- Modify: `src/vault-ui.js`
- Manual test: `dist/kunji.html` in a browser

- [ ] **Step 1: Replace `src/vault-ui.js`**

```js
// The Vault tab. References bundle-global functions from vault.js / derive.js
// after concatenation (createVault, addEntry, updateEntry, removeEntry,
// encodeEnvelope, parseEnvelope, unlockVault, deriveMasterKey, computeKcv,
// derivePassword, groupInFours). Never imported by tests.

function initVaultTab() {
  const panel = document.getElementById('tab-vault');
  if (!panel) return;

  const writerId = crypto.randomUUID();

  // Session state. Cleared on lock.
  let state = 'NO_VAULT';        // NO_VAULT | CREATE | LOCKED | UNLOCKED
  let loadedEnvelope = null;     // parsed envelope while LOCKED/UNLOCKED
  let masterKey = null;          // Uint8Array while UNLOCKED
  let vault = null;              // { entries, settings } while UNLOCKED
  let sessionIdentity = '';      // the identity used to unlock/create, for the hint
  let identityHintOn = false;    // write identity into the plaintext envelope?
  let dirty = false;
  let view = 'list';             // list | detail | editor  (within UNLOCKED)
  let selectedId = null;

  const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]
  ));

  function wipe() {
    masterKey = null;
    vault = null;
    sessionIdentity = '';
    dirty = false;
    view = 'list';
    selectedId = null;
  }

  function render() {
    if (state === 'NO_VAULT') return renderNoVault();
    if (state === 'CREATE') return renderCreate();
    if (state === 'LOCKED') return renderLocked();
    return renderUnlocked();
  }

  // ---- NO_VAULT ----------------------------------------------------------
  function renderNoVault() {
    panel.innerHTML = `
      <p class="v-explain">A vault stores custom rules, PINs, 2FA recovery codes and
      notes, encrypted with your master passphrase. It is optional — the generator
      works without it.</p>
      <button class="btn-ghost" id="vOpenBtn" type="button">Open vault file&hellip;</button>
      <input type="file" id="vFileInput" accept=".json,application/json" hidden>
      <div class="v-center-link"><button class="link-btn" id="vCreateBtn" type="button">Create a new vault</button></div>
      <div class="error" id="vError"></div>
    `;
    panel.querySelector('#vOpenBtn').addEventListener('click', () => panel.querySelector('#vFileInput').click());
    panel.querySelector('#vFileInput').addEventListener('change', onFilePicked);
    panel.querySelector('#vCreateBtn').addEventListener('click', () => { state = 'CREATE'; render(); });
  }

  async function onFilePicked(ev) {
    const file = ev.target.files && ev.target.files[0];
    if (!file) return;
    const errEl = panel.querySelector('#vError');
    try {
      const text = await file.text();
      loadedEnvelope = parseEnvelope(text);
      identityHintOn = typeof loadedEnvelope.identityHint === 'string';
      state = 'LOCKED';
      render();
    } catch (e) {
      errEl.textContent = e && e.name === 'BadEnvelopeError'
        ? 'That does not look like a Kunji vault file.'
        : 'Could not read that file.';
    }
  }

  // ---- CREATE ----------------------------------------------------------
  function renderCreate() {
    panel.innerHTML = `
      <div class="fields">
        <div class="field"><input id="vcIdentity" type="text" autocomplete="off" spellcheck="false" placeholder=" "><label for="vcIdentity">Identity</label></div>
        <div class="field"><input id="vcPass" type="password" autocomplete="off" spellcheck="false" placeholder=" "><label for="vcPass">Master passphrase</label></div>
        <div class="field"><input id="vcConfirm" type="password" autocomplete="off" spellcheck="false" placeholder=" "><label for="vcConfirm">Confirm passphrase</label></div>
      </div>
      <button class="btn-primary" id="vcCreate" type="button">Create vault</button>
      <div class="v-foot">Same identity + passphrase as the generator.</div>
      <div class="v-center-link"><button class="link-btn" id="vcCancel" type="button">Cancel</button></div>
      <div class="error" id="vcError"></div>
    `;
    panel.querySelector('#vcCancel').addEventListener('click', () => { state = 'NO_VAULT'; render(); });
    panel.querySelector('#vcCreate').addEventListener('click', onCreate);
  }

  async function onCreate() {
    const id = panel.querySelector('#vcIdentity').value.trim();
    const pass = panel.querySelector('#vcPass').value;
    const confirm = panel.querySelector('#vcConfirm').value;
    const errEl = panel.querySelector('#vcError');
    errEl.textContent = '';
    if (!id || !pass) { errEl.textContent = 'Identity and passphrase are required.'; return; }
    if (pass !== confirm) { errEl.textContent = 'The two passphrases do not match.'; return; }
    const btn = panel.querySelector('#vcCreate');
    btn.disabled = true; btn.textContent = 'Creating…';
    try {
      masterKey = await deriveMasterKey(pass, id);
      vault = createVault();
      loadedEnvelope = null;
      sessionIdentity = id;
      identityHintOn = false;
      dirty = true;
      state = 'UNLOCKED';
      render();
    } catch (e) {
      errEl.textContent = 'Could not create the vault.';
      btn.disabled = false; btn.textContent = 'Create vault';
    }
  }

  // ---- LOCKED / UNLOCKED: filled in Tasks 10-13 ----
  function renderLocked() { panel.innerHTML = '<p class="v-explain">Locked (Task 10)</p>'; }
  function renderUnlocked() { panel.innerHTML = '<p class="v-explain">Unlocked (Task 11)</p>'; }

  render();
}

if (typeof document !== 'undefined') {
  initVaultTab();
}
```

- [ ] **Step 2: Build**

Run: `node tools/build.mjs && node tools/check-invariants.mjs`
Expected: both green. `check-invariants` must still pass — this file uses `<input type="file">` in an HTML string; the forbidden pattern is `<script ... src=` / `<link`, not `<input>`, so it is fine. Confirm the run prints `invariants ok`.

- [ ] **Step 3: Run the suite**

Run: `node --test`
Expected: 83 tests green (no new tests; this task is DOM-only, covered by the browser checklist and the `vault.js` unit tests).

- [ ] **Step 4: Manual browser test**

`cd dist && python3 -m http.server 8801`, open `http://localhost:8801/kunji.html`, click the Vault tab. Checklist:
- [ ] Shows the explainer paragraph, a "Open vault file…" ghost button, a "Create a new vault" link.
- [ ] Click "Create a new vault" → three fields (Identity, Master passphrase, Confirm passphrase), a "Create vault" button, "Cancel".
- [ ] "Cancel" → back to the no-vault view.
- [ ] Enter mismatched passphrases → "Create vault" → "The two passphrases do not match."
- [ ] Enter identity + matching passphrases → "Create vault" → the panel changes to the placeholder "Unlocked (Task 11)" text (proves `deriveMasterKey` + `createVault` ran without error).
- [ ] No console errors.

- [ ] **Step 5: Commit**

```bash
git add src/vault-ui.js
git commit -m "feat: vault tab — no-vault and create states"
```

---

## Task 10: Vault tab — LOCKED state and unlock

**Files:**
- Modify: `src/vault-ui.js`
- Manual test: `dist/kunji.html` in a browser

- [ ] **Step 1: Replace `renderLocked` in `src/vault-ui.js`**

Replace the `function renderLocked() { ... }` placeholder with:

```js
  function renderLocked() {
    const hint = typeof loadedEnvelope.identityHint === 'string' ? esc(loadedEnvelope.identityHint) : '';
    panel.innerHTML = `
      <div class="v-loaded">Vault file loaded.</div>
      <div class="fields">
        <div class="field"><input id="vlIdentity" type="text" autocomplete="off" spellcheck="false" placeholder=" " value="${hint}"><label for="vlIdentity">Identity</label></div>
        <div class="field"><input id="vlPass" type="password" autocomplete="off" spellcheck="false" placeholder=" "><label for="vlPass">Master passphrase</label></div>
      </div>
      <div class="kcv" id="vlKcv" data-state="none"><span class="dot"></span> <span id="vlKcvText">enter identity and passphrase</span></div>
      <button class="btn-primary" id="vlUnlock" type="button">Unlock</button>
      <div class="v-center-link"><button class="link-btn" id="vlOther" type="button">Open a different file</button></div>
      <div class="error" id="vlError"></div>
    `;
    const identityEl = panel.querySelector('#vlIdentity');
    const passEl = panel.querySelector('#vlPass');
    const kcv = panel.querySelector('#vlKcv');
    const kcvText = panel.querySelector('#vlKcvText');

    async function refresh() {
      const id = identityEl.value.trim();
      const pw = passEl.value;
      if (!id || !pw) { kcv.dataset.state = 'none'; kcvText.textContent = 'enter identity and passphrase'; return; }
      kcv.dataset.state = 'none'; kcvText.textContent = 'checking…';
      try {
        const mk = await deriveMasterKey(pw, id);
        if (await computeKcv(mk) === loadedEnvelope.kcv) {
          kcv.dataset.state = 'ok'; kcvText.textContent = 'passphrase matches this vault';
        } else {
          kcv.dataset.state = 'bad'; kcvText.textContent = 'not this vault’s passphrase';
        }
      } catch {
        kcv.dataset.state = 'bad'; kcvText.textContent = 'could not derive key';
      }
    }
    identityEl.addEventListener('change', refresh);
    passEl.addEventListener('change', refresh);

    panel.querySelector('#vlOther').addEventListener('click', () => {
      if (dirty && !confirm('Discard unsaved changes and open a different file?')) return;
      loadedEnvelope = null; wipe(); state = 'NO_VAULT'; render();
    });

    panel.querySelector('#vlUnlock').addEventListener('click', async () => {
      const errEl = panel.querySelector('#vlError');
      errEl.textContent = '';
      const id = identityEl.value.trim();
      const pw = passEl.value;
      if (!id || !pw) { errEl.textContent = 'Identity and passphrase are required.'; return; }
      const btn = panel.querySelector('#vlUnlock');
      btn.disabled = true; btn.textContent = 'Unlocking…';
      try {
        const mk = await deriveMasterKey(pw, id);
        const out = await unlockVault(loadedEnvelope, { masterKey: mk });
        masterKey = mk;
        vault = out;
        sessionIdentity = id;
        identityHintOn = typeof loadedEnvelope.identityHint === 'string';
        dirty = false;
        state = 'UNLOCKED';
        render();
      } catch (e) {
        btn.disabled = false; btn.textContent = 'Unlock';
        if (e && e.name === 'WrongPassphraseError') {
          errEl.textContent = 'That is not the passphrase for this vault.';
        } else if (e && e.name === 'CorruptVaultError') {
          errEl.textContent = 'Could not unlock — the file may be corrupted or from a different passphrase.';
        } else {
          errEl.textContent = 'Could not unlock this vault.';
        }
      }
    });
  }
```

- [ ] **Step 2: Build**

Run: `node tools/build.mjs && node tools/check-invariants.mjs`
Expected: both green.

- [ ] **Step 3: Run the suite**

Run: `node --test`
Expected: 83 tests green.

- [ ] **Step 4: Manual browser test**

You need a vault file. Generate one in the Node REPL (uses the same code paths):
```bash
node -e "Promise.all([import('./src/vault.js'),import('./src/derive.js')]).then(async([v,d])=>{ const mk=await d.deriveMasterKey('correct horse battery staple','alex@example.com'); let vault=v.addEntry(v.createVault(),{name:'GitHub',site:'github.com',account:'alex',notes:'personal'}); const text=await v.encodeEnvelope(vault,{masterKey:mk,writerId:'seed'}); require('fs').writeFileSync('/tmp/kunji-data.json',text); console.log('wrote /tmp/kunji-data.json'); })"
```
`cd dist && python3 -m http.server 8801`, open the page, Vault tab. Checklist:
- [ ] Click "Open vault file…" → pick `/tmp/kunji-data.json` → the LOCKED view appears (Identity + Master passphrase + KCV dot + Unlock).
- [ ] Type identity `alex@example.com`, passphrase `wrong`, click elsewhere → red dot, "not this vault's passphrase".
- [ ] Fix the passphrase to `correct horse battery staple`, click elsewhere → green dot, "passphrase matches this vault".
- [ ] Click "Unlock" → the panel changes to the "Unlocked (Task 11)" placeholder.
- [ ] Re-open the page, open the file, enter the wrong passphrase, click "Unlock" directly → "That is not the passphrase for this vault." and it stays on the LOCKED view.
- [ ] "Open a different file" returns to the no-vault view.
- [ ] No console errors.

- [ ] **Step 5: Commit**

```bash
git add src/vault-ui.js
git commit -m "feat: vault tab — locked state and unlock"
```

---

## Task 11: Vault tab — UNLOCKED list, save, lock, dirty bar

**Files:**
- Modify: `src/vault-ui.js`
- Manual test: `dist/kunji.html` in a browser

- [ ] **Step 1: Replace `renderUnlocked` and add helpers in `src/vault-ui.js`**

Replace the `function renderUnlocked() { ... }` placeholder with the following, and add `renderList`, `saveVault`, `lock`, `markDirty` alongside it:

```js
  function markDirty() { dirty = true; if (state === 'UNLOCKED' && view === 'list') renderList(); }

  function lock() {
    // keep loadedEnvelope so re-unlock only needs the passphrase
    wipe();
    state = loadedEnvelope ? 'LOCKED' : 'NO_VAULT';
    render();
  }

  async function saveVault() {
    const prevRevision = loadedEnvelope ? (loadedEnvelope.revision || 0) : 0;
    const text = await encodeEnvelope(vault, {
      masterKey,
      identityHint: currentIdentityForHint(),
      prevRevision,
      writerId,
    });
    loadedEnvelope = parseEnvelope(text); // adopt the new revision/updatedAt
    dirty = false;
    const blob = new Blob([text], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'kunji-data.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    if (!sessionMoveNoteShown) {
      sessionMoveNoteShown = true;
      alert('Saved as kunji-data.json in your downloads. Move it to wherever your sync watches, and overwrite the previous copy.');
    }
    renderList();
  }

  function currentIdentityForHint() {
    if (!identityHintOn) return null;
    return sessionIdentity
      || (loadedEnvelope && typeof loadedEnvelope.identityHint === 'string' ? loadedEnvelope.identityHint : null);
  }

  function renderUnlocked() {
    if (view === 'detail') return renderDetail();
    if (view === 'editor') return renderEditor();
    return renderList();
  }

  // Shared row markup so the full render and the search re-filter never drift.
  function rowsHtml() {
    const q = (listQuery || '').toLowerCase();
    const html = vault.entries
      .filter((e) => !q || `${e.name} ${e.site} ${e.account}`.toLowerCase().includes(q))
      .map((e) => {
        const meta = e.type === 'sso'
          ? `${esc(e.site)} &middot; via ${esc(e.via && e.via.site)} <span class="v-chip">SSO</span>`
          : `${esc(e.site)} &middot; ${esc(e.account)}`;
        return `<div class="v-row" data-id="${e.id}"><div class="v-name">${esc(e.name) || '(no name)'}</div><div class="v-meta">${meta}</div></div>`;
      })
      .join('');
    return html || `<div class="v-foot">${q ? 'No match.' : 'No entries yet.'}</div>`;
  }

  function bindRowClicks(container) {
    container.querySelectorAll('.v-row').forEach((row) => row.addEventListener('click', () => {
      selectedId = row.dataset.id; view = 'detail'; render();
    }));
  }

  function renderList() {
    panel.innerHTML = `
      <div class="v-bar">
        <span class="v-count">Vault &middot; ${vault.entries.length}</span>
        <button class="link-btn" id="vNew" type="button">+ New</button>
      </div>
      <input class="v-search" id="vSearch" type="text" placeholder="Search…" value="${esc(listQuery || '')}">
      <div id="vRows">${rowsHtml()}</div>
      ${dirty ? '<div class="v-dirty">Unsaved changes<button class="link-btn" id="vSaveTop" type="button" style="color:#f5c518">Save vault</button></div>' : ''}
      <div class="v-foot"><button class="link-btn" id="vSave" type="button">Save vault</button> &middot; <button class="link-btn" id="vLock" type="button">Lock</button></div>
      <label class="v-foot" style="display:block"><input type="checkbox" id="vHint" ${identityHintOn ? 'checked' : ''}> Prefill identity on devices that open this file <span class="v-danger">(anyone with the file can read it)</span></label>
      <div class="error" id="vListError"></div>
    `;

    const search = panel.querySelector('#vSearch');
    search.addEventListener('input', () => {
      listQuery = search.value;
      const c = panel.querySelector('#vRows');
      c.innerHTML = rowsHtml();
      bindRowClicks(c);
    });
    bindRowClicks(panel.querySelector('#vRows'));
    panel.querySelector('#vNew').addEventListener('click', () => { selectedId = null; view = 'editor'; render(); });
    panel.querySelector('#vSave').addEventListener('click', () => saveVault().catch(showSaveError));
    if (panel.querySelector('#vSaveTop')) panel.querySelector('#vSaveTop').addEventListener('click', () => saveVault().catch(showSaveError));
    panel.querySelector('#vHint').addEventListener('change', (ev) => { identityHintOn = ev.target.checked; markDirty(); });
    panel.querySelector('#vLock').addEventListener('click', () => {
      if (dirty && !confirm('Discard unsaved changes and lock?')) return;
      lock();
    });
  }

  function showSaveError(e) {
    const el = panel.querySelector('#vListError');
    if (el) el.textContent = 'Save was blocked — allow downloads for this page and try again.';
  }
```

Add these declarations near the other `let` state variables at the top of `initVaultTab`:

```js
  let listQuery = '';
  let sessionMoveNoteShown = false;
```

Add a `beforeunload` guard once, right before the final `render();` call in `initVaultTab`:

```js
  window.addEventListener('beforeunload', (e) => {
    if (dirty) { e.preventDefault(); e.returnValue = ''; }
  });
```

- [ ] **Step 2: Build + suite**

Run: `node tools/build.mjs && node tools/check-invariants.mjs && node --test`
Expected: build + invariants green; 83 tests green.

- [ ] **Step 3: Manual browser test**

Use `/tmp/kunji-data.json` from Task 10 (it has one entry, "GitHub"). Open the page, Vault tab, open the file, unlock with `correct horse battery staple`. Checklist:
- [ ] "Vault · 1", a "+ New" link, a search box, one row "GitHub / github.com · alex".
- [ ] Footer "Save vault · Lock".
- [ ] Type "git" in search → the row still shows; type "zzz" → "No match."; clear it → the row returns. Focus stays in the search box while typing.
- [ ] Click "Lock" → back to the LOCKED view (file still loaded, only the passphrase needed to re-unlock).
- [ ] Re-unlock. Click "Save vault" → a `kunji-data.json` downloads; a one-time alert about moving the file appears. The dirty bar is not shown (nothing was edited).
- [ ] Open the downloaded file in a text editor: valid JSON, `revision` is 1 higher than before, `decoy` block present, `ct` and `decoy.ct` are the same length.
- [ ] No console errors.

- [ ] **Step 4: Commit**

```bash
git add src/vault-ui.js
git commit -m "feat: vault tab — entry list, save (download), lock, dirty bar"
```

---

## Task 12: Vault tab — entry detail

**Files:**
- Modify: `src/vault-ui.js`
- Manual test: `dist/kunji.html` in a browser

- [ ] **Step 1: Replace `renderDetail` placeholder and add reveal/copy helpers**

Write the masked-bullet string as the JS escape `'•'` (not a literal `•`), matching the Phase 1 `src/app.js` convention of keeping source ASCII-only.

Replace `function renderDetail() { ... }` (the placeholder from Task 11's `renderUnlocked`) with:

```js
  function selectedEntry() { return vault.entries.find((e) => e.id === selectedId) || null; }

  async function renderDetail() {
    const e = selectedEntry();
    if (!e) { view = 'list'; return renderList(); }

    if (e.type === 'sso') {
      panel.innerHTML = `
        <div class="v-bar"><button class="link-btn" id="vBack" type="button">&lsaquo; Vault</button><button class="link-btn" id="vEdit" type="button">Edit</button></div>
        <div class="title" style="font-size:18px">${esc(e.name)}</div>
        <div class="v-meta">${esc(e.site)} &middot; ${esc(e.account)}</div>
        <div class="v-sec"><div class="v-h">Log in via</div><div>${esc(e.via && e.via.site)} &middot; ${esc(e.via && e.via.account)}</div></div>
        <div class="v-sec"><div class="v-h">Notes</div><div class="v-meta">${esc(e.notes) || '—'}</div></div>
      `;
      panel.querySelector('#vBack').addEventListener('click', () => { view = 'list'; render(); });
      panel.querySelector('#vEdit').addEventListener('click', () => { view = 'editor'; render(); });
      return;
    }

    const codes = Array.isArray(e.recoveryCodes) ? e.recoveryCodes : [];
    panel.innerHTML = `
      <div class="v-bar"><button class="link-btn" id="vBack" type="button">&lsaquo; Vault</button><button class="link-btn" id="vEdit" type="button">Edit</button></div>
      <div class="title" style="font-size:18px">${esc(e.name)}</div>
      <div class="v-meta">${esc(e.site)} &middot; ${esc(e.account)}</div>
      <div style="margin:8px 0">
        <span class="v-chip">${esc(e.profile)}</span><span class="v-chip">len ${esc(e.length)}</span><span class="v-chip">${esc(e.rules)}</span><span class="v-chip">counter ${esc(e.counter)}</span>
      </div>
      <div class="result-value empty" id="vPw">not derived</div>
      <div><button class="link-btn" id="vReveal" type="button">Reveal</button> &middot; <button class="link-btn" id="vCopy" type="button">Copy</button></div>
      <div class="error" id="vDetailError"></div>
      <div class="v-sec"><div class="v-h">Notes</div><div class="v-meta">${esc(e.notes) || '—'}</div></div>
      <div class="v-sec"><div class="v-h">Recovery codes &middot; ${codes.length}</div><div id="vCodes" class="v-meta">${codes.length ? '<button class="link-btn" id="vShowCodes" type="button">Reveal / copy</button>' : '—'}</div></div>
      <div class="v-sec"><div class="v-h">TOTP secret</div><div class="v-meta">${e.totp ? '&bull;&bull;&bull;&bull; <button class="link-btn" id="vTotpCopy" type="button">copy</button>' : '—'}</div></div>
    `;

    panel.querySelector('#vBack').addEventListener('click', () => { view = 'list'; render(); });
    panel.querySelector('#vEdit').addEventListener('click', () => { view = 'editor'; render(); });

    const pwEl = panel.querySelector('#vPw');
    const errEl = panel.querySelector('#vDetailError');
    let plaintext = '';
    let revealTimer = null;

    async function derive() {
      if (plaintext) return plaintext;
      plaintext = await derivePassword({
        masterKey, site: e.site, account: e.account,
        counter: e.counter, rules: e.rules, length: e.length,
      });
      return plaintext;
    }

    panel.querySelector('#vReveal').addEventListener('click', async () => {
      errEl.textContent = '';
      try {
        const pw = await derive();
        pwEl.classList.remove('empty');
        pwEl.textContent = groupInFours(pw);
        if (revealTimer) clearTimeout(revealTimer);
        revealTimer = setTimeout(() => {
          pwEl.textContent = groupInFours('•'.repeat(pw.length));
        }, (vault.settings.revealSeconds || 20) * 1000);
      } catch (err) { errEl.textContent = err.message; }
    });

    panel.querySelector('#vCopy').addEventListener('click', async () => {
      errEl.textContent = '';
      try {
        const pw = await derive();
        try { await navigator.clipboard.writeText(pw); }
        catch {
          const ta = document.createElement('textarea'); ta.value = pw;
          document.body.appendChild(ta); ta.select();
          try { document.execCommand('copy'); } catch (_) {}
          document.body.removeChild(ta);
        }
        const btn = panel.querySelector('#vCopy');
        btn.textContent = 'Copied';
        setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
        setTimeout(async () => { try { await navigator.clipboard.writeText(''); } catch (_) {} },
          (vault.settings.clipboardClearSeconds || 25) * 1000);
      } catch (err) { errEl.textContent = err.message; }
    });

    const showCodes = panel.querySelector('#vShowCodes');
    if (showCodes) showCodes.addEventListener('click', () => {
      panel.querySelector('#vCodes').innerHTML = codes.map((c) => esc(c)).join('<br>');
    });
    const totpCopy = panel.querySelector('#vTotpCopy');
    if (totpCopy) totpCopy.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(e.totp); totpCopy.textContent = 'copied'; } catch (_) {}
    });
  }
```

- [ ] **Step 2: Build + suite**

Run: `node tools/build.mjs && node tools/check-invariants.mjs && node --test`
Expected: build + invariants green; 83 tests green.

- [ ] **Step 3: Manual browser test**

Open `/tmp/kunji-data.json`, unlock, click the "GitHub" row. Checklist:
- [ ] Detail view: name "GitHub", `github.com · alex`, chips `v1 / len 20 / standard / counter 1`.
- [ ] "Reveal" → shows a 20-char password grouped in fours, with all four character classes; after `revealSeconds` it re-masks on its own.
- [ ] "Copy" → button flashes "Copied"; paste elsewhere and confirm it matches the revealed value.
- [ ] Cross-check determinism: in a terminal run
  `node -e "import('./src/derive.js').then(async d=>{const mk=await d.deriveMasterKey('correct horse battery staple','alex@example.com');console.log(await d.derivePassword({masterKey:mk,site:'github.com',account:'alex',counter:1,rules:'standard',length:20}))})"`
  — it must equal the revealed value.
- [ ] Notes shows "personal". Recovery codes shows "· 0" and a dash. TOTP shows a dash.
- [ ] "‹ Vault" returns to the list.
- [ ] No console errors.

- [ ] **Step 4: Commit**

```bash
git add src/vault-ui.js
git commit -m "feat: vault tab — entry detail with derive/reveal/copy"
```

---

## Task 13: Vault tab — entry editor

**Files:**
- Modify: `src/vault-ui.js`
- Manual test: `dist/kunji.html` in a browser

- [ ] **Step 1: Replace `renderEditor` placeholder**

Replace `function renderEditor() { ... }` with:

```js
  function renderEditor() {
    const existing = selectedEntry(); // null when creating
    const e = existing || makeEntry({ type: 'password' });
    const isSso = e.type === 'sso';

    panel.innerHTML = `
      <div class="v-bar"><button class="link-btn" id="edCancel" type="button">&lsaquo; Cancel</button><button class="link-btn" id="edDone" type="button">Done</button></div>
      <div class="fields">
        <div class="field"><input id="edName" type="text" autocomplete="off" spellcheck="false" placeholder=" " value="${esc(e.name)}"><label for="edName">Name</label></div>
        <div class="field select-wrap">
          <select id="edType">
            <option value="password" ${isSso ? '' : 'selected'}>password</option>
            <option value="sso" ${isSso ? 'selected' : ''}>sso</option>
          </select>
          <label for="edType">Type</label>
        </div>
        <div class="field"><input id="edSite" type="text" autocomplete="off" spellcheck="false" placeholder=" " value="${esc(e.site)}"><label for="edSite">Site or app</label></div>
        <div class="field"><input id="edAccount" type="text" autocomplete="off" spellcheck="false" placeholder=" " value="${esc(e.account)}"><label for="edAccount">Account</label></div>
        <div id="edPwFields" ${isSso ? 'hidden' : ''}>
          <div class="v-editrow">
            <div class="field"><input id="edLength" type="text" inputmode="numeric" placeholder=" " value="${esc(e.length ?? 20)}"><label for="edLength">Length</label></div>
            <div class="field select-wrap">
              <select id="edRules">
                <option value="standard" ${e.rules === 'letters-digits' || e.rules === 'max-symbols' ? '' : 'selected'}>standard</option>
                <option value="letters-digits" ${e.rules === 'letters-digits' ? 'selected' : ''}>letters-digits</option>
                <option value="max-symbols" ${e.rules === 'max-symbols' ? 'selected' : ''}>max-symbols</option>
              </select>
              <label for="edRules">Rules</label>
            </div>
            <div class="field"><input id="edCounter" type="text" inputmode="numeric" placeholder=" " value="${esc(e.counter ?? 1)}"><label for="edCounter">Counter</label></div>
          </div>
          <div class="field"><input id="edTotp" type="text" autocomplete="off" spellcheck="false" placeholder=" " value="${esc(e.totp ?? '')}"><label for="edTotp">TOTP secret (optional)</label></div>
          <div class="field"><textarea id="edCodes" rows="3" placeholder=" ">${esc((e.recoveryCodes || []).join('\n'))}</textarea><label for="edCodes">Recovery codes (one per line)</label></div>
        </div>
        <div id="edSsoFields" ${isSso ? '' : 'hidden'}>
          <div class="field"><input id="edViaSite" type="text" autocomplete="off" spellcheck="false" placeholder=" " value="${esc(e.via && e.via.site)}"><label for="edViaSite">Log in via — site</label></div>
          <div class="field"><input id="edViaAccount" type="text" autocomplete="off" spellcheck="false" placeholder=" " value="${esc(e.via && e.via.account)}"><label for="edViaAccount">Log in via — account</label></div>
        </div>
        <div class="field"><textarea id="edNotes" rows="2" placeholder=" ">${esc(e.notes)}</textarea><label for="edNotes">Notes</label></div>
      </div>
      ${existing ? '<div class="v-center-link"><button class="link-btn v-danger" id="edDelete" type="button">Delete entry</button></div>' : ''}
      <div class="error" id="edError"></div>
    `;

    const typeSel = panel.querySelector('#edType');
    typeSel.addEventListener('change', () => {
      const sso = typeSel.value === 'sso';
      panel.querySelector('#edPwFields').hidden = sso;
      panel.querySelector('#edSsoFields').hidden = !sso;
    });

    panel.querySelector('#edCancel').addEventListener('click', () => {
      view = existing ? 'detail' : 'list'; render();
    });

    if (existing) panel.querySelector('#edDelete').addEventListener('click', () => {
      if (!confirm('Delete this entry?')) return;
      vault = removeEntry(vault, existing.id);
      markDirty();
      selectedId = null; view = 'list'; render();
    });

    panel.querySelector('#edDone').addEventListener('click', () => {
      const errEl = panel.querySelector('#edError');
      errEl.textContent = '';
      const type = typeSel.value;
      const name = panel.querySelector('#edName').value.trim();
      const site = panel.querySelector('#edSite').value.trim();
      const account = panel.querySelector('#edAccount').value.trim();
      if (!name || !site || !account) { errEl.textContent = 'Name, site, and account are required.'; return; }

      let patch;
      if (type === 'sso') {
        patch = {
          type: 'sso', name, site, account,
          via: {
            site: panel.querySelector('#edViaSite').value.trim(),
            account: panel.querySelector('#edViaAccount').value.trim(),
          },
          notes: panel.querySelector('#edNotes').value,
        };
      } else {
        const length = parseInt(panel.querySelector('#edLength').value, 10);
        const counter = parseInt(panel.querySelector('#edCounter').value, 10);
        if (!Number.isInteger(length) || length < 8 || length > 64) { errEl.textContent = 'Length must be a whole number from 8 to 64.'; return; }
        if (!Number.isInteger(counter) || counter < 1) { errEl.textContent = 'Counter must be a whole number of at least 1.'; return; }
        patch = {
          type: 'password', name, site, account,
          length, counter, rules: panel.querySelector('#edRules').value,
          profile: 'v1',
          totp: panel.querySelector('#edTotp').value.trim() || null,
          recoveryCodes: panel.querySelector('#edCodes').value.split('\n').map((s) => s.trim()).filter(Boolean),
          notes: panel.querySelector('#edNotes').value,
        };
      }

      const dup = vault.entries.find((x) => x.id !== (existing && existing.id)
        && x.site.toLowerCase() === site.toLowerCase()
        && x.account.toLowerCase() === account.toLowerCase());
      if (dup && !confirm('An entry for this site and account already exists. Save anyway?')) return;

      if (existing) {
        vault = updateEntry(vault, existing.id, patch);
        selectedId = existing.id;
        view = 'detail';
      } else {
        vault = addEntry(vault, patch);
        selectedId = vault.entries[vault.entries.length - 1].id;
        view = 'detail';
      }
      markDirty();
      render();
    });
  }
```

- [ ] **Step 2: Build + suite**

Run: `node tools/build.mjs && node tools/check-invariants.mjs && node --test`
Expected: build + invariants green (`<textarea>` is not a forbidden pattern); 83 tests green.

- [ ] **Step 3: Manual browser test**

Open `/tmp/kunji-data.json`, unlock. Checklist:
- [ ] Click "+ New" → editor with empty fields, Type = password, the Length/Rules/Counter row + TOTP + Recovery codes visible, no "Delete entry".
- [ ] Switch Type to "sso" → the password row and TOTP/codes hide; "Log in via" site + account appear.
- [ ] Switch back to "password". Fill Name "Router", Site "router.local", Account "admin", Length "12", Rules "letters-digits", Counter "1". Click "Done" → detail view for "Router", dirty bar now shows in the list.
- [ ] Open "Router" → "Edit" → change Length to "5" → "Done" → "Length must be a whole number from 8 to 64."
- [ ] Fix to "12", "Done". Back to list. "Vault · 2".
- [ ] Edit "GitHub", add two lines to Recovery codes, "Done", open detail → "Recovery codes · 2", "Reveal / copy" shows them.
- [ ] Edit "GitHub" → "Delete entry" → confirm → back to list, "Vault · 1".
- [ ] "Save vault" downloads; reopen that file, unlock, confirm the entries and the recovery codes survived the round-trip.
- [ ] No console errors.

- [ ] **Step 4: Commit**

```bash
git add src/vault-ui.js
git commit -m "feat: vault tab — entry editor (password + sso)"
```

---

## Task 14: Idle auto-lock

**Files:**
- Modify: `src/vault-ui.js`
- Manual test: `dist/kunji.html` in a browser

- [ ] **Step 1: Add the idle timer to `src/vault-ui.js`**

Add near the other `let` declarations at the top of `initVaultTab`:

```js
  let idleTimer = null;
```

Add these two functions (anywhere inside `initVaultTab`):

```js
  function clearIdle() { if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; } }

  function armIdle() {
    clearIdle();
    if (state !== 'UNLOCKED') return;
    const mins = (vault && vault.settings && vault.settings.autoLockMinutes) || 5;
    idleTimer = setTimeout(() => {
      // discard unsaved edits — the lock guarantee wins
      lock();
    }, mins * 60 * 1000);
  }
```

In `lock()`, call `clearIdle()` first. At the end of every `render*` path for `UNLOCKED` (simplest: at the top of `renderUnlocked`, before the `view` branching), call `armIdle()`. Also reset on interaction — add once, right after the `beforeunload` listener:

```js
  ['keydown', 'pointerdown'].forEach((evt) =>
    panel.addEventListener(evt, () => { if (state === 'UNLOCKED') armIdle(); }),
  );
```

Update `renderUnlocked`:

```js
  function renderUnlocked() {
    armIdle();
    if (view === 'detail') return renderDetail();
    if (view === 'editor') return renderEditor();
    return renderList();
  }
```

- [ ] **Step 2: Build + suite**

Run: `node tools/build.mjs && node tools/check-invariants.mjs && node --test`
Expected: build + invariants green; 83 tests green.

- [ ] **Step 3: Manual browser test (shortened timeout)**

Temporarily set the timeout short for the test: in the built page this reads `vault.settings.autoLockMinutes`. Instead of editing source, create a seed vault with a fractional value:
```bash
node -e "Promise.all([import('./src/vault.js'),import('./src/derive.js')]).then(async([v,d])=>{ const mk=await d.deriveMasterKey('p','i'); let vault=v.createVault(); vault.settings.autoLockMinutes=0.1; vault=v.addEntry(vault,{name:'X',site:'s',account:'a'}); require('fs').writeFileSync('/tmp/kunji-fast.json', await v.encodeEnvelope(vault,{masterKey:mk,writerId:'s'})); console.log('ok'); })"
```
Open the page, Vault tab, open `/tmp/kunji-fast.json`, unlock with identity `i` / passphrase `p`. Checklist:
- [ ] Wait ~6 seconds without touching the page → it returns to the LOCKED view on its own.
- [ ] Re-unlock. Now keep clicking/typing in the panel every few seconds for ~20s → it does NOT lock while you interact.
- [ ] Stop interacting → ~6s later it locks.
- [ ] Re-unlock, add an entry (don't save), wait for the idle lock → the unsaved entry is gone after re-unlock (expected — the lock discards unsaved edits).
- [ ] No console errors.

- [ ] **Step 4: Commit**

```bash
git add src/vault-ui.js
git commit -m "feat: vault tab — 5-minute idle auto-lock"
```

---

## Task 15: Docs, parent-spec sync, full verification

**Files:**
- Modify: `docs/specs/2026-09-01-kunji-design.md`
- Modify: `README.md`
- Modify: `package.json` (no change if `verify` already exists — confirm)

- [ ] **Step 1: Update parent spec section 12**

In `docs/specs/2026-09-01-kunji-design.md`, section 12, phase 2 bullet, change:

```
2. **Vault.** `kunji-data.json` read/write, AES-256-GCM, entry list, entry
   editor, the account picker, SSO entries, decoy section, import/export as
   encrypted file.
```

to:

```
2. **Vault.** `kunji-data.json` read/write, AES-256-GCM, entry list, entry
   editor, SSO entries, and the always-present random `decoy` envelope section
   (decoy *authoring* and the Generate-tab account picker move to Phase 3).
   Import is "open a file"; export is "save vault" (a download).
```

- [ ] **Step 2: Update `README.md`**

Change the Status section:

```markdown
## Status

Phase 2: the deterministic v1 generator (Phase 1) plus an optional encrypted
vault — `kunji-data.json`, AES-256-GCM, entry list / detail / editor, SSO
entries, 5-minute idle auto-lock — still shipped as a single file. Decoy
authoring, QR, and sync merge are Phase 3.
```

Add after the "## Test" section:

```markdown
## The vault

Open the Vault tab, create a vault or open a `kunji-data.json` file, unlock it
with the same identity + master passphrase that drives the generator. The file
is one AES-256-GCM blob; it holds no derived passwords, only entry parameters,
notes, TOTP secrets and recovery codes. "Save vault" downloads a fresh copy —
move it wherever your sync tool watches.
```

- [ ] **Step 3: Full verification**

Run: `npm run verify`
Expected: all test files pass — sanity 2, encoding 7, webcrypto 8, build 3, derive 32, vectors 8, app 2, vault 22 (**83 total**); `dist/kunji.html` written; `invariants ok`.

- [ ] **Step 4: Full manual browser regression**

`cd dist && python3 -m http.server 8801`, open `http://localhost:8801/kunji.html`. Run this end-to-end:
- [ ] Generate tab: identity + passphrase → KCV green; site + account → Generate → 20-char password; reveal, copy, length-7 error all work. (Phase 1 intact.)
- [ ] Vault tab → Create a new vault (identity + passphrase + confirm) → empty list.
- [ ] Add a `password` entry and an `sso` entry. Save vault (file downloads, one-time move note).
- [ ] Reload the page. Vault tab → Open the downloaded file → Unlock → both entries present.
- [ ] Open the password entry → Reveal → cross-check the value against a terminal `derivePassword` call with the same parameters → identical.
- [ ] Edit an entry, watch the dirty bar appear; Save; the bar clears.
- [ ] Tick "Prefill identity on devices that open this file", Save, reopen the downloaded file → the LOCKED view's Identity field is pre-filled; open the file in a text editor → `identityHint` holds the identity string. Untick, Save, reopen → `identityHint` is `null` again.
- [ ] Lock; re-unlock with just the passphrase.
- [ ] Delete an entry; Save; reopen; it stays deleted.
- [ ] Downloaded file: valid JSON, `format: "kunji-data"`, `v: 1`, `decoy` block present, `decoy.ct` length == `ct` length, `revision` incremented across saves.
- [ ] DevTools: no console errors, Network tab empty on reload.

- [ ] **Step 5: Commit**

```bash
git add docs/specs/2026-09-01-kunji-design.md README.md
git commit -m "docs: phase 2 vault — readme and parent-spec sync"
```

---

## Self-review

**Spec coverage (spec section in parentheses):**

- `deriveVaultKey` HKDF exact params (3.1) — Task 2.
- Envelope fields `format`/`v`/`kdf`/`identityHint`/`kcv`/`iv`/`ct`/`decoy`/`revision`/`lastWriter`/`updatedAt` (3.2) — Task 5 (`encodeEnvelope`), Task 6 (`parseEnvelope` validation).
- AES-256-GCM, 12-byte random IV per save, AAD `kunji-vault-v1` (3.2) — Task 1 wrappers, Task 5 usage.
- KCV gate then GCM-tag fallback (3.2, 6) — Task 6 `unlockVault`, Task 10 error mapping.
- `decoy` always written, random, length matched to real `ct` (3.2) — Task 3 `newDecoyBytes`, Task 5 call site, asserted in Task 5 tests.
- Decrypted plaintext `{entries, settings}` with `autoLockMinutes` (3.3) — Task 4 `createVault`, Task 6 `unlockVault` shape check.
- `password` and `sso` entry schemas, TOTP/codes stored-only (3.4) — Task 4 `makeEntry`, Task 12 detail (display only), Task 13 editor.
- `identityHint` off by default, plaintext, caveat (3.5) — Task 5 (`encodeEnvelope` writes it only when `currentIdentityForHint()` is non-null), Task 9/10 (`sessionIdentity` captured on create and unlock, `identityHintOn` seeded from the opened file), Task 11 (the "Prefill identity…" checkbox in the list footer with the "anyone with the file can read it" caveat, toggling `identityHintOn` and marking dirty).
- Scheme-lock tests: decrypt vector + `deriveVaultKey` vector + round-trip + wrong-pw + decoy presence (3.6) — Tasks 1, 2, 5, 6.
- State machine: NO_VAULT / CREATE / LOCKED / UNLOCKED, re-lock keeps file, idle resets on interaction, discard on idle-lock, `beforeunload` (4) — Tasks 9, 10, 11, 14.
- Save = plain download, one-time move note (4) — Task 11 `saveVault`.
- Tab strip, six views, reuse `.kcv` and palette (5) — Task 8 (shell), Tasks 9-13 (views).
- Reveal/copy on the same timers as Generate (5.2) — Task 12.
- Hygiene: secrets only in closure state, wiped on lock/`beforeunload`/manual (5.3) — Task 9 `wipe()`, Task 11 `lock()`, Task 14 idle, Task 11 `beforeunload`.
- Error table (6) — Task 6 typed errors; Tasks 9, 10, 11 map them to copy.
- Tests (7) — `tests/vault.test.mjs` across Tasks 3-6; `webcrypto`/`derive`/`build` extended in Tasks 1, 2, 7.
- Deferred items (8) — none implemented; parent spec §12 reworded in Task 15.

**Dirty tracking location:** spec §2's module table lists "dirty tracking" under `vault.js`. This plan keeps `vault.js` pure and puts the `dirty` boolean in `vault-ui.js` (set on create/add/update/remove, cleared on save). `vault.js` has no natural place to hold cross-call state without threading a "last saved" reference. This is a deliberate refinement, not a gap.

**Placeholder scan:** `__FILL_IN_STEP_4__` (Task 2) and `__FILL_VK__`/`__FILL_IV__`/`__FILL_CT__` (Task 6) are frozen-vector values the implementer generates with the exact command given in the same task's "Freeze" step, then pastes in — the Phase 1 plan used the same generate-then-freeze pattern (Task 11 there). No `TODO`/`TBD`/"handle edge cases" in any step. `renderLocked` / `renderUnlocked` / `renderDetail` / `renderEditor` are created as one-line placeholders in Task 9 and fully written in Tasks 10-13, each step showing the complete function body.

**Type/name consistency:** `encodeEnvelope(vault, { masterKey, identityHint, prevRevision, writerId })`, `parseEnvelope(text)`, `unlockVault(envelope, { masterKey })`, `createVault()`, `makeEntry`/`addEntry`/`updateEntry`/`removeEntry`, `newDecoyBytes(ctLen)`, `randomBytes(n)`, `deriveVaultKey(masterKey)`, `aesGcmEncrypt`/`aesGcmDecrypt(key, iv, data, aad)` are named identically everywhere they appear (Tasks 1-6 code, tests, and the vault-ui call sites in Tasks 9-14). Error class names `BadEnvelopeError` / `WrongPassphraseError` / `CorruptVaultError` match between `vault.js` (Task 3), the `unlockVault` throws (Task 6), and the `e.name` checks in `vault-ui.js` (Tasks 9, 10). Envelope constants `VAULT_FORMAT` = `'kunji-data'`, `VAULT_V` = `1`, `VAULT_AAD` = `utf8('kunji-vault-v1')` match spec §3.2 and Task 1's test AAD.

**Scope:** Phase 2 only. New crypto wrappers, one new pure module, one new UI module, an `app.js` refactor that preserves every Phase 1 DOM id and derivation call, styles, and tests. No decoy authoring, no account picker, no sync, no QR, no service worker. Produces a working, testable single file at every task boundary.
