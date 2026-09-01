# Kunji Phase 5 — Profile Seam, Live TOTP, Passkey Unlock Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** (1) route master-key derivation through a `PROFILES` registry so a future `v2` KDF is a one-object drop-in, and freeze v1's last two open parameters; (2) generate live TOTP codes from the `totp` secrets the vault already stores; (3) let a device unlock a vault with a WebAuthn passkey instead of the master passphrase.

**Architecture:** Three independent additive slices. **Part 1** adds `PROFILES`/`profileOf`/`DEFAULT_PROFILE` to `src/derive.js`; `deriveMasterKey` and `derivePassword` route through it; the frozen v1 vectors reproduce byte-for-byte. **Part 2** adds pure `src/totp.js` (base32 + RFC 4226 truncation; HMAC via `crypto.subtle`), a `normaliseTotp` folder in `src/vault.js`, and a live-code + countdown block in the entry detail view. **Part 3** adds `src/webauthn.js` (`navigator.credentials` + PRF wrapper), `src/passkey-store.js` (`localStorage` CRUD), `wrapMasterKey`/`unwrapMasterKey` in `src/vault.js`, and an "unlock with passkey" path on the LOCKED screen — PWA-only, and amends spec §10 to permit the one device-local wrapped-key exception. No `format`/`v` bump; `check-invariants` and the CSP are unchanged (WebAuthn and `localStorage` are not network APIs).

**Tech Stack:** Node ≥ 20 ESM, browser `crypto.subtle` (HMAC-SHA1/256/512, HKDF, AES-GCM, PBKDF2) + `navigator.credentials` (PRF) + `localStorage`, plain HTML/CSS/JS, zero runtime dependencies. Build is concatenation via `tools/build.mjs`.

**Specs:**
- `docs/specs/2026-09-01-kunji-phase5a-profile-seam-design.md`
- `docs/specs/2026-09-01-kunji-phase5bc-passkey-and-totp-design.md`
- Parent: `docs/specs/2026-09-01-kunji-design.md` §4.3, §4.4, §5.2, §10, §11, §13.
- **RFC references (Part 2):** RFC 4648 §6 (base32), RFC 4226 (HOTP; Appendix D vectors), RFC 6238 (TOTP; Appendix B vectors).

**Baseline:** Phases 1–4 on `main` (commit `e7cbc42` or later). `npm test` = `node --test --test-concurrency=1`, currently 166 tests, `fail 0`. `npm run verify` = tests + build + invariant scan (`invariants ok (17 files)`).

Work from `the repository root`, directly on `main`, one commit per task. Trailers:

```
Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
```

Use `git -c commit.gpgsign=false commit` if signing prompts. **`fail 0` is the gate.** The frozen v1 vectors (`tests/vectors/v1.json`) must reproduce unchanged through every task in Part 1.

---

## File structure

| File | Change | Part |
|---|---|---|
| `src/derive.js` | + `PROFILES` / `profileOf` / `DEFAULT_PROFILE`; `deriveMasterKey` routes through it (drops `iterations` arg); `derivePassword` reads `params.profile`; freeze comments | 1 |
| `src/vault.js` | + `parseEnvelope` KDF-tag check (1); + `normaliseTotp` (2); + `wrapMasterKey` / `unwrapMasterKey` (3); `makeEntry` totp via `normaliseTotp` (2) | 1,2,3 |
| `src/encoding.js` | + `uint64be` | 2 |
| `src/webcrypto.js` | + `hmac(algorithm, key, msg)`; `hmacSha256` becomes a thin wrapper | 2 |
| `src/totp.js` | **new** — `base32Decode`, `hotp`, `totp`, `parseOtpauth` | 2 |
| `src/webauthn.js` | **new** — `isPasskeySupported`, `registerPasskey`, `getPasskeySecret` | 3 |
| `src/passkey-store.js` | **new** — `hasPasskey` / `loadPasskey` / `savePasskey` / `removePasskey` | 3 |
| `src/vault-ui.js` | detail: live TOTP code + countdown; editor: `otpauth://` parse (2). LOCKED: "unlock with passkey"; footer: set-up / remove passkey (3) | 2,3 |
| `src/style.css` | `.v-totp-code` / `.v-totp-bar` | 2 |
| `tools/build.mjs` | `JS_ORDER` += `src/totp.js` (2), `src/webauthn.js` + `src/passkey-store.js` (3) | 2,3 |
| `docs/specs/2026-09-01-kunji-design.md` | §4.3 / §4.4 / §13 (1); §5.2 (2); §10 / §11 (3) | 1,2,3 |
| `docs/specs/2026-09-01-kunji-v2-profile-requirements.md` | **new** | 1 |
| `README.md` | "live 2FA codes" (2); "unlock with a passkey (PWA only)" (3) | 2,3 |
| `tests/*` | new/extended per task | — |

`check-invariants.mjs` scans `src/*` + `dist/kunji.html` for `fetch(`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, `<script src>`, `<link>`, `@import`, `https?://`. None of the new code uses any of these. `navigator.credentials`, `localStorage`, `crypto.subtle` are not on the list. No invariant change; the file count rises (17 → 20).

**Execution order:** Part 1 → Part 2 → Part 3 (per spec §X2: TOTP before passkey; the seam is independent and goes first).

---

# PART 1 — Profile seam & v1 freeze (Tasks S1–S5)

## Task S1: `PROFILES` registry

**Files:**
- Modify: `src/derive.js`
- Test: `tests/derive.test.mjs` (append)

- [ ] **Step 1: Append the failing tests to `tests/derive.test.mjs`**

```js
import { PROFILES, profileOf, DEFAULT_PROFILE } from '../src/derive.js';

test('PROFILES has exactly v1 and DEFAULT_PROFILE points to it', () => {
  assert.deepEqual(Object.keys(PROFILES), ['v1']);
  assert.equal(DEFAULT_PROFILE, 'v1');
  assert.equal(PROFILES.v1.id, 'v1');
  assert.equal(PROFILES.v1.kdfTag, 'pbkdf2-sha512-600000');
  assert.equal(typeof PROFILES.v1.deriveMasterKey, 'function');
});

test('profileOf returns the profile or throws on an unknown id', () => {
  assert.equal(profileOf('v1').id, 'v1');
  assert.throws(() => profileOf('v2'), /unknown profile: v2/);
  assert.throws(() => profileOf(''), /unknown profile:/);
});

test('PROFILES.v1.deriveMasterKey matches raw PBKDF2 for a known input', async () => {
  const { pbkdf2Sha512 } = await import('../src/webcrypto.js');
  const { utf8 } = await import('../src/encoding.js');
  const got = await PROFILES.v1.deriveMasterKey('pw', 'alex@example.com');
  const want = await pbkdf2Sha512(utf8('pw'), utf8('alex@example.com'), 600000, 32);
  assert.deepEqual(got, want);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/derive.test.mjs`
Expected: FAIL — `PROFILES` / `profileOf` / `DEFAULT_PROFILE` not exported.

- [ ] **Step 3: Add the registry to `src/derive.js`**

Immediately after the `PBKDF2_ITERATIONS` declaration (currently line ~7), add:

```js
// --- Profile registry -----------------------------------------------------
// Every master-key derivation routes through a profile so a future KDF (v2)
// is a one-object drop-in. See docs/specs/2026-09-01-kunji-v2-profile-requirements.md.

export const PROFILES = {
  v1: {
    id: 'v1',
    label: 'PBKDF2-HMAC-SHA512',
    // passphrase: raw string; normalisedIdentity: already NFKC+trim+lowercase
    deriveMasterKey: (passphrase, normalisedIdentity) =>
      pbkdf2Sha512(utf8(passphrase), utf8(normalisedIdentity), PBKDF2_ITERATIONS, MASTER_KEY_BYTES),
    kdfTag: `pbkdf2-sha512-${PBKDF2_ITERATIONS}`,
  },
};

export const DEFAULT_PROFILE = 'v1';

export function profileOf(id) {
  const p = PROFILES[id];
  if (!p) throw new Error(`unknown profile: ${id}`);
  return p;
}
```

`MASTER_KEY_BYTES` (= 32) and `PBKDF2_ITERATIONS` are already declared above this
point; `pbkdf2Sha512` and `utf8` are already imported.

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/derive.test.mjs` — PASS.
Run: `npm test` — `fail 0` (169 total: 166 + 3).
Run: `node tools/build.mjs && node tools/check-invariants.mjs` — `invariants ok (17 files)`.

- [ ] **Step 5: Commit**

```bash
git add src/derive.js tests/derive.test.mjs
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: PROFILES registry in derive.js (v1 the only entry)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Task S2: `deriveMasterKey` routes through the registry

**Files:**
- Modify: `src/derive.js`
- Modify: `tests/derive.test.mjs` (one call site)
- Modify: `tests/vectors.test.mjs` (two call sites)
- Test: `tests/derive.test.mjs` (append equivalence test)

- [ ] **Step 1: Append the equivalence test to `tests/derive.test.mjs`**

```js
test('deriveMasterKey(pw,id) == deriveMasterKey(pw,id,"v1") and normalises identity', async () => {
  const a = await deriveMasterKey('correct horse', 'ALEX@EXAMPLE.com ');
  const b = await deriveMasterKey('correct horse', 'ALEX@EXAMPLE.com ', 'v1');
  assert.deepEqual(a, b);
  const { pbkdf2Sha512 } = await import('../src/webcrypto.js');
  const { utf8 } = await import('../src/encoding.js');
  const want = await pbkdf2Sha512(utf8('correct horse'), utf8('alex@example.com'), 600000, 32);
  assert.deepEqual(a, want);
});

test('deriveMasterKey rejects an unknown profile', async () => {
  await assert.rejects(() => deriveMasterKey('pw', 'id', 'v2'), /unknown profile: v2/);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/derive.test.mjs`
Expected: the unknown-profile test FAILS (3rd arg is still an iteration count, so `'v2'` → `NaN` iterations → a thrown/rejected error but not the expected message; or it silently misbehaves).

- [ ] **Step 3: Rewrite `deriveMasterKey` in `src/derive.js`**

Replace:

```js
export async function deriveMasterKey(passphrase, identity, iterations = PBKDF2_ITERATIONS) {
  return pbkdf2Sha512(
    utf8(passphrase), utf8(normaliseInput(identity)), iterations, MASTER_KEY_BYTES,
  );
}
```

with:

```js
export async function deriveMasterKey(passphrase, identity, profile = DEFAULT_PROFILE) {
  return profileOf(profile).deriveMasterKey(passphrase, normaliseInput(identity));
}
```

- [ ] **Step 4: Migrate the three test call sites that pass a 3rd argument**

`tests/derive.test.mjs` line ~217 — currently:
```js
  const mk = await deriveMasterKey('correct horse battery staple', '  ALEX@example.com ', 1000);
```
This test measures behaviour at low cost. Replace with a direct PBKDF2 call:
```js
  const { pbkdf2Sha512 } = await import('../src/webcrypto.js');
  const { utf8 } = await import('../src/encoding.js');
  const mk = await pbkdf2Sha512(utf8('correct horse battery staple'), utf8(normaliseInput('  ALEX@example.com ')), 1000, 32);
```
(add `normaliseInput` to the existing `../src/derive.js` import in that file if not already there — it is exported).

`tests/vectors.test.mjs` line ~19 (the `highCost` vector) — currently:
```js
  const mk = await deriveMasterKey(h.input.passphrase, h.input.identity, h.iterations);
```
`h.iterations` is the frozen 600000, i.e. `PBKDF2_ITERATIONS`. Drop the 3rd arg:
```js
  const mk = await deriveMasterKey(h.input.passphrase, h.input.identity);
```
The surrounding assertion `assert.equal(h.iterations, PBKDF2_ITERATIONS, …)` stays — it still guards the freeze.

`tests/vectors.test.mjs` line ~31 (the low-cost `cases` loop, `vectors.iterations = 1000`) — currently:
```js
    const mk = await deriveMasterKey(v.input.passphrase, v.input.identity, vectors.iterations);
```
Replace with a direct PBKDF2 call so the vectors keep their 1000-iteration speed without a fake profile:
```js
    const mk = await pbkdf2Sha512(_utf8(v.input.passphrase), _utf8(normaliseInput(v.input.identity)), vectors.iterations, 32);
```
Add to the top of `tests/vectors.test.mjs`:
```js
import { pbkdf2Sha512 } from '../src/webcrypto.js';
import { utf8 as _utf8 } from '../src/encoding.js';
import { normaliseInput } from '../src/derive.js';
```
(`normaliseInput` may already be importable via the existing `../src/derive.js` line — extend it rather than adding a second import.)

- [ ] **Step 5: Run to verify everything passes**

Run: `node --test tests/vectors.test.mjs` — PASS, every v1 vector reproduces (master key hex, kcv, password all unchanged).
Run: `node --test tests/derive.test.mjs` — PASS.
Run: `npm test` — `fail 0` (171).
Run: `node tools/build.mjs && node tools/check-invariants.mjs` — green.

- [ ] **Step 6: Commit**

```bash
git add src/derive.js tests/derive.test.mjs tests/vectors.test.mjs
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: deriveMasterKey routes through PROFILES; drop the iterations arg

The v1 iteration count is now a property of the v1 profile, not a caller
knob. Speed-sensitive test call sites move to a direct pbkdf2Sha512 call.
Frozen v1 vectors reproduce unchanged.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Task S3: `derivePassword` profile dispatch

**Files:**
- Modify: `src/derive.js`
- Test: `tests/derive.test.mjs` (append)

- [ ] **Step 1: Append the failing tests**

```js
test('derivePassword with no profile == profile "v1"', async () => {
  const input = { identity: 'alex@example.com', passphrase: 'correct horse battery staple',
    site: 'github.com', account: 'alex', counter: 1, rules: 'standard', length: 20 };
  const a = await derivePassword({ ...input });
  const b = await derivePassword({ ...input, profile: 'v1' });
  assert.equal(a, b);
  assert.equal(a.length, 20);
});

test('derivePassword rejects an unknown profile', async () => {
  await assert.rejects(
    () => derivePassword({ identity: 'x', passphrase: 'y', site: 's', account: 'a', profile: 'v2' }),
    /unknown profile: v2/,
  );
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/derive.test.mjs`
Expected: the unknown-profile test FAILS (`profile` is ignored today; the call succeeds).

- [ ] **Step 3: Edit `derivePassword` in `src/derive.js`**

Find the master-key block:

```js
  const masterKey = params.masterKey
    ? params.masterKey
    : await deriveMasterKey(
        params.passphrase,
        normaliseInput(params.identity ?? ''),
        params.iterations ?? PBKDF2_ITERATIONS,
      );
```

Replace with:

```js
  const profile = params.profile ?? DEFAULT_PROFILE;
  const masterKey = params.masterKey
    ? params.masterKey
    : await deriveMasterKey(params.passphrase, params.identity ?? '', profile);
```

(`deriveMasterKey` now normalises `identity` itself; the `params.iterations`
escape hatch is removed — nothing in `src/` passed it, and `derivePassword`'s own
signature never documented it.)

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/derive.test.mjs` — PASS.
Run: `node --test tests/vectors.test.mjs` — PASS (unchanged).
Run: `npm test` — `fail 0` (173).
Run: `node tools/build.mjs && node tools/check-invariants.mjs` — green.

- [ ] **Step 5: Commit**

```bash
git add src/derive.js tests/derive.test.mjs
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: derivePassword dispatches the master-key step on params.profile

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Task S4: Vault envelope KDF-tag validation

**Files:**
- Modify: `src/vault.js`
- Test: `tests/vault.test.mjs` (append)

- [ ] **Step 1: Inspect the current envelope KDF field**

Run: `grep -n "kdf" src/vault.js`
`encodeEnvelope` writes `kdf: \`pbkdf2-sha512-${PBKDF2_ITERATIONS}\`` (imported
from `./derive.js`). `parseEnvelope` currently does not validate it.

- [ ] **Step 2: Append the failing tests to `tests/vault.test.mjs`**

```js
import { PROFILES } from '../src/derive.js';

test('encodeEnvelope stamps the v1 profile kdf tag', async () => {
  const v = addEntry(createVault(), { name: 'A', site: 's', account: 'a' });
  const env = JSON.parse(await encodeEnvelope(v, { masterKey: MK, writerId: 'w' }));
  assert.equal(env.kdf, PROFILES.v1.kdfTag);
});

test('parseEnvelope rejects a header with an unknown kdf', async () => {
  const v = addEntry(createVault(), { name: 'A', site: 's', account: 'a' });
  const env = JSON.parse(await encodeEnvelope(v, { masterKey: MK, writerId: 'w' }));
  env.kdf = 'argon2id-m65536-t3-p1';
  assert.throws(() => parseEnvelope(JSON.stringify(env)), /unknown KDF/);
});

test('parseEnvelope still accepts the current pbkdf2 tag', async () => {
  const v = addEntry(createVault(), { name: 'A', site: 's', account: 'a' });
  const text = await encodeEnvelope(v, { masterKey: MK, writerId: 'w' });
  assert.doesNotThrow(() => parseEnvelope(text));
});
```

(`MK` is the module-level test master key already defined in `tests/vault.test.mjs`.)

- [ ] **Step 3: Run to verify it fails**

Run: `node --test tests/vault.test.mjs`
Expected: the "unknown kdf" test FAILS (no validation yet).

- [ ] **Step 4: Add the check to `parseEnvelope` in `src/vault.js`**

At the top of `src/vault.js`, ensure the import from `./derive.js` includes the
registry (extend the existing import line):

```js
import { PROFILES } from './derive.js';
```

(If `src/vault.js` has no `./derive.js` import yet, add it — but check first; it
may already import `deriveVaultKey` / `computeKcv`. Extend that line.)

In `parseEnvelope`, after the existing shape checks (format, `v`, presence of
`kcv`/`iv`/`ct`) and before returning, add:

```js
  const known = Object.values(PROFILES).some((p) => p.kdfTag === env.kdf);
  if (!known) throw new BadEnvelopeError(`unknown KDF: ${env.kdf}`);
```

Place it where the other `throw new BadEnvelopeError(...)` validations live so the
error type and flow match.

- [ ] **Step 5: Run to verify it passes**

Run: `node --test tests/vault.test.mjs` — PASS.
Run: `npm test` — `fail 0` (176).
Run: `node tools/build.mjs && node tools/check-invariants.mjs` — green.

- [ ] **Step 6: Manual smoke (browser)**

`node tools/build.mjs`, serve `dist/`, create a vault, add an entry, Save, reopen
the file, unlock — still works (the `kdf` tag round-trips). Open the saved JSON in
an editor, change `"kdf"` to `"nope"`, reopen — Kunji shows
"That does not look like a Kunji vault file." (the `BadEnvelopeError` path).

- [ ] **Step 7: Commit**

```bash
git add src/vault.js tests/vault.test.mjs
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: parseEnvelope rejects a header whose kdf is not a known profile

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Task S5: Freeze v1 + docs

**Files:**
- Modify: `src/derive.js` (comments only)
- Modify: `docs/specs/2026-09-01-kunji-design.md`
- Create: `docs/specs/2026-09-01-kunji-v2-profile-requirements.md`

- [ ] **Step 1: `src/derive.js` freeze comments**

Replace:
```js
// OPEN DECISION (spec s13): confirm on the slowest target device before freezing v1.
export const PBKDF2_ITERATIONS = 600000;
```
with:
```js
// FROZEN as part of the v1 profile. Never change in place — a different cost is
// a different profile (see PROFILES and
// docs/specs/2026-09-01-kunji-v2-profile-requirements.md).
export const PBKDF2_ITERATIONS = 600000;
```

Above the `CHARSETS` declaration, add:
```js
// FROZEN for v1. `max-symbols` deliberately includes brackets and punctuation
// that some sites reject — that is the point of the preset; `standard` is the
// safe default.
```

- [ ] **Step 2: `docs/specs/2026-09-01-kunji-design.md` edits**

**§4.3** — after the `max-symbols` charset line, add:
```
These three sets are final for v1. `max-symbols` deliberately includes brackets
and punctuation that some sites reject; that is the point of the preset, and
`standard` is the safe default.
```

**§4.4** — in Step 1, replace the sentence about `v2` cost parameters with:
```
The PBKDF2 iteration count for v1 is frozen at 600000 (see the `PROFILES`
registry in `src/derive.js`). A future `v2` profile registers its own KDF —
contract in `docs/specs/2026-09-01-kunji-v2-profile-requirements.md`.
```

**§13** — delete the "v1 KDF cost" bullet and the "`max-symbols` character set"
bullet; in their place add:
```
- **Resolved in Phase 5a.** PBKDF2-600000 and the three character sets are frozen
  as v1. Future cost/primitive changes ship as a new profile.
```
Leave the "shared family master" and "`identityHint` default" bullets.

- [ ] **Step 3: Create `docs/specs/2026-09-01-kunji-v2-profile-requirements.md`**

```markdown
# v2 profile — requirements

A future `v2` KDF profile must meet this contract before it can be registered in
`PROFILES` (`src/derive.js`).

## Interface

    deriveMasterKey(passphrase: string, normalisedIdentity: string)
      -> Promise<Uint8Array(32)>

Deterministic. `normalisedIdentity` is already NFKC + trim + lowercase (the
registry wrapper applies `normaliseInput`). No salt input beyond the identity; no
cost knobs in the signature — cost is baked into the profile object.

## Primitive

Memory-hard. Argon2id (RFC 9106) preferred; scrypt (RFC 7914) acceptable; a
browser-native Argon2 if one ships in `crypto.subtle`. Pure JavaScript, zero
dependencies. WASM only if `tools/check-invariants.mjs` and the CSP still pass —
today they would not, so effectively pure JS.

## CI gate

Every applicable RFC test vector passes (a committed `tests/vectors/v2.json` in
the same shape as `v1.json`, plus the primitive's own KAT file). Output drift
fails the vector test exactly as a v1 change does.

## Cost target

<= ~1.5 s for one derivation on the slowest supported device (an older Android
tablet). `p = 1` — JavaScript is single-threaded.

## Registration

One object added to `PROFILES`: `{ id, label, deriveMasterKey, kdfTag }` with a
unique `kdfTag` (e.g. `argon2id-m65536-t3-p1`). No change to `src/derive.js`
Steps 2–6 (HKDF entry seed, HMAC keystream, rejection sampling, class
enforcement — all SHA-256, profile-agnostic).

## Migration

Per entry: set `entry.profile = 'v2'`, re-derive, change the password at the
site. A whole-vault re-key (re-encrypt the envelope under a v2 master key, new
`kdf` tag) is a separate explicit action. Never automatic, never global. A vault
may hold v1 and v2 entries simultaneously; the envelope stays on its original
profile until an explicit re-key.
```

- [ ] **Step 4: Verify nothing regressed**

Run: `npm run verify` — `fail 0`; `dist/kunji.html written`; `dist/pwa/ written`;
`invariants ok (17 files)`. `git status --porcelain` shows only the three files.

- [ ] **Step 5: Commit**

```bash
git add src/derive.js docs/specs/2026-09-01-kunji-design.md docs/specs/2026-09-01-kunji-v2-profile-requirements.md
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
docs: freeze v1 (PBKDF2-600000, charsets); v2 profile requirements

Closes the two remaining spec §13 open decisions.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

# PART 2 — Live TOTP (Tasks T1–T6)

## Task T1: `uint64be` + generalised `hmac`

**Files:**
- Modify: `src/encoding.js`
- Modify: `src/webcrypto.js`
- Test: `tests/encoding.test.mjs` (append), `tests/webcrypto.test.mjs` (append)

- [ ] **Step 1: Append the failing tests**

To `tests/encoding.test.mjs`:
```js
import { uint64be } from '../src/encoding.js';

test('uint64be is 8 big-endian bytes', () => {
  assert.deepEqual([...uint64be(0)], [0, 0, 0, 0, 0, 0, 0, 0]);
  assert.deepEqual([...uint64be(1)], [0, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual([...uint64be(0x0102030405)], [0, 0, 0, 1, 2, 3, 4, 5]);
  assert.deepEqual([...uint64be(0xffffffff)], [0, 0, 0, 0, 255, 255, 255, 255]);
});
```

To `tests/webcrypto.test.mjs`:
```js
import { hmac, hmacSha256 } from '../src/webcrypto.js';
import { createHmac } from 'node:crypto';

test('hmac(SHA-1) matches node:crypto', async () => {
  const key = new Uint8Array([1, 2, 3, 4]);
  const msg = new Uint8Array([9, 9, 9]);
  const got = await hmac('SHA-1', key, msg);
  const want = new Uint8Array(createHmac('sha1', Buffer.from(key)).update(Buffer.from(msg)).digest());
  assert.deepEqual(got, want);
});

test('hmac(SHA-256) still equals hmacSha256', async () => {
  const key = new Uint8Array([5, 6, 7]);
  const msg = new Uint8Array([1, 1, 1, 1]);
  assert.deepEqual(await hmac('SHA-256', key, msg), await hmacSha256(key, msg));
});

test('hmac(SHA-512) matches node:crypto', async () => {
  const got = await hmac('SHA-512', new Uint8Array([1]), new Uint8Array([2]));
  const want = new Uint8Array(createHmac('sha512', Buffer.from([1])).update(Buffer.from([2])).digest());
  assert.deepEqual(got, want);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/encoding.test.mjs tests/webcrypto.test.mjs`
Expected: FAIL — `uint64be` / `hmac` not exported.

- [ ] **Step 3: Add `uint64be` to `src/encoding.js`**

After `uint32be`:
```js
export function uint64be(n) {
  const b = new Uint8Array(8);
  // n is a JS number; safe for TOTP counters (< 2^53). High 32 bits via division.
  let hi = Math.floor(n / 0x100000000);
  let lo = n >>> 0;
  for (let i = 3; i >= 0; i--) { b[i] = hi & 0xff; hi >>>= 8; }
  for (let i = 7; i >= 4; i--) { b[i] = lo & 0xff; lo >>>= 8; }
  return b;
}
```

- [ ] **Step 4: Generalise `hmac` in `src/webcrypto.js`**

Replace `hmacSha256`:
```js
export async function hmacSha256(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, msgBytes);
  return new Uint8Array(sig);
}
```
with:
```js
// algorithm: 'SHA-1' | 'SHA-256' | 'SHA-512'
export async function hmac(algorithm, keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: algorithm }, false, ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, msgBytes);
  return new Uint8Array(sig);
}

export const hmacSha256 = (keyBytes, msgBytes) => hmac('SHA-256', keyBytes, msgBytes);
```

The derivation pipeline and vault code call `hmacSha256` unchanged.

- [ ] **Step 5: Run to verify it passes**

Run: `node --test tests/encoding.test.mjs tests/webcrypto.test.mjs` — PASS.
Run: `node --test tests/vectors.test.mjs` — PASS (the HMAC-SHA256 keystream is
untouched; the frozen passwords reproduce).
Run: `npm test` — `fail 0` (182).
Run: `node tools/build.mjs && node tools/check-invariants.mjs` — green.

- [ ] **Step 6: Commit**

```bash
git add src/encoding.js src/webcrypto.js tests/encoding.test.mjs tests/webcrypto.test.mjs
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: uint64be encoder; generalise hmac to SHA-1/256/512

hmacSha256 becomes a thin wrapper so the frozen derivation vectors are
untouched.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Task T2: `src/totp.js` — base32 + HOTP

**Files:**
- Create: `src/totp.js`
- Modify: `tools/build.mjs` (`JS_ORDER`)
- Test: `tests/totp.test.mjs` (new), `tests/build.test.mjs` (append)

- [ ] **Step 1: Write `tests/totp.test.mjs`**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { base32Decode, hotp } from '../src/totp.js';

const td = (u8) => Buffer.from(u8).toString('latin1');

test('base32Decode: RFC 4648 examples', () => {
  assert.equal(td(base32Decode('MY======')), 'f');
  assert.equal(td(base32Decode('MZXW6===')), 'foo');
  assert.equal(td(base32Decode('MZXW6YTBOI======')), 'foobar');
});

test('base32Decode: case-insensitive, tolerates spaces and missing padding', () => {
  assert.equal(td(base32Decode('mzxw6ytboi')), 'foobar');
  assert.equal(td(base32Decode('MZXW 6YTB OI')), 'foobar');
});

test('base32Decode: throws on a non-alphabet char', () => {
  assert.throws(() => base32Decode('MZXW0YTB'));   // 0 and 1 are not in base32
  assert.throws(() => base32Decode('abc!def'));
});

test('hotp: RFC 4226 Appendix D vectors (secret "12345678901234567890")', async () => {
  const key = new TextEncoder().encode('12345678901234567890');
  const expected = ['755224','287082','359152','969429','338314','254676','287922','162583','399871','520489'];
  for (let c = 0; c < 10; c++) {
    assert.equal(await hotp(key, c, { algorithm: 'SHA-1', digits: 6 }), expected[c], `counter ${c}`);
  }
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/totp.test.mjs` — FAIL (module missing).

- [ ] **Step 3: Create `src/totp.js`**

```js
import { uint64be } from './encoding.js';
import { hmac } from './webcrypto.js';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// RFC 4648 base32, case-insensitive; strips spaces and '=' padding.
// Throws on any non-alphabet character.
export function base32Decode(str) {
  const clean = String(str).replace(/[\s=]/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error(`base32Decode: invalid character ${JSON.stringify(ch)}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

// RFC 4226. counter: integer >= 0. algorithm: 'SHA-1'|'SHA-256'|'SHA-512'.
export async function hotp(keyBytes, counter, { algorithm = 'SHA-1', digits = 6 } = {}) {
  const mac = await hmac(algorithm, keyBytes, uint64be(counter));
  const offset = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[offset] & 0x7f) << 24)
    | (mac[offset + 1] << 16)
    | (mac[offset + 2] << 8)
    | mac[offset + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}
```

- [ ] **Step 4: Wire into `JS_ORDER` and add the build test**

`tools/build.mjs` — add `'src/totp.js'` to `JS_ORDER` after `'src/webcrypto.js'`
and before `'src/qr.js'`:
```js
const JS_ORDER = [
  'src/encoding.js',
  'src/webcrypto.js',
  'src/totp.js',
  'src/qr.js',
  ...
];
```

Append to `tests/build.test.mjs`:
```js
test('built html inlines src/totp.js after webcrypto.js and before vault.js', () => {
  execFileSync('node', ['tools/build.mjs'], { stdio: 'pipe' });
  const html = readFileSync('dist/kunji.html', 'utf8');
  assert.ok(html.includes('==== src/totp.js ===='), 'totp.js concatenated');
  assert.ok(html.indexOf('src/webcrypto.js') < html.indexOf('src/totp.js'));
  assert.ok(html.indexOf('src/totp.js') < html.indexOf('src/vault.js'));
});
```

- [ ] **Step 5: Run to verify it passes**

Run: `node --test tests/totp.test.mjs tests/build.test.mjs` — PASS.
Run: `npm test` — `fail 0` (186).
Run: `node tools/build.mjs && node tools/check-invariants.mjs` — `invariants ok (18 files)`.

- [ ] **Step 6: Commit**

```bash
git add src/totp.js tools/build.mjs tests/totp.test.mjs tests/build.test.mjs
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: src/totp.js — base32 decode + RFC 4226 HOTP

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Task T3: `totp()` + `parseOtpauth()`

**Files:**
- Modify: `src/totp.js`
- Test: `tests/totp.test.mjs` (append)

- [ ] **Step 1: Append the failing tests**

```js
import { totp, parseOtpauth } from '../src/totp.js';

// RFC 6238 Appendix B. 8 digits. Seeds are the ASCII "12345678901234567890"
// repeated/truncated to the hash block size.
const SEED_SHA1 = '12345678901234567890';
const SEED_SHA256 = '12345678901234567890123456789012';
const SEED_SHA512 = '1234567890123456789012345678901234567890123456789012345678901234';
const b32 = (ascii) => {
  // encode ASCII -> base32 for the totp() secret input
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes = new TextEncoder().encode(ascii);
  let bits = 0, val = 0, out = '';
  for (const byte of bytes) { val = (val << 8) | byte; bits += 8;
    while (bits >= 5) { bits -= 5; out += A[(val >>> bits) & 31]; } }
  if (bits > 0) out += A[(val << (5 - bits)) & 31];
  return out;
};

const RFC6238 = [
  [59,          '94287082', 'SHA-1',   SEED_SHA1],
  [1111111109,  '07081804', 'SHA-1',   SEED_SHA1],
  [1234567890,  '89005924', 'SHA-1',   SEED_SHA1],
  [2000000000,  '69279037', 'SHA-1',   SEED_SHA1],
  [59,          '46119246', 'SHA-256', SEED_SHA256],
  [1111111109,  '68084774', 'SHA-256', SEED_SHA256],
  [59,          '90693936', 'SHA-512', SEED_SHA512],
  [1234567890,  '93441116', 'SHA-512', SEED_SHA512],
];

for (const [t, code, algorithm, seed] of RFC6238) {
  test(`totp: RFC 6238 ${algorithm} @ ${t}`, async () => {
    const r = await totp({ secret: b32(seed), algorithm, digits: 8, period: 30 }, { now: t * 1000 });
    assert.equal(r.code, code);
    assert.equal(r.period, 30);
  });
}

test('totp: secondsRemaining is period at a boundary and 1 just before', async () => {
  const o = { secret: b32(SEED_SHA1), algorithm: 'SHA-1', digits: 6, period: 30 };
  assert.equal((await totp(o, { now: 30_000 })).secondsRemaining, 30);
  assert.equal((await totp(o, { now: 29_000 })).secondsRemaining, 1);
});

test('parseOtpauth: full URI -> fields', () => {
  const r = parseOtpauth('otpauth://totp/ACME:alice@acme.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA256&digits=8&period=60');
  assert.equal(r.secret, 'JBSWY3DPEHPK3PXP');
  assert.equal(r.algorithm, 'SHA-256');
  assert.equal(r.digits, 8);
  assert.equal(r.period, 60);
  assert.equal(r.issuer, 'ACME');
});

test('parseOtpauth: defaults and rejects', () => {
  const r = parseOtpauth('otpauth://totp/x?secret=ABCDEF');
  assert.equal(r.algorithm, 'SHA-1');
  assert.equal(r.digits, 6);
  assert.equal(r.period, 30);
  assert.equal(parseOtpauth('otpauth://hotp/x?secret=A&counter=0'), null);
  assert.equal(parseOtpauth('https://example.com'), null);
  assert.equal(parseOtpauth('not a uri'), null);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/totp.test.mjs` — the `totp` / `parseOtpauth` tests FAIL.

- [ ] **Step 3: Append to `src/totp.js`**

```js
// totpObj: { secret (base32 string), algorithm, digits, period }
export async function totp(totpObj, { now = Date.now() } = {}) {
  const key = base32Decode(totpObj.secret);
  const seconds = Math.floor(now / 1000);
  const counter = Math.floor(seconds / totpObj.period);
  const code = await hotp(key, counter, totpObj);
  const secondsRemaining = totpObj.period - (seconds % totpObj.period);
  return { code, secondsRemaining, period: totpObj.period };
}

const ALGO_MAP = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512',
  'SHA-1': 'SHA-1', 'SHA-256': 'SHA-256', 'SHA-512': 'SHA-512' };

// otpauth://totp/LABEL?secret=...&algorithm=...&digits=...&period=...&issuer=...
// Returns null (never throws) for anything that is not a totp otpauth URI.
export function parseOtpauth(uri) {
  let u;
  try { u = new URL(String(uri)); } catch { return null; }
  if (u.protocol !== 'otpauth:') return null;
  if (u.host.toLowerCase() !== 'totp') return null;
  const q = u.searchParams;
  const secret = (q.get('secret') || '').replace(/\s+/g, '');
  if (!secret) return null;
  const algorithm = ALGO_MAP[(q.get('algorithm') || 'SHA1').toUpperCase()] || 'SHA-1';
  const digits = Number(q.get('digits')) || 6;
  const period = Number(q.get('period')) || 30;
  const label = decodeURIComponent(u.pathname.replace(/^\//, ''));
  const issuer = q.get('issuer') || (label.includes(':') ? label.split(':')[0] : '');
  const account = label.includes(':') ? label.split(':').slice(1).join(':') : label;
  return { secret, algorithm, digits, period, issuer, account };
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/totp.test.mjs` — PASS (all RFC 4226 + RFC 6238 vectors).
Run: `npm test` — `fail 0` (196).
Run: `node tools/build.mjs && node tools/check-invariants.mjs` — green.

- [ ] **Step 5: Commit**

```bash
git add src/totp.js tests/totp.test.mjs
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: totp() with countdown + otpauth:// URI parser

RFC 6238 Appendix B vectors (SHA-1/256/512) pass.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Task T4: `normaliseTotp` in `src/vault.js`

**Files:**
- Modify: `src/vault.js`
- Test: `tests/vault.test.mjs` (append)

- [ ] **Step 1: Append the failing tests to `tests/vault.test.mjs`**

```js
import { normaliseTotp } from '../src/vault.js';

test('normaliseTotp folds string / object / null into the object form', () => {
  assert.equal(normaliseTotp(null), null);
  assert.equal(normaliseTotp(''), null);
  assert.equal(normaliseTotp('  '), null);
  assert.deepEqual(normaliseTotp('JBSW Y3DP'),
    { secret: 'JBSWY3DP', algorithm: 'SHA-1', digits: 6, period: 30 });
  assert.deepEqual(normaliseTotp({ secret: 'ABC' }),
    { secret: 'ABC', algorithm: 'SHA-1', digits: 6, period: 30 });
  assert.deepEqual(normaliseTotp({ secret: 'ABC', algorithm: 'SHA-256', digits: 8, period: 60 }),
    { secret: 'ABC', algorithm: 'SHA-256', digits: 8, period: 60 });
});

test('makeEntry stores the totp object form', () => {
  assert.equal(makeEntry({ name: 'a', site: 's', account: 'x' }).totp, null);
  assert.deepEqual(makeEntry({ name: 'a', site: 's', account: 'x', totp: 'ABCDEF' }).totp,
    { secret: 'ABCDEF', algorithm: 'SHA-1', digits: 6, period: 30 });
});

test('a totp object round-trips through encodeEnvelope/openVault', async () => {
  let v = addEntry(createVault(), { name: 'a', site: 's', account: 'x', totp: 'ABCDEF' });
  const text = await encodeEnvelope(v, { masterKey: MK, writerId: 'w' });
  const back = await openVault(JSON.parse(text), { masterKey: MK });
  assert.deepEqual(back.entries[0].totp,
    { secret: 'ABCDEF', algorithm: 'SHA-1', digits: 6, period: 30 });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/vault.test.mjs` — FAIL (`normaliseTotp` not exported;
`makeEntry` stores the bare string).

- [ ] **Step 3: Add `normaliseTotp` and use it in `makeEntry`**

In `src/vault.js`, add near the other pure helpers:
```js
// A totp field is null, a bare base32 string (legacy), or
// { secret, algorithm, digits, period }. Fold all into the object form or null.
export function normaliseTotp(value) {
  if (value == null) return null;
  const raw = typeof value === 'string' ? { secret: value } : value;
  const secret = String(raw.secret ?? '').replace(/\s+/g, '');
  if (!secret) return null;
  const A = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512',
    'SHA-1': 'SHA-1', 'SHA-256': 'SHA-256', 'SHA-512': 'SHA-512' };
  return {
    secret,
    algorithm: A[String(raw.algorithm ?? 'SHA-1').toUpperCase()] || 'SHA-1',
    digits: Number.isInteger(raw.digits) ? raw.digits : 6,
    period: Number.isInteger(raw.period) && raw.period > 0 ? raw.period : 30,
  };
}
```

In `makeEntry`, change the password-branch line:
```js
    totp: partial.totp ?? null,
```
to:
```js
    totp: normaliseTotp(partial.totp),
```

Check `updateEntry`: it spreads `patch` onto the existing entry. If `patch.totp`
is present, route it through `normaliseTotp` too — find the merge and wrap
`patch.totp` (if the key is in `patch`) with `normaliseTotp`. If `updateEntry`
rebuilds via `makeEntry` on a type change, the `makeEntry` change already covers
it; add an explicit `totp: normaliseTotp(...)` only on the same-type patch path.

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/vault.test.mjs` — PASS.
Run: `npm test` — `fail 0` (199). Check the existing `makeEntry: password defaults`
test still passes (`e.totp === null` when no totp given — `normaliseTotp(null)` is
`null`, unchanged).
Run: `node tools/build.mjs && node tools/check-invariants.mjs` — green.

- [ ] **Step 5: Commit**

```bash
git add src/vault.js tests/vault.test.mjs
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: normaliseTotp folds the totp field to { secret, algorithm, digits, period }

Legacy bare-string secrets still load. makeEntry/updateEntry route through it.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Task T5: Entry detail — live code + countdown

**Files:**
- Modify: `src/vault-ui.js`
- Modify: `src/style.css`
- Manual test: browser

Context: `renderDetail` (around line 694) currently renders the TOTP section as
`<div class="v-sec"><div class="v-h">TOTP secret</div><div class="v-meta">${e.totp ? '&bull;&bull;&bull;&bull; <button class="link-btn" id="vTotpCopy" ...>copy</button>' : '—'}</div></div>`
and wires `#vTotpCopy` (around line 788) to `navigator.clipboard.writeText(e.totp)`.
`e.totp` is now the **object** form (Task T4), so the current copy handler is
already broken and must change.

- [ ] **Step 1: Append CSS to `src/style.css`**

```css
/* Live TOTP (Phase 5c) */
.v-totp-code { font: 600 20px ui-monospace, Menlo, monospace; letter-spacing: 2px; }
.v-totp-bar { height: 3px; background: #1a1c1f; border-radius: 2px; margin-top: 6px; overflow: hidden; }
.v-totp-bar > i { display: block; height: 100%; background: var(--blue); transition: width 1s linear; }
```

- [ ] **Step 2: Replace the TOTP section markup in `renderDetail`**

```js
      <div class="v-sec"><div class="v-h">TOTP</div>
        <div class="v-meta" id="vTotpBox">${e.totp ? '<span class="v-totp-code" id="vTotpCode">……</span> <button class="link-btn" id="vTotpCopy" type="button">copy</button><div class="v-totp-bar"><i id="vTotpFill"></i></div>' : '—'}</div>
      </div>
```

- [ ] **Step 3: Replace the `#vTotpCopy` wiring block with a live loop**

Remove the old `const totpCopy = panel.querySelector('#vTotpCopy'); …` block and
add, after the existing detail wiring:

```js
    if (e.totp) {
      const codeEl = panel.querySelector('#vTotpCode');
      const fillEl = panel.querySelector('#vTotpFill');
      const copyEl = panel.querySelector('#vTotpCopy');
      let totpInterval = null;
      const tick = async () => {
        try {
          const r = await totp(e.totp);
          const half = e.totp.digits > 6 ? 4 : 3;
          codeEl.textContent = `${r.code.slice(0, half)} ${r.code.slice(half)}`;
          codeEl.dataset.raw = r.code;
          fillEl.style.width = `${Math.round((r.secondsRemaining / r.period) * 100)}%`;
        } catch {
          codeEl.textContent = 'invalid base32';
          codeEl.dataset.raw = '';
          if (totpInterval) { clearInterval(totpInterval); totpInterval = null; }
        }
      };
      tick();
      totpInterval = setInterval(tick, 1000);
      copyEl.addEventListener('click', async () => {
        const raw = codeEl.dataset.raw;
        if (!raw) return;
        try {
          await navigator.clipboard.writeText(raw);
          copyEl.textContent = 'copied';
          setTimeout(() => { copyEl.textContent = 'copy'; }, 1500);
          setTimeout(async () => { try { await navigator.clipboard.writeText(''); } catch (_) {} },
            (vault.settings.clipboardClearSeconds || 25) * 1000);
        } catch (_) {}
      });
      // stop the loop when we leave the detail view
      detailCleanups.push(() => { if (totpInterval) clearInterval(totpInterval); });
    }
```

- [ ] **Step 4: Add a `detailCleanups` mechanism**

Near the top of `initVaultTab` add `let detailCleanups = [];`. At the very start
of `renderDetail` (before it sets `panel.innerHTML`), add:
```js
    detailCleanups.forEach((fn) => { try { fn(); } catch (_) {} });
    detailCleanups = [];
```
In `wipe()` add:
```js
    detailCleanups.forEach((fn) => { try { fn(); } catch (_) {} });
    detailCleanups = [];
```
(This also future-proofs the existing `revealTimer` if it is later moved here; for
now the TOTP interval is the only registered cleanup.)

- [ ] **Step 5: Build + suite**

Run: `node tools/build.mjs && node tools/check-invariants.mjs && npm test`
Expected: green; `fail 0` (199, no new unit tests — the codec is covered by
`tests/totp.test.mjs`, the UI is manual).

- [ ] **Step 6: Manual browser test**

`node tools/build.mjs`, serve `dist/`, create/unlock a vault. Add an entry, in the
editor paste a real `otpauth://totp/...` URI from an authenticator app (this needs
Task T6 for the editor to parse it — for now paste a raw base32 secret like
`JBSWY3DPEHPK3PXP`). Open the entry: the detail view shows a 6-digit code
`XXX XXX`, a shrinking bar, and the code changes on the 30-second boundary — cross
-check against `oathtool --totp -b JBSWY3DPEHPK3PXP` or an authenticator app with
the same secret. Copy → paste elsewhere → clears after `clipboardClearSeconds`.
Leave the detail view and come back → the interval restarts, no console errors,
no leaked timers (check with repeated open/close). An entry whose stored secret
is `not base32!!` shows "invalid base32" and no bar movement.

- [ ] **Step 7: Commit**

```bash
git add src/vault-ui.js src/style.css
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: vault detail — live TOTP code, countdown bar, copy-with-clear

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Task T6: Editor — `otpauth://` paste + hint; docs

**Files:**
- Modify: `src/vault-ui.js`
- Modify: `docs/specs/2026-09-01-kunji-design.md` (§5.2), `README.md`
- Manual test: browser

Context: the editor field `#edTotp` (around line 831) is
`<input id="edTotp" ... value="${esc(e.totp ?? '')}">` with label
"TOTP secret (optional)". `e.totp` is now an object — `value="${esc(e.totp ?? '')}"`
would render `[object Object]`. The save path (around line 890) is
`totp: panel.querySelector('#edTotp').value.trim() || null`.

- [ ] **Step 1: Fix the field's initial value and label**

```js
      <div class="field">
        <input id="edTotp" type="text" autocomplete="off" spellcheck="false" placeholder=" " value="${esc(e.totp ? e.totp.secret : '')}">
        <label for="edTotp">TOTP secret or otpauth:// URI (optional)</label>
      </div>
      <div class="v-foot" id="edTotpHint"></div>
```

- [ ] **Step 2: Save path — parse `otpauth://`, else treat as a bare secret**

Replace the save line:
```js
        totp: panel.querySelector('#edTotp').value.trim() || null,
```
with:
```js
        totp: (() => {
          const raw = panel.querySelector('#edTotp').value.trim();
          if (!raw) return null;
          const parsed = parseOtpauth(raw);
          return normaliseTotp(parsed || raw);
        })(),
```
(`parseOtpauth` and `normaliseTotp` are bundle globals after the build strips
`export`.)

- [ ] **Step 3: Live "doesn't look like base32" hint**

In the editor wiring, after the fields are in the DOM:
```js
    const edTotp = panel.querySelector('#edTotp');
    const edTotpHint = panel.querySelector('#edTotpHint');
    const checkTotp = () => {
      const raw = edTotp.value.trim();
      if (!raw || raw.startsWith('otpauth://')) { edTotpHint.textContent = ''; return; }
      edTotpHint.textContent = /^[A-Za-z2-7= ]+$/.test(raw) ? '' : 'that does not look like a base32 secret';
    };
    edTotp.addEventListener('input', checkTotp);
    checkTotp();
```

- [ ] **Step 4: Spec + README**

`docs/specs/2026-09-01-kunji-design.md` §5.2 — after the entry schema, add:
```
`totp` is `null`, a bare base32 string (legacy), or
`{ secret, algorithm: "SHA-1"|"SHA-256"|"SHA-512", digits, period }`. The loader
folds the first two forms into the object form (`normaliseTotp`); no `format`/`v`
bump — reading old data needs no migration.
```

`README.md` — under `## The vault`, append:
```
An entry with a TOTP secret (paste the base32 or an `otpauth://` URI) shows the
live 6-digit 2FA code and a countdown in its detail view.
```

- [ ] **Step 5: Build + suite**

Run: `node tools/build.mjs && node tools/check-invariants.mjs && npm test`
Expected: green; `fail 0` (199).

- [ ] **Step 6: Manual browser test**

Editor: paste `otpauth://totp/ACME:me?secret=JBSWY3DPEHPK3PXP&digits=8&period=60`
→ Save → the detail view shows an 8-digit code `XXXX XXXX` refreshing on a
60-second period. Edit the same entry → the field shows just the base32 secret,
Save again → unchanged. Type `not#base32` → the hint appears; `otpauth://…` →
hint clears. A pre-5c vault file with a legacy string `totp` opens and shows a
live code (the loader normalised it).

- [ ] **Step 7: Commit**

```bash
git add src/vault-ui.js docs/specs/2026-09-01-kunji-design.md README.md
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: editor accepts an otpauth:// URI; totp data-model doc

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

# PART 3 — Passkey unlock (Tasks P1–P5)

## Task P1: `wrapMasterKey` / `unwrapMasterKey`

**Files:**
- Modify: `src/vault.js`
- Test: `tests/vault.test.mjs` (append)

- [ ] **Step 1: Append the failing tests**

```js
import { wrapMasterKey, unwrapMasterKey } from '../src/vault.js';

test('wrap then unwrap round-trips a 32-byte key', async () => {
  const mk = crypto.getRandomValues(new Uint8Array(32));
  const prf = crypto.getRandomValues(new Uint8Array(32));
  const wrapped = await wrapMasterKey(mk, prf);
  assert.equal(wrapped.iv.length, 12);
  assert.ok(wrapped.ct.length >= 32 + 16);
  assert.deepEqual(await unwrapMasterKey(wrapped, prf), mk);
});

test('unwrap with the wrong PRF secret throws, never returns garbage', async () => {
  const mk = crypto.getRandomValues(new Uint8Array(32));
  const wrapped = await wrapMasterKey(mk, new Uint8Array(32).fill(1));
  await assert.rejects(() => unwrapMasterKey(wrapped, new Uint8Array(32).fill(2)));
});

test('wrap uses a fresh IV each call', async () => {
  const mk = new Uint8Array(32);
  const prf = new Uint8Array(32).fill(7);
  const a = await wrapMasterKey(mk, prf);
  const b = await wrapMasterKey(mk, prf);
  assert.notDeepEqual([...a.iv], [...b.iv]);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/vault.test.mjs` — FAIL (not exported).

- [ ] **Step 3: Add to `src/vault.js`**

`src/vault.js` already imports `aesGcmEncrypt`/`aesGcmDecrypt` from
`./webcrypto.js` and `randomBytes` is defined locally; it imports `hkdfSha256`
via `deriveVaultKey`'s neighbourhood — add `hkdfSha256` to the `./webcrypto.js`
import if not present, and `utf8` from `./encoding.js` if not present (check the
existing import lines and extend them).

```js
const PASSKEY_AAD = utf8('kunji-passkey-v1');

async function passkeyWrapKey(prfSecret) {
  return hkdfSha256(prfSecret, utf8('kunji/v1'), utf8('passkey-wrap'), 32);
}

// masterKey, prfSecret: Uint8Array(32). Returns { iv: Uint8Array(12), ct: Uint8Array }.
export async function wrapMasterKey(masterKey, prfSecret) {
  const key = await passkeyWrapKey(prfSecret);
  const iv = randomBytes(12);
  const ct = await aesGcmEncrypt(key, iv, masterKey, PASSKEY_AAD);
  return { iv, ct };
}

// { iv, ct }: Uint8Array. Throws on tag failure.
export async function unwrapMasterKey({ iv, ct }, prfSecret) {
  const key = await passkeyWrapKey(prfSecret);
  return aesGcmDecrypt(key, iv, ct, PASSKEY_AAD);
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/vault.test.mjs` — PASS.
Run: `npm test` — `fail 0` (202).
Run: `node tools/build.mjs && node tools/check-invariants.mjs` — green.

- [ ] **Step 5: Commit**

```bash
git add src/vault.js tests/vault.test.mjs
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: wrapMasterKey / unwrapMasterKey (AES-GCM under an HKDF(PRF) key)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Task P2: `src/passkey-store.js`

**Files:**
- Create: `src/passkey-store.js`
- Modify: `tools/build.mjs` (`JS_ORDER`)
- Test: `tests/passkey-store.test.mjs` (new), `tests/build.test.mjs` (append)

- [ ] **Step 1: Write `tests/passkey-store.test.mjs`**

```js
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { hasPasskey, loadPasskey, savePasskey, removePasskey } from '../src/passkey-store.js';

// minimal localStorage shim
beforeEach(() => {
  const m = new Map();
  globalThis.localStorage = {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
  };
});

const REC = { v: 1, credentialId: 'Y2lk', prfSalt: 'c2FsdA', iv: 'aXY', ct: 'Y3Q', label: 'this device', createdAt: '2026-09-01T00:00:00Z' };

test('save / has / load / remove, namespaced by kcv', () => {
  assert.equal(hasPasskey('KCV_A'), false);
  savePasskey('KCV_A', REC);
  assert.equal(hasPasskey('KCV_A'), true);
  assert.equal(hasPasskey('KCV_B'), false);
  assert.deepEqual(loadPasskey('KCV_A'), REC);
  removePasskey('KCV_A');
  assert.equal(hasPasskey('KCV_A'), false);
  assert.equal(loadPasskey('KCV_A'), null);
});

test('loadPasskey returns null on corrupt JSON, does not throw', () => {
  localStorage.setItem('kunji.passkey.KCV_C', '{not json');
  assert.equal(loadPasskey('KCV_C'), null);
  assert.equal(hasPasskey('KCV_C'), true); // key exists, value unparseable -> present but unusable
});

test('all functions no-op safely when localStorage throws', () => {
  globalThis.localStorage = {
    getItem() { throw new Error('blocked'); },
    setItem() { throw new Error('blocked'); },
    removeItem() { throw new Error('blocked'); },
  };
  assert.equal(hasPasskey('X'), false);
  assert.equal(loadPasskey('X'), null);
  assert.doesNotThrow(() => savePasskey('X', REC));
  assert.doesNotThrow(() => removePasskey('X'));
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/passkey-store.test.mjs` — FAIL (module missing).

- [ ] **Step 3: Create `src/passkey-store.js`**

```js
// Per-device passkey records, keyed by the vault's KCV so a record is only
// offered for the file it belongs to. localStorage only; never written to the
// vault file, never cached by the service worker.

const PREFIX = 'kunji.passkey.';

function ls() {
  try { return globalThis.localStorage || null; } catch { return null; }
}

export function hasPasskey(kcv) {
  const s = ls();
  try { return !!s && s.getItem(PREFIX + kcv) !== null; } catch { return false; }
}

export function loadPasskey(kcv) {
  const s = ls();
  if (!s) return null;
  try {
    const raw = s.getItem(PREFIX + kcv);
    if (raw == null) return null;
    return JSON.parse(raw);
  } catch { return null; }
}

export function savePasskey(kcv, record) {
  const s = ls();
  try { if (s) s.setItem(PREFIX + kcv, JSON.stringify(record)); } catch { /* quota / private mode */ }
}

export function removePasskey(kcv) {
  const s = ls();
  try { if (s) s.removeItem(PREFIX + kcv); } catch { /* ignore */ }
}
```

- [ ] **Step 4: `JS_ORDER` + build test**

`tools/build.mjs` — add `'src/passkey-store.js'` after `'src/webcrypto.js'` (and
after `'src/totp.js'`), before `'src/qr.js'`.

Append to `tests/build.test.mjs`:
```js
test('built html inlines src/passkey-store.js before vault.js', () => {
  execFileSync('node', ['tools/build.mjs'], { stdio: 'pipe' });
  const html = readFileSync('dist/kunji.html', 'utf8');
  assert.ok(html.includes('==== src/passkey-store.js ===='));
  assert.ok(html.indexOf('src/passkey-store.js') < html.indexOf('src/vault.js'));
});
```

- [ ] **Step 5: Run to verify it passes**

Run: `node --test tests/passkey-store.test.mjs tests/build.test.mjs` — PASS.
Run: `npm test` — `fail 0` (206).
Run: `node tools/build.mjs && node tools/check-invariants.mjs` — `invariants ok (19 files)`.

- [ ] **Step 6: Commit**

```bash
git add src/passkey-store.js tools/build.mjs tests/passkey-store.test.mjs tests/build.test.mjs
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: src/passkey-store.js — per-device passkey records in localStorage

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Task P3: `src/webauthn.js`

**Files:**
- Create: `src/webauthn.js`
- Modify: `tools/build.mjs` (`JS_ORDER`)
- Test: `tests/webauthn.test.mjs` (new — support probe only), `tests/build.test.mjs` (append)

- [ ] **Step 1: Write `tests/webauthn.test.mjs`**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isPasskeySupported } from '../src/webauthn.js';

test('isPasskeySupported returns false (not throws) with no WebAuthn present', async () => {
  // Node has no window / navigator.credentials
  assert.equal(await isPasskeySupported(), false);
});
```

(No test for `registerPasskey` / `getPasskeySecret` — they require a real
authenticator and are covered by the manual browser pass.)

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/webauthn.test.mjs` — FAIL (module missing).

- [ ] **Step 3: Create `src/webauthn.js`**

```js
import { utf8 } from './encoding.js';

function b(arr) { return new Uint8Array(arr); }
function rand(n) { return crypto.getRandomValues(new Uint8Array(n)); }

// Cheap capability check. Never throws.
export async function isPasskeySupported() {
  try {
    if (typeof window === 'undefined') return false;
    if (location && location.protocol === 'file:') return false;   // WebAuthn needs an origin
    return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
  } catch {
    return false;
  }
}

// Creates a discoverable credential with the PRF extension. Returns { credentialId }.
// Rejects if PRF is not available on this authenticator.
export async function registerPasskey({ rpName = 'Kunji', userName = 'vault' } = {}) {
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: rand(32),
      rp: { name: rpName },                       // rp.id omitted -> current origin
      user: { id: utf8(userName), name: userName, displayName: userName },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
      extensions: { prf: {} },
      timeout: 60000,
    },
  });
  const ext = cred.getClientExtensionResults();
  if (!ext || !ext.prf || ext.prf.enabled !== true) {
    throw new Error('this device does not support the WebAuthn PRF extension');
  }
  return { credentialId: new Uint8Array(cred.rawId) };
}

// Returns a stable 32-byte secret for (credential, salt). Rejects on cancel / failure.
export async function getPasskeySecret(credentialId, salt) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: rand(32),
      allowCredentials: [{ type: 'public-key', id: b(credentialId) }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: b(salt) } } },
      timeout: 60000,
    },
  });
  const ext = assertion.getClientExtensionResults();
  const first = ext && ext.prf && ext.prf.results && ext.prf.results.first;
  if (!first) throw new Error('PRF result missing from the assertion');
  return new Uint8Array(first);
}
```

- [ ] **Step 4: `JS_ORDER` + build test**

`tools/build.mjs` — add `'src/webauthn.js'` after `'src/webcrypto.js'` (grouped
with `totp.js` / `passkey-store.js`), before `'src/qr.js'`.

Append to `tests/build.test.mjs`:
```js
test('built html inlines src/webauthn.js before vault.js', () => {
  execFileSync('node', ['tools/build.mjs'], { stdio: 'pipe' });
  const html = readFileSync('dist/kunji.html', 'utf8');
  assert.ok(html.includes('==== src/webauthn.js ===='));
  assert.ok(html.indexOf('src/webauthn.js') < html.indexOf('src/vault.js'));
});
```

- [ ] **Step 5: Run to verify it passes**

Run: `node --test tests/webauthn.test.mjs tests/build.test.mjs` — PASS.
Run: `npm test` — `fail 0` (208).
Run: `node tools/build.mjs && node tools/check-invariants.mjs` — `invariants ok (20 files)`.
Confirm `grep -n "navigator.credentials" dist/kunji.html` shows the code is in the
bundle and `npm run check` still passes (WebAuthn is not a network API).

- [ ] **Step 6: Commit**

```bash
git add src/webauthn.js tools/build.mjs tests/webauthn.test.mjs tests/build.test.mjs
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: src/webauthn.js — PRF-extension passkey register/get wrapper

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Task P4: LOCKED-screen "unlock with passkey" + footer set-up/remove

**Files:**
- Modify: `src/vault-ui.js`
- Manual test: browser (PWA origin)

Context: `renderLocked` (around line 257) shows the identity/passphrase fields,
a KCV dot, an "Unlock" button, and an "Open a different file" link. The unlock
handler derives `masterKey` via `deriveMasterKey`, checks the KCV, and calls
`openVault`. `renderList`'s footer (around line 495) has the Save/Lock/countdown
row plus the decoy controls in a `${unlockedSlot === 'real' && activeSlot === 'real' ? ... : ''}`
block.

- [ ] **Step 1: LOCKED screen — offer passkey when a record exists**

In `renderLocked`, before building `panel.innerHTML`:
```js
    const kcv = loadedEnvelope ? loadedEnvelope.kcv : null;
    const passkeyRecord = kcv ? loadPasskey(kcv) : null;
```
Add, immediately above the `<div class="fields">` in the template, when
`passkeyRecord` is set:
```js
      ${passkeyRecord ? '<button class="btn-primary" id="vlPasskey" type="button">Unlock with passkey</button><div class="v-or">or use your passphrase</div>' : ''}
```
Wire it (in `renderLocked`'s event section), guarded by `isPasskeySupported()`:
```js
    if (passkeyRecord) {
      const pkBtn = panel.querySelector('#vlPasskey');
      if (!(await isPasskeySupported())) {
        pkBtn.disabled = true;
        pkBtn.textContent = 'Passkey needs the installed app';
      } else {
        pkBtn.addEventListener('click', async () => {
          const errEl = panel.querySelector('#vlError');
          errEl.textContent = '';
          pkBtn.disabled = true; pkBtn.textContent = 'Waiting for passkey…';
          try {
            const secret = await getPasskeySecret(
              base64ToBytes(passkeyRecord.credentialId), base64ToBytes(passkeyRecord.prfSalt));
            const mk = await unwrapMasterKey(
              { iv: base64ToBytes(passkeyRecord.iv), ct: base64ToBytes(passkeyRecord.ct) }, secret);
            if (await computeKcv(mk) !== loadedEnvelope.kcv) throw new Error('kcv mismatch');
            const opened = await openVault(loadedEnvelope, { masterKey: mk });
            masterKey = mk;
            vault = { entries: opened.entries, settings: opened.settings };
            sessionIdentity = panel.querySelector('#vlIdentity')?.value.trim() || sessionIdentity;
            identityHintOn = typeof loadedEnvelope.identityHint === 'string';
            unlockedSlot = opened.slot; activeSlot = 'real';
            decoyVault = null; decoyMasterKey = null; realVault = null; realMasterKey = null;
            dirty = false; state = 'UNLOCKED';
            vaultBridge.publish(visibleEntries(vault));
            render();
          } catch (e) {
            errEl.textContent = 'Passkey unlock failed — use your passphrase.';
            pkBtn.disabled = false; pkBtn.textContent = 'Unlock with passkey';
          }
        });
      }
    }
```
`base64ToBytes` is a bundle global (from `encoding.js`). Add a `.v-or` style to
`src/style.css`: `.v-or { text-align:center; color:var(--muted); font-size:12px; margin:8px 0; }`.

> **Decoy note:** `openVault` still routes real-then-decoy on `masterKey`. A
> passkey wraps the *real* master key, so `opened.slot` is `'real'` in normal
> use; the generic handling above keeps parity if a future change wraps a decoy
> key.

- [ ] **Step 2: Footer — set-up / remove passkey (real slot only)**

Inside the existing `${unlockedSlot === 'real' && activeSlot === 'real' ? \`...\` : ''}`
block in `renderList`, next to the decoy controls, add:
```js
          <div class="v-passkey-row">
            ${!loadedEnvelope
              ? '<span class="v-foot">Save the vault to enable passkey unlock.</span>'
              : (hasPasskey(loadedEnvelope.kcv)
                ? '<button class="link-btn" id="vPkRemove" type="button">Remove passkey (this device)</button>'
                : '<button class="link-btn" id="vPkAdd" type="button">Set up passkey on this device&hellip;</button>')}
            <div class="error" id="vPkError"></div>
          </div>
```
Wire (in `renderList`'s event section):
```js
    if (panel.querySelector('#vPkAdd')) panel.querySelector('#vPkAdd').addEventListener('click', async () => {
      const err = panel.querySelector('#vPkError'); err.textContent = '';
      if (!(await isPasskeySupported())) { err.textContent = 'Passkeys need the installed app (open Kunji from your home screen).'; return; }
      if (!confirm('Register a passkey so this device can unlock this vault with your fingerprint / PIN instead of the passphrase?')) return;
      try {
        const { credentialId } = await registerPasskey({ userName: sessionIdentity || 'vault' });
        const prfSalt = crypto.getRandomValues(new Uint8Array(32));
        const secret = await getPasskeySecret(credentialId, prfSalt);
        const wrapped = await wrapMasterKey(masterKey, secret);
        savePasskey(loadedEnvelope.kcv, {
          v: 1,
          credentialId: bytesToBase64(credentialId),
          prfSalt: bytesToBase64(prfSalt),
          iv: bytesToBase64(wrapped.iv),
          ct: bytesToBase64(wrapped.ct),
          label: 'this device',
          createdAt: new Date().toISOString(),
        });
        render();
      } catch (e) {
        err.textContent = 'Could not set up the passkey.';
      }
    });
    if (panel.querySelector('#vPkRemove')) panel.querySelector('#vPkRemove').addEventListener('click', () => {
      if (!confirm('Forget the passkey for this vault on this device? (The platform credential must be deleted in your OS settings separately.)')) return;
      removePasskey(loadedEnvelope.kcv);
      render();
    });
```
`bytesToBase64` / `base64ToBytes` are bundle globals.

- [ ] **Step 3: `wipe()` leaves the passkey store alone**

Confirm `wipe()` does **not** call any `passkey-store` function — the record is
device-persistent, not session state. (No code change; a checklist item.)

- [ ] **Step 4: Build + suite**

Run: `node tools/build.mjs && node tools/check-invariants.mjs && npm test`
Expected: green; `fail 0` (208 — no new unit tests; the flow is manual).

- [ ] **Step 5: Manual browser test (over the PWA origin, e.g. `http://localhost:8802` from `dist/pwa/`)**

- Unlock a real vault by passphrase. Footer shows "Set up passkey on this
  device…". Click → OS prompt → register → footer flips to "Remove passkey".
- Lock. The LOCKED screen shows "Unlock with passkey" above the passphrase
  fields. Click → OS biometric/PIN → unlocked; Generate tab works; KCV green.
- Wrong finger / cancel → "Passkey unlock failed — use your passphrase", the
  passphrase path still works.
- "Remove passkey (this device)" → confirm → on next lock the button is gone.
- Open the same file from `file://` (single-file build) → the passkey controls
  never appear (`isPasskeySupported()` is false).
- A second, different vault file on the same device → its own independent passkey
  slot (keyed by its KCV).
- DevTools → Application → Local Storage: exactly one `kunji.passkey.<kcv>` key,
  opaque base64 value. Network tab empty throughout.

- [ ] **Step 6: Commit**

```bash
git add src/vault-ui.js src/style.css
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: vault tab — unlock with a passkey; set-up / remove per device

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Task P5: Spec §10 / §11 + README

**Files:**
- Modify: `docs/specs/2026-09-01-kunji-design.md`
- Modify: `README.md`

- [ ] **Step 1: §10 amendment**

Find the §10 hygiene bullet:
```
no secret written to `localStorage` or a service
worker cache
```
Replace that clause with:
```
no secret written to `localStorage` or a service worker cache, **with one
exception**: a passkey-wrapped master key (AES-256-GCM under a key derived from a
WebAuthn PRF secret). That blob is inert without the platform authenticator that
produced the PRF secret, it is per-device, and it is never written to the vault
file or cached by the service worker.
```

- [ ] **Step 2: §11 row**

In the §11 platform table (or the WebAuthn note beneath it), replace the "Not in
v1" sentence about biometric unlock with:
```
Passkey unlock (WebAuthn PRF extension wrapping the master key in a per-device
`localStorage` blob) is available in the installed PWA build on platforms with a
PRF-capable authenticator. The single-file `file://` build cannot use it (no
origin). It is a per-device convenience — the passphrase always still works, and
a registered passkey is a signal that a real vault exists on that device.
```

- [ ] **Step 3: README**

Under `## The vault`, append:
```
On the installed app you can register a **passkey** so a device unlocks the vault
with its fingerprint / PIN instead of the master passphrase. The passphrase
always still works; the passkey is per-device and never leaves it.
```

- [ ] **Step 4: Full verification**

Run: `npm run verify` — `fail 0`; `dist/kunji.html written`; `dist/pwa/ written`;
`invariants ok (20 files)`. `git status --porcelain` shows only the two files.

- [ ] **Step 5: Commit**

```bash
git add docs/specs/2026-09-01-kunji-design.md README.md
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
docs: §10 passkey-wrapped-key exception; §11 passkey unlock; README

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Self-review

**Spec coverage — 5a (profile seam):**
- `PROFILES` / `profileOf` / `DEFAULT_PROFILE` — Task S1.
- `deriveMasterKey` routes through the registry, drops `iterations`; speed-test
  call sites migrated; frozen vectors unchanged — Task S2 (enumerates all three
  3rd-arg call sites: `derive.test.mjs:217`, `vectors.test.mjs:19`, `:31`).
- `derivePassword` reads `params.profile`; `profile:'v2'` rejects — Task S3.
- Envelope `kdf` validated against a known profile's `kdfTag` — Task S4.
- Freeze `PBKDF2_ITERATIONS` + `max-symbols`; spec §4.3/§4.4/§13; `v2`
  requirements doc — Task S5.
- Out of scope respected: no second KDF, no Steps 2–6 change, no `format`/`v`
  bump, no migration UI.

**Spec coverage — 5c (TOTP):**
- `uint64be`, generalised `hmac` (`hmacSha256` kept as a wrapper so vectors are
  untouched) — Task T1.
- `src/totp.js`: `base32Decode`, `hotp` (RFC 4226 App. D), `totp` (RFC 6238
  App. B, all three hashes), `parseOtpauth` — Tasks T2, T3.
- `normaliseTotp` in `src/vault.js`; `makeEntry`/`updateEntry` route through it;
  legacy string still loads; round-trips through `encodeEnvelope`/`openVault` —
  Task T4.
- Detail view: live grouped code, countdown bar, copy-with-clear, "invalid
  base32" line, interval torn down on view-leave and `wipe()` via
  `detailCleanups` — Task T5.
- Editor: `otpauth://` paste → parsed; bare secret → SHA-1/6/30; non-blocking
  base32 hint; field shows `e.totp.secret` not `[object Object]` — Task T6.
- Spec §5.2 totp shape; README — Task T6.
- Out of scope respected: no hand-entered algorithm/digits/period fields; no
  decoy-specific handling; no `v` bump.

**Spec coverage — 5b (passkey):**
- `src/webauthn.js` — `isPasskeySupported` (false, not throw, off-origin),
  `registerPasskey` (PRF-required), `getPasskeySecret` — Task P3.
- `src/passkey-store.js` — KCV-namespaced CRUD, corrupt-JSON → null,
  localStorage-throws → safe no-op — Task P2.
- `wrapMasterKey` / `unwrapMasterKey` (AES-GCM under `HKDF(prfSecret,
  "passkey-wrap")`, fresh IV, wrong-secret throws) — Task P1.
- LOCKED "Unlock with passkey" → `getPasskeySecret` → `unwrapMasterKey` → KCV
  guard → `openVault` → identical unlocked state; failure falls back to
  passphrase — Task P4.
- Footer set-up (real slot, needs `loadedEnvelope`) / remove; `wipe()` untouched
  — Task P4.
- PWA-only (`file://` → controls absent); decoy tradeoff documented — Tasks P3,
  P4, P5.
- §10 amendment (approved option i); §11; README — Task P5.
- Out of scope respected: no decoy passkey, no multi-passkey, no conditional-UI,
  passkey blob never in the vault file / SW cache.

**Placeholder scan:** every code step contains complete code or an exact edit
with the surrounding anchor quoted. Manual browser steps are the acceptance gate
for the three UI tasks (T5, T6, P4) — each lists concrete, checkable
observations. `src/webauthn.js` register/get have no unit test because they need
a real authenticator; `isPasskeySupported` is unit-tested for the false path.

**Type / name consistency:**
`PROFILES` / `profileOf(id)` / `DEFAULT_PROFILE`; `deriveMasterKey(passphrase,
identity, profile='v1')`; `derivePassword({ ..., profile })`; `PROFILES.v1.kdfTag`
(= `pbkdf2-sha512-600000`); `normaliseTotp(value) -> { secret, algorithm, digits,
period } | null`; `base32Decode`, `hotp(key, counter, {algorithm,digits})`,
`totp(totpObj, {now}) -> { code, secondsRemaining, period }`, `parseOtpauth(uri)`;
`hmac(algorithm, key, msg)`; `uint64be(n)`; `wrapMasterKey(mk, prf) -> { iv, ct }`,
`unwrapMasterKey({iv,ct}, prf) -> Uint8Array(32)`; `hasPasskey/loadPasskey/
savePasskey/removePasskey(kcv[, record])`; `isPasskeySupported()`,
`registerPasskey({rpName,userName}) -> { credentialId }`, `getPasskeySecret(
credentialId, salt) -> Uint8Array(32)` — each used identically across every task
and both the pure code and the UI wiring.

**Running test total:** 166 → S1 169 → S2 171 → S3 173 → S4 176 → T1 182 →
T2 186 → T3 196 → T4 199 → T5–T6 199 (UI, no unit tests) → P1 202 → P2 206 →
P3 208 → P4–P5 208. `fail 0` is the gate; the frozen v1 vectors reproduce
unchanged from S1 through P5. `invariants ok` file count 17 → 20.

**Scope:** three independent slices in one plan, ordered seam → TOTP → passkey so
the two browser-only / policy-touching tasks (P4, P5) land last. Each task
boundary produces a working `dist/kunji.html`. No `format`/`v` bump; no CSP
change; `dist/kunji.html` behaviour changes only where a task adds a feature (the
vector test guards the derivation path throughout).
