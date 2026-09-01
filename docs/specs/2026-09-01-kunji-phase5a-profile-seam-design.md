# Kunji Phase 5a — Profile Seam & v1 Freeze Design

> Sub-project of the Kunji Phase 5 line in `docs/specs/2026-09-01-kunji-design.md`
> §12.5 ("Own Argon2id as profile `v2`"). Depends on: Phases 1–4 (shipped on
> `main`). **Does not implement a second KDF.** It adds the seam that makes a
> future `v2` a contained drop-in, and closes the two §13 open decisions that
> block freezing v1.

## 1. Goal

Two things:

1. **Profile seam.** Route every master-key derivation through a `PROFILES`
   registry keyed on a profile id, with `v1` as the only entry. Adding a future
   profile (Argon2id, scrypt, or a browser-native Argon2) becomes "add one object
   to `PROFILES`", not a refactor of `src/derive.js`.
2. **Freeze v1.** Ratify `PBKDF2_ITERATIONS = 600000` and the `max-symbols`
   charset as final, striking the two remaining §13 open decisions. After 5a, v1
   has no unresolved parameters.

## 2. Why not build Argon2id now

`crypto.subtle` has no Argon2. A `v2` therefore means a hand-written pure-JS
Argon2id (BLAKE2b + the Argon2 core, ~600–900 lines, RFC 9106 vectors). Pure-JS
Argon2id is slow: to stay under ~1.5 s on the slowest supported device it would
be limited to roughly `m = 32–64 MiB, t = 2–3` — a real but modest improvement
over PBKDF2-600k, bought with a large hand-audited crypto surface. That trade is
poor for a project whose stated identity is "zero hand-written crypto in v1"
(spec §9), and the QR codec already added ~1,500 lines of hand-rolled code in
Phase 3. The seam is the valuable, low-risk part and it ships now; the primitive
waits for a browser-native Argon2, a decision to accept the JS cost, or a
threat-model change. `docs/specs/2026-09-01-kunji-v2-profile-requirements.md`
(created by this project) is the contract a future `v2` must meet.

## 3. Scope

**In scope**

| Change | File | Effect |
|---|---|---|
| `PROFILES` registry + `profileOf` + `DEFAULT_PROFILE` | `src/derive.js` | The seam |
| `deriveMasterKey` routes through the registry; drops the `iterations` param | `src/derive.js` | Iteration count is a property of `v1`, not a caller knob |
| `derivePassword` reads `params.profile` (default `v1`) for the master-key step | `src/derive.js` | Per-entry profile dispatch (Steps 2–6 untouched) |
| Vault envelope `kdf` header validated against a known profile's `kdfTag` | `src/vault.js` | The file records its profile; `parseEnvelope` rejects an unknown KDF |
| Ratify + mark frozen: `PBKDF2_ITERATIONS`, `max-symbols` charset | `src/derive.js`, spec | Closes §13 |
| `v2` requirements reference doc | `docs/specs/2026-09-01-kunji-v2-profile-requirements.md` | Contract for a future profile |
| Spec sync: §4.3, §4.4, §13 | `docs/specs/2026-09-01-kunji-design.md` | v1 fully frozen; seam documented |

**Out of scope**

- Implementing Argon2id, scrypt, or any second KDF. No WASM.
- Any change to derivation Steps 2–6 (HKDF entry seed, HMAC keystream, rejection
  sampling, class enforcement) — they are SHA-256-based and profile-agnostic.
- Auto-migration of entries or vaults. Adding a UI to *choose* a profile (there
  is only one).
- Changing the vault `format` / `v` number, the envelope layout, or any on-disk
  bytes for existing v1 vaults.
- Re-keying / whole-vault migration flows (a `v2` concern, sketched in the
  requirements doc, not built).

## 4. The profile seam

### 4.1 Registry (`src/derive.js`)

```js
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

`PROFILES` is production-only — tests never mutate it (see §7).

### 4.2 `deriveMasterKey`

Before:
```js
export async function deriveMasterKey(passphrase, identity, iterations = PBKDF2_ITERATIONS) {
  return pbkdf2Sha512(utf8(passphrase), utf8(normaliseInput(identity)), iterations, MASTER_KEY_BYTES);
}
```
After:
```js
export async function deriveMasterKey(passphrase, identity, profile = DEFAULT_PROFILE) {
  return profileOf(profile).deriveMasterKey(passphrase, normaliseInput(identity));
}
```

The `iterations` positional parameter is **removed**. It exists today only so the
test suite can run PBKDF2 at 1,000 iterations for speed; those call sites move to
importing `pbkdf2Sha512` directly (§7). No production caller passes `iterations`.
`PBKDF2_ITERATIONS` stays exported (the vector test asserts against it and the
`v1` profile reads it).

### 4.3 `derivePassword`

The master-key step becomes profile-aware:
```js
const profile = params.profile ?? DEFAULT_PROFILE;
const masterKey = params.masterKey
  ? params.masterKey
  : await deriveMasterKey(params.passphrase, params.identity ?? '', profile);
```
`params.identity` is passed through to `deriveMasterKey`, which normalises it
(unchanged behaviour — `deriveMasterKey` already called `normaliseInput`). Steps
2–6 are byte-identical. A `params` with no `profile` and no `masterKey` derives
under `v1` exactly as today, so the frozen vectors reproduce unchanged.

Entries carry `profile` in the data model already (`makeEntry` stamps `'v1'`).
The Vault tab passes `entry.profile` when it calls `derivePassword` for an entry.

### 4.4 Vault envelope

`encodeEnvelope` already writes a header field `kdf: "pbkdf2-sha512-600000"`.
Formalise it:

- The envelope's KDF string is `profileOf(vaultProfile).kdfTag`, where
  `vaultProfile` is `DEFAULT_PROFILE` for a freshly `createVault`ed vault and,
  on save-through, whatever the loaded envelope declared.
- `parseEnvelope` gains a check: the header `kdf` must equal the `kdfTag` of some
  registered profile, else `BadEnvelopeError('unknown KDF: <value>')`. Today's
  files (`pbkdf2-sha512-600000`) pass unchanged.
- The whole vault file is one profile: its envelope encryption, KCV, `vaultKey`,
  and decoy section all derive from the single master key produced by that
  profile. There is no per-entry profile *inside* the envelope's crypto — only
  the per-entry `profile` field that governs that entry's *password* derivation.

`openVault` / `unlockVault` are unaffected: they take a `masterKey` the caller
already derived. The caller (Vault tab) will, in a future `v2`, pick the profile
from the envelope header before deriving; for 5a there is only `v1` so the call
path is unchanged.

## 5. Freezing v1

### 5.1 `PBKDF2_ITERATIONS`

Ratified at **600000**. OWASP's 2023 minimum for PBKDF2-HMAC-SHA512 is 210,000;
600k is ~3× that. The `src/derive.js` comment changes from:

```js
// OPEN DECISION (spec s13): confirm on the slowest target device before freezing v1.
export const PBKDF2_ITERATIONS = 600000;
```

to:

```js
// FROZEN as part of the v1 profile. Never change in place — a different cost is
// a different profile (see PROFILES / docs/specs/…-v2-profile-requirements.md).
export const PBKDF2_ITERATIONS = 600000;
```

`tests/vectors.test.mjs`'s existing "iterations changed since the freeze" guard
becomes a permanent invariant rather than a pre-freeze placeholder — no test
change needed, only intent.

### 5.2 `max-symbols` charset

Ratified exactly as shipped:
`abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*()-_=+[]{};:,.?@`

It is opt-in and named "max". Trimming `[]{};:,` for strict sites defeats its
purpose; a 4th preset is scope creep; `standard` covers the common case. The
`CHARSETS` object is unchanged; the spec notes are updated to call it final.

### 5.3 Spec edits (`docs/specs/2026-09-01-kunji-design.md`)

- **§4.3** — after the `max-symbols` line, add: *"These three sets are final for
  v1. `max-symbols` deliberately includes brackets and punctuation that some
  sites reject; that is the point of the preset, and `standard` is the safe
  default."*
- **§4.4** — Step 1: replace *"cost parameters frozen at that time"* nuance with
  a pointer: *"PBKDF2 iteration count for v1 is frozen at 600000; see the
  `PROFILES` registry in `src/derive.js`. A future `v2` registers its own KDF —
  contract in `docs/specs/2026-09-01-kunji-v2-profile-requirements.md`."*
- **§13** — remove the "v1 KDF cost" and "`max-symbols` character set" bullets;
  add a one-line "Resolved in Phase 5a" note in their place. The "shared family
  master" and "`identityHint` default" bullets stay.

## 6. `v2` requirements reference doc

`docs/specs/2026-09-01-kunji-v2-profile-requirements.md` — short, ~1 page:

- **Interface:** `deriveMasterKey(passphrase: string, normalisedIdentity: string)
  → Promise<Uint8Array(32)>`. Deterministic. No salt input beyond the identity,
  no cost knobs in the signature (cost is baked into the profile).
- **Primitive:** memory-hard. Argon2id (RFC 9106) preferred; scrypt acceptable;
  a browser-native Argon2 if one ships. Pure JS, zero dependencies. WASM only if
  the no-network + CSP invariants (`check-invariants.mjs`) still hold — currently
  they would not, so effectively pure JS.
- **CI gate:** every applicable RFC test vector passes before the profile may be
  registered. A drift in output fails the vector test the same way v1's does.
- **Cost target:** ≤ ~1.5 s for one derivation on the slowest supported device;
  `p = 1`.
- **Registration:** one object added to `PROFILES` (`id`, `label`,
  `deriveMasterKey`, unique `kdfTag`). No change to `src/derive.js` Steps 2–6.
- **Migration:** per entry — `entry.profile = 'v2'`, re-derive, change the
  password at the site. Whole-vault re-key (new envelope under v2) is a separate
  explicit action. Never automatic, never global.
- **Coexistence:** a vault may hold `v1` and `v2` entries simultaneously; the
  envelope itself stays on whatever profile it was created under until an
  explicit re-key.

## 7. Testing

- **Frozen vectors unchanged.** `tests/vectors/v1.json` and
  `tests/vectors.test.mjs` pass byte-for-byte — the primary proof the seam is
  transparent. No edits to either file.
- **`tests/derive.test.mjs`** (extend):
  - `DEFAULT_PROFILE === 'v1'`; `Object.keys(PROFILES)` is exactly `['v1']`.
  - `profileOf('v1')` returns an object with `id === 'v1'` and a `kdfTag` of
    `pbkdf2-sha512-600000`.
  - `profileOf('v2')` / `profileOf('')` throw `unknown profile:`.
  - `deriveMasterKey(p, i)` (two args) deep-equals `deriveMasterKey(p, i, 'v1')`
    deep-equals `pbkdf2Sha512(utf8(p), utf8(normaliseInput(i)), 600000, 32)` for a
    fixed `(p, i)`.
  - `derivePassword({ ...input })` (no `profile`) equals
    `derivePassword({ ...input, profile: 'v1' })`.
  - `derivePassword({ ...input, profile: 'v2' })` rejects with `unknown profile:`.
- **Speed-sensitive tests.** Grep the suite for `deriveMasterKey(` calls that
  pass a third argument (an iteration count like `1000` or `vectors.iterations`).
  Each moves to a direct `pbkdf2Sha512(utf8(pass), utf8(normaliseInput(id)), n, 32)`
  call, or — for the vector tests, which need the *real* `deriveMasterKey`
  contract — stays as-is but drops the third arg (the vector file's high-cost
  case already uses `PBKDF2_ITERATIONS`; the low-cost `cases` use
  `vectors.iterations = 1000`). **Decision:** the vector test keeps a low-iter
  path by calling `pbkdf2Sha512` directly for the `cases` loop and the real
  `deriveMasterKey` for the `highCost` case (which uses the frozen 600k). This
  keeps `PROFILES` free of a test entry. The plan enumerates each touched call
  site with before/after.
- **`tests/vault.test.mjs`** (extend): `parseEnvelope` accepts a header with
  `kdf: "pbkdf2-sha512-600000"`; rejects `kdf: "argon2id-m65536-t3"` with
  `BadEnvelopeError`; `encodeEnvelope` output's `kdf` equals
  `PROFILES.v1.kdfTag`.
- **`npm run verify`** green; `check-invariants` `ok (17 files)`;
  `dist/kunji.html` differs from pre-5a only by the seam refactor (no behavioural
  change — the vector test is the guarantee).

## 8. Rollout / task order

1. `PROFILES` + `profileOf` + `DEFAULT_PROFILE` in `src/derive.js`; `derive.test.mjs`
   registry tests.
2. Refactor `deriveMasterKey` to route through the registry, drop `iterations`;
   migrate the speed-sensitive test call sites (enumerated in the plan);
   `vectors.test.mjs` still green.
3. `derivePassword` profile dispatch + the `profile: 'v2'` rejection test.
4. Vault envelope `kdf` validation in `parseEnvelope`; `vault.test.mjs` cases.
5. Freeze comments + spec §4.3 / §4.4 / §13 edits.
6. `docs/specs/2026-09-01-kunji-v2-profile-requirements.md`.

Each task is one commit. `npm run verify` green throughout; the frozen v1 vectors
never change.

## 9. Open questions

None. The two that existed (§13 KDF cost, `max-symbols` set) are resolved by
ratification in §5.
