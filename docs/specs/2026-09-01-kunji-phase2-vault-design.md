# Kunji Phase 2 — Vault design spec

**Date:** 2026-09-01
**Status:** Draft for review
**Authors:** grd + friend
**Parent spec:** `docs/specs/2026-09-01-kunji-design.md` — sections 4.6, 4.7, 5, 6,
7.3 are the source of truth for every frozen detail. This document adds the
Phase 2 decisions and the implementation surface.

---

## 1. Purpose and scope

Phase 1 shipped a single auditable `kunji.html` that derives a deterministic
password from identity + master passphrase + site + account, with no persistence.
Phase 2 adds **the vault**: an encrypted `kunji-data.json` file that stores the
things pure derivation cannot express — custom rules, counters, PINs, 2FA
recovery codes, TOTP secrets, notes, and SSO pointers.

The vault is **optional and additive**. The Phase 1 generator keeps working
unchanged with no vault, which is what the memory-only recovery story in parent
spec section 6.1 depends on.

### In scope

- `deriveVaultKey` (one HKDF from the existing master key) and AES-256-GCM
  encrypt/decrypt wrappers over `crypto.subtle`.
- `kunji-data.json` envelope: encode/decode, including the always-present random
  `decoy` section so files with and without a decoy are byte-indistinguishable.
- Vault lifecycle: **create** a new vault, **open** a file, **unlock** with the
  master passphrase (reusing the Phase 1 KCV for instant pre-decrypt feedback),
  edit in memory, **save** (download a fresh file), **auto-lock** after 5 minutes
  idle.
- A **Vault tab** beside the untouched **Generate tab**: locked view → two-line
  entry list → entry detail → entry editor.
- Entry types `password` and `sso` per parent spec section 5.2. TOTP secret and
  recovery codes are **stored and displayed only** — no live code generation.
- `identityHint` written to the plaintext envelope only when the user opts in.

### Out of scope (which phase owns it)

- Decoy **authoring / opening** behaviour → Phase 3. Phase 2 only reserves the
  random blob.
- Generate-tab account picker / live vault matching (parent spec 5.3) → Phase 3.
  The Generate tab has zero vault awareness in Phase 2.
- QR import/export, sync-conflict detection and per-entry merge (parent spec
  7.3), service worker / PWA manifest → Phase 3.
- Reproducible-build script, release checksums, signed tags, CI gates → Phase 4.
- Argon2id `v2`, WebAuthn unlock, live TOTP → Phase 5.

### File-handling model (decided)

**Manual load/save only.** "Open vault file…" is a file picker; "Save vault"
triggers a browser download of `kunji-data.json`. The app holds no vault data
between sessions and has no filesystem handle. This is the only model uniform
across all five target platforms (parent spec section 11), and it keeps the
hygiene story airtight: nothing at rest except the file the user controls.
File System Access API ergonomics can be added later as a pure enhancement
without touching the data model.

---

## 2. Architecture and modules

The build stays a plain concatenation into one `dist/kunji.html`
(`tools/build.mjs`). `JS_ORDER` grows to:
`encoding → webcrypto → derive → vault → app → vault-ui`.

| File | Change | Responsibility |
|---|---|---|
| `src/encoding.js` | none | unchanged |
| `src/webcrypto.js` | **add** `aesGcmEncrypt`, `aesGcmDecrypt` | thin typed `crypto.subtle` wrappers, no app logic |
| `src/derive.js` | **add** `deriveVaultKey(masterKey)` | one more HKDF; a frozen v1 detail |
| `src/vault.js` | **new** | pure, no-DOM vault domain logic: envelope `encodeEnvelope` / `decodeEnvelope`, `createVault`, `unlockVault`, `lockVault`, `addEntry` / `updateEntry` / `removeEntry`, dirty tracking, `revision` bump, `newDecoyBytes` |
| `src/app.js` | **refactor** | tab shell + the Generate tab. Phase 1 logic moves behind a tab; its behaviour is otherwise byte-for-byte the same (same DOM ids, same `derivePassword` call, same hygiene). |
| `src/vault-ui.js` | **new** | the Vault tab only: file open/save, the six view states, the 5-minute idle timer, dirty bar, `beforeunload` guard |
| `src/head.html` | **edit** | add the tab strip and the Vault tab's markup containers |
| `src/style.css` | **edit** | tab styles, list rows, detail sections, editor fields, the unsaved-changes bar. Reuse the existing palette and `.kcv` component. |
| `tools/build.mjs` | **edit** | extend `JS_ORDER` |
| `tools/check-invariants.mjs` | none | still applies to the larger `src/` and `dist/` |

### Isolation boundaries

- `src/vault.js` is **pure**: it takes bytes and objects, returns bytes and
  objects, throws typed errors. It never touches the DOM, `document`, timers, or
  downloads. It is unit-tested in Node exactly like `derive.js`.
- `src/vault-ui.js` owns everything stateful and browser-specific for the Vault
  tab. It calls `vault.js` and `derive.js`; it does not reach into `app.js`
  internals. The two tabs share only the DOM tab-strip and the `deriveMasterKey`
  / `computeKcv` / `derivePassword` functions already in scope after
  concatenation.
- Splitting the Vault UI out of `app.js` keeps each file small enough to hold in
  context and keeps the audited Generate path readable on its own.

---

## 3. Crypto and data model

### 3.1 Vault key (frozen v1 detail, added to `derive.js`)

```
vaultKey = HKDF(SHA-256, ikm = masterKey, salt = utf8("kunji/v1"),
                info = utf8("vault-key"), L = 32)
```

`masterKey` is exactly Phase 1's `deriveMasterKey(passphrase, identity)` output
(PBKDF2-SHA512, `PBKDF2_ITERATIONS`, normalised identity as salt). Unlocking the
vault therefore needs the same identity + master passphrase that drives the
generator: one secret, one KCV.

### 3.2 Envelope: `kunji-data.json` (plaintext outer, parent spec 5.1)

```jsonc
{
  "format": "kunji-data",
  "v": 1,
  "kdf": "pbkdf2-sha512-600000",   // profile that produced vaultKey/kcv; string mirrors PBKDF2_ITERATIONS
  "identityHint": null,             // string only if the user opts in (3.5)
  "kcv": "aB3d",                    // 4-byte base64 — identical to Phase 1 computeKcv(masterKey)
  "iv": "…",                        // 12 random bytes, base64, regenerated every save
  "ct": "…",                        // AES-256-GCM(plaintext JSON) + 16-byte tag, base64
  "decoy": { "kcv": "…", "iv": "…", "ct": "…" },  // random bytes of a plausible length until Phase 3
  "revision": 42,                   // integer, +1 on every successful save
  "lastWriter": "…",                // random UUID generated once per session; real per-install id lands in Phase 3
  "updatedAt": "2026-09-01T00:00:00Z"  // ISO 8601, set on save
}
```

- **Encrypt:** `AES-256-GCM`, key = `vaultKey`, fresh random 12-byte IV per save,
  `additionalData = utf8("kunji-vault-v1")`. All randomness from
  `crypto.getRandomValues`.
- **Wrong passphrase:** the entered passphrase's `computeKcv(masterKey)` is
  compared to the envelope `kcv` first — a mismatch rejects instantly with no
  decrypt attempt. A KCV collision (1 in 2^32) still fails at the GCM tag. Both
  surface to the user as "could not unlock this vault".
- **`decoy`:** always written. When no real decoy is configured (all of Phase 2),
  `newDecoyBytes()` produces `{ kcv, iv, ct }` filled with random bytes whose
  lengths match a real small vault, so a file without a decoy is
  byte-indistinguishable from one with a decoy. Phase 2 unlock logic checks only
  the real `kcv`; it never tries the decoy `kcv`.
- **`kdf` string:** informational, records which KDF profile made the key. If
  `PBKDF2_ITERATIONS` changes before v1 freeze, this string changes with it and
  old files carry the old value (they still decrypt — the count that matters is
  the one that made *their* key, and that is fixed once a file exists).

### 3.3 Decrypted plaintext (parent spec 5.2)

```jsonc
{
  "entries": [ /* see 3.4 */ ],
  "settings": {
    "clipboardClearSeconds": 25,
    "revealSeconds": 20,
    "defaultRules": "standard",
    "defaultLength": 20,
    "autoLockMinutes": 5
  }
}
```

`settings` seeds a new vault with these defaults. The Generate tab continues to
use its own hardcoded Phase 1 constants in Phase 2; wiring `settings` into the
Generate tab is a Phase 3 concern (it belongs with the account-picker coupling).
`autoLockMinutes` is read by the Vault tab.

### 3.4 Entry schemas

**`type: "password"`**

| field | notes |
|---|---|
| `id` | uuid v4, `crypto.randomUUID()` |
| `name` | display label, required |
| `site` | required; stored as entered, normalised at derive time by `derivePassword` |
| `account` | required |
| `profile` | `"v1"` (only value in Phase 2) |
| `counter` | integer ≥ 1, default 1 |
| `length` | integer 8..64, default 20 |
| `rules` | `"standard"` \| `"letters-digits"` \| `"max-symbols"`, default `"standard"` |
| `notes` | free text, default `""` |
| `totp` | base32 string or `null`; **stored and displayed only** |
| `recoveryCodes` | array of strings, default `[]` |
| `updatedAt` | ISO 8601, set on entry edit |

**`type: "sso"`**

| field | notes |
|---|---|
| `id`, `name`, `site`, `account`, `notes`, `updatedAt` | as above |
| `via` | `{ site, account }` pointing at the underlying password entry to log in with |

No password is derived for `sso` entries. The editor swaps the
Length/Rules/Counter row and the password block for a single "Log in via"
site+account pair.

### 3.5 `identityHint`

Off by default. A checkbox — "Prefill identity on devices that open this file" —
writes the current identity string into the **plaintext** `identityHint` field of
the envelope. It sits next to a one-line caveat: *anyone who has this file can
read this.* When unchecked (default), the field is `null` and identity is never
written anywhere.

### 3.6 Scheme lock (tests)

AES-GCM with a random IV is not reproducible, so the frozen tests are:

- **Decrypt vector** — fixed `vaultKey`, `iv`, `ct`, `aad` → known plaintext
  bytes. Committed in `tests/vault.test.mjs`. Any change to the GCM parameters or
  AAD breaks it.
- **`deriveVaultKey` vector** — fixed `masterKey` → fixed 32 bytes. Committed in
  `tests/derive.test.mjs`.
- **Round-trip** — `encodeEnvelope(createVault(...))` then `decodeEnvelope` +
  `unlockVault` returns the original entries.
- **Wrong passphrase** — a different master passphrase fails, via KCV mismatch
  and (with a forced KCV match) via GCM tag failure.
- **Decoy presence** — every `encodeEnvelope` output has a `decoy` object with
  non-empty `kcv`/`iv`/`ct` whose lengths are in the expected range.

---

## 4. Vault lifecycle / state machine

The Vault tab is a small state machine. The Generate tab is unaffected by all of
it.

```
NO_VAULT ──"Open vault file…"──▶ parse envelope ──▶ LOCKED
   │                                 └─ not a kunji-data file ──▶ error, stay NO_VAULT
   └──"Create a new vault"──▶ CREATE ──submit──▶ UNLOCKED (empty, dirty)

CREATE: identity + master passphrase + confirm passphrase (same inputs that drive
        the generator). Produces an empty UNLOCKED vault marked dirty. Nothing
        exists on disk until the first Save.

LOCKED ──type passphrase──▶ live KCV check (green = matches envelope kcv, red = not)
   ├──"Unlock"──▶ deriveMasterKey → computeKcv gate → deriveVaultKey → AES-GCM decrypt
   │                 ├─ ok ──▶ UNLOCKED
   │                 └─ tag failure ──▶ error, stay LOCKED
   └──"Open a different file"──▶ (confirm if dirty) ──▶ LOCKED (new file)

UNLOCKED ── list ⇄ entry detail ⇄ entry editor
   │  idle timer = settings.autoLockMinutes (default 5), resets on any keypress or
   │  tap inside the Vault tab
   ├──"Save vault"──▶ re-encrypt (fresh IV), revision +1, updatedAt = now,
   │                   download kunji-data.json, clear dirty  ──▶ stays UNLOCKED
   ├──"Lock" / idle fires / tab closed ──▶ wipe entries + vaultKey + dirty ──▶ LOCKED
   └──"Create" or "Open different" while dirty ──▶ confirm discard first
```

- **Re-lock keeps the loaded file** (envelope only, still encrypted) in memory,
  so re-unlocking after an idle lock is just the passphrase — no re-picking the
  file. Leaving `NO_VAULT` is the only way to fully drop the file reference.
- **Unsaved edits + idle lock:** the idle timer resets on every interaction, so
  active editing never triggers a lock. If the timer fires with unsaved edits,
  they are discarded — the security guarantee wins. Guards against accidental
  loss: a persistent "Unsaved changes — Save vault" bar whenever dirty, and a
  `beforeunload` prompt on tab close while dirty.
- **Save is a plain download** — file lands in the browser's download folder as
  `kunji-data.json`. After the first save in a session, a one-time note:
  *"Move this to wherever your sync watches, and overwrite the previous copy."*
- **Unlock enabled state:** the Unlock button is always clickable. On a red KCV
  it short-circuits to "that is not the passphrase for this vault" without a
  decrypt attempt.

---

## 5. UI spec

Reuses the Phase 1 palette, type scale, and the `.kcv` dot component (parent spec
section 10). New surface:

### 5.1 Tab strip

Two tabs at the top of the existing card: **Generate** | **Vault**. Active tab is
`#E7E9EA` / 700 with a 2px `#1D9BF0` underline; inactive is `#8B98A5`. Costs
~40px above the fields. The card, border, width `min(400px, 100%)`, radius, and
padding are unchanged. The Generate tab's contents are exactly Phase 1.

### 5.2 Vault tab — six states

1. **No vault.** One paragraph of muted explainer ("stores custom rules, PINs,
   2FA recovery codes and notes; encrypted with your master passphrase; optional
   — the generator works without it"), a ghost "Open vault file…" button, and a
   "Create a new vault" text link.
2. **Create.** Identity, Master passphrase, Confirm passphrase (floating-label
   fields, same style as Generate). "Create vault" white pill. Muted line: "Same
   identity + passphrase as the generator."
3. **Locked.** Muted "kunji-data.json · loaded" line, Identity (prefilled from
   `identityHint` if present, else editable), Master passphrase with the KCV dot
   below (green "key verified (xxxx)" / red "not this vault's passphrase"),
   "Unlock" pill, "Open a different file" link.
4. **Unlocked — list.** Header "Vault · N" and a "+ New" link. Search field
   (client-side filter over name / site / account). Two-line rows: `name` at
   13px/700, `site · account` at 10px/`#8B98A5`; `sso` rows show "via <provider>"
   and an `SSO` chip. Footer: "Save vault · Lock · auto-locks in M:SS". A yellow
   "Unsaved changes — Save vault" bar appears above the footer whenever dirty.
5. **Entry detail.** Back link ("‹ Vault") and "Edit" link. Name, `site ·
   account`, a row of chips (`v1`, `len 20`, `standard`, `counter 1`). Masked
   password value in `ui-monospace` 19px grouped in fours, with "Reveal" (re-
   hides after `revealSeconds`) and "Copy" (clipboard auto-clears after
   `clipboardClearSeconds`) — the same reveal/copy behaviour and timers as the
   Generate tab. Then stacked sections separated by hairlines: **Notes**,
   **Recovery codes · N** (tap to reveal/copy, individually), **TOTP secret**
   (shown as text with a copy link; no live code). For `sso` entries the chips
   and password block are replaced by "Log in via <site> · <account>".
6. **Entry editor.** "‹ Cancel" and "Done" links. Fields: Name, Type
   (password / sso select), Site, Account. For `password`: a three-up row of
   Length, Rules, Counter, then Notes, TOTP secret, Recovery codes (one per
   line). For `sso`: a "Log in via" site + account pair instead of the
   Length/Rules/Counter row and the code fields. A red "Delete entry" link at the
   bottom (confirm before removing). "Done" validates (name/site/account
   non-empty, length 8..64, counter ≥ 1) and returns to detail; "Cancel"
   discards the field edits.

### 5.3 Hygiene (extends parent spec section 10)

- Decrypted entries and `vaultKey` live only in `vault-ui.js` closure state,
  never in `localStorage`, `sessionStorage`, IndexedDB, or a service-worker
  cache.
- Idle lock and `beforeunload` are the two clearing paths in addition to manual
  Lock.
- Revealed passwords and revealed recovery codes re-mask on the same timers as
  the Generate tab.
- `autocomplete="off"`, `spellcheck="false"` on the passphrase and secret fields.

---

## 6. Error handling

| Situation | Behaviour |
|---|---|
| Selected file is not JSON / not `format: "kunji-data"` / `v` unknown | Stay in `NO_VAULT`, inline error: "That does not look like a Kunji vault file." |
| Envelope JSON valid but a required field missing/malformed | Same as above; never partially load. |
| KCV mismatch on Unlock | Red dot, "That is not the passphrase for this vault." No decrypt attempt. |
| KCV match but GCM tag failure | "Could not unlock — the file may be corrupted or from a different passphrase." Stay `LOCKED`. |
| Decrypted plaintext is not the expected shape | Treat as corrupt: "Vault contents could not be read." Stay `LOCKED`, do not enter `UNLOCKED` with a half-parsed model. |
| `crypto.subtle` unavailable | Vault tab shows "This browser lacks Web Crypto; the vault needs it." Generate tab already handles this in Phase 1. |
| Download blocked by the browser | Keep dirty state, show "Save was blocked — allow downloads for this page and try again." |
| Duplicate `site + account` on Done | Warn ("An entry for this site and account already exists"), let the user confirm or change it. |
| `sso` `via` points at a deleted entry | Detail shows "linked entry missing" rather than erroring. |

All `vault.js` failures are typed errors (`BadEnvelopeError`, `WrongPassphraseError`,
`CorruptVaultError`) so `vault-ui.js` can map them to copy without string
matching.

---

## 7. Testing

**`tests/vault.test.mjs` (new)** — pure logic in Node:
- envelope round-trip (`createVault` → `encodeEnvelope` → `decodeEnvelope` →
  `unlockVault` returns identical entries + settings)
- wrong passphrase: KCV-gated rejection, and GCM-tag rejection with a forced KCV
  match
- committed **decrypt vector**: fixed `vaultKey` + `iv` + `ct` + `aad` → known
  plaintext
- `decoy` object always present with plausible-length random `kcv`/`iv`/`ct`
- `revision` increments on each `encodeEnvelope`; `updatedAt` is ISO 8601
- entry CRUD: `addEntry` assigns a uuid and `updatedAt`; `updateEntry` bumps
  `updatedAt`; `removeEntry` drops by id
- `identityHint` is `null` unless explicitly set; when set it is the raw identity
  string
- typed errors thrown for each malformed-input case in section 6

**`tests/webcrypto.test.mjs` (extend)** — `aesGcmEncrypt` / `aesGcmDecrypt`
against a published AES-256-GCM test vector; round-trip; tampered ciphertext and
tampered AAD both throw.

**`tests/derive.test.mjs` (extend)** — `deriveVaultKey` determinism and exact
HKDF parameters (`salt "kunji/v1"`, `info "vault-key"`, `L 32`), plus the
committed fixed-input vector.

**`tests/build.test.mjs` (extend)** — the built `dist/kunji.html` contains the
vault module markers and still trips no `check-invariants` pattern.

**Manual browser checklist** (added to the Phase 2 plan, run on Chrome + Safari):
create a vault, add a `password` and an `sso` entry, Save, reload, Open, Unlock,
verify entries, derive + reveal + copy a password, edit an entry, watch the
dirty bar, let it idle-lock, re-unlock, delete an entry, confirm the downloaded
file is valid JSON with a `decoy` block.

---

## 8. Deferred items and open questions

Deferred (owning phase in parentheses): decoy authoring/opening (3), Generate-tab
account picker and `settings` wiring (3), QR (3), sync-conflict merge (3), service
worker / PWA (3), reproducible build + signing + CI gates (4), Argon2id `v2` /
WebAuthn / live TOTP (5).

Open, to settle during planning or first implementation:
- **`lastWriter` in Phase 2.** Proposed: a random UUID generated once per page
  session. It is only a merge tiebreak hint that Phase 3 uses; a per-session
  value is harmless now. Confirm, or omit the field until Phase 3.
- **Decoy blob sizing.** `newDecoyBytes()` must pick `ct` lengths from a
  distribution that plausibly covers real small vaults without leaking the real
  vault's size. Proposed: fixed nominal size (e.g. ct for ~20 entries) regardless
  of the real vault, revisited when real decoys ship in Phase 3.
- **Recovery-code storage shape.** Array of strings (proposed) vs a single
  newline-joined blob. Array is cleaner for per-code reveal/copy.
- **Parent-spec sync.** Parent spec section 12 lists "decoy section" under
  Phase 2; this document narrows that to "envelope only, behaviour in Phase 3".
  Update parent spec section 12 wording when this design is approved.

---

## 9. Self-review

- **Placeholders:** none. Every section is concrete. The three open questions in
  section 8 each carry a proposed answer.
- **Internal consistency:** module table (section 2) matches the file changes
  named in sections 3–5 and the test files in section 7. The state machine
  (section 4) and the six UI states (section 5.2) are the same six states in the
  same order. `autoLockMinutes` appears in `settings` (3.3), the state machine
  (4), and the UI footer (5.2).
- **Scope:** one implementation plan's worth — new crypto wrappers, one new pure
  module, one refactor, one new UI module, styles, tests. No decoy authoring, no
  sync, no Generate-tab changes. The Generate tab moving behind a tab is the only
  touch to audited Phase 1 code and it preserves ids and behaviour.
- **Ambiguity:** "manual load/save" is pinned in 1; "additive, generator works
  without a vault" is stated in 1 and enforced by keeping the Generate tab
  Phase-1-identical; "TOTP stored only" is stated in 1, 3.4, and 5.2.
