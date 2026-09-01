# Kunji Phase 3b — Decoy authoring

**Date:** 2026-09-01
**Status:** Draft for review
**Authors:** grd + friend
**Parent spec:** `docs/specs/2026-09-01-kunji-design.md` (§2 threat model — "Coerced to open the app (duress)"; §4.7 Decoy)
**Depends on:** Phase 2 vault (`src/vault.js`, `src/vault-ui.js`), shipped on `main`.

---

## 1. Purpose

The envelope already reserves a `decoy` section (`{ kcv, iv, ct }`), today filled
with random bytes sized to the real ciphertext. This phase makes it real: the
user sets a **second (decoy) master passphrase** that unlocks a **prepared fake
vault**. Under coercion the user hands over the decoy passphrase; the coercer
sees a complete, ordinary-looking vault and cannot tell a real one is also in the
file.

One of five independent Phase 3 sub-projects; its own spec.

## 2. Principles

- **The decoy is deception, not cryptographic hiding.** A file inspector knows a
  decoy *may* exist. Kunji's job is to make "has a real decoy" and "has random
  filler" byte-indistinguishable, and to make the decoy-unlocked view
  indistinguishable from a normal unlock.
- **The duress path is safe by construction.** Entering the decoy passphrase
  derives only the decoy key. The real `ct` is AES-256-GCM under the real
  `vaultKey` and simply cannot be decrypted with the decoy key. No code needs to
  "hide" the real vault — it is unreachable.
- **No tell.** Unlocking with the decoy passphrase opens a fully normal unlocked
  vault: no badge, no dot, no "decoy" wording, no decoy-setup panel. The
  `⚠ Editing the DECOY vault` banner appears **only** when the real owner
  deliberately enters decoy authoring from the real vault.

## 3. Crypto & data model

### 3.1 Envelope (unchanged shape)

```jsonc
{
  "format": "kunji-data", "v": 1,
  "kdf": "pbkdf2-sha512-600000",
  "identityHint": null,
  "kcv": "…",  "iv": "…",  "ct": "…",           // real vault
  "decoy": { "kcv": "…", "iv": "…", "ct": "…" }, // real decoy OR random filler
  "revision": 42, "lastWriter": "…", "updatedAt": "…"
}
```

No new fields. `revision` / `lastWriter` / `updatedAt` describe the **file**;
there is no separate decoy revision.

### 3.2 Length matching (`_pad`)

`ct.length` is exactly `plaintext.length` (+16-byte tag). To keep
`ct.length === decoy.ct.length`, `encodeEnvelope` pads the **shorter** of the two
plaintext JSON strings, before encryption, with one extra top-level key:

```jsonc
{ "entries": [...], "settings": {...}, "_pad": "<random base64, length chosen so both JSON blobs are byte-equal>" }
```

- The pad length is computed exactly (binary-search the base64 length until the
  serialised object matches the target byte length). Both plaintexts serialise
  with the same `JSON.stringify` settings the Phase 2 code uses.
- The loader (`openVault` / `unlockVault`) **deletes `_pad`** before returning
  `{ entries, settings }`. `_pad` never reaches the UI or the account-picker
  bridge.
- When there is no real decoy, behaviour is exactly today's: `decoy` is
  `newDecoyBytes(ct.length)` (random `kcv`/`iv`/`ct`), and no `_pad` is added
  (the real plaintext is encrypted as-is; the random decoy `ct` is generated at
  the real `ct` length).

### 3.3 Setup guard

Reject a decoy passphrase whose `computeKcv(decoyMasterKey)` equals the real
`envelope.kcv` (≈ 1 in 2³²): *"That passphrase collides with your real one —
choose a different decoy passphrase."* This keeps unlock routing (§4.1)
unambiguous.

### 3.4 `src/vault.js` changes

| Function | Change |
|---|---|
| `openVault(envelope, { masterKey })` | **new.** Compute `k = computeKcv(masterKey)`. If `k === envelope.kcv` → decrypt `ct` → `{ slot: 'real', entries, settings }`. Else if `k === envelope.decoy.kcv` → decrypt `decoy.ct` → `{ slot: 'decoy', entries, settings }`. Else `throw new WrongPassphraseError(...)`. Each decrypt path reuses the Phase 2 GCM-tag-then-shape checks and strips `_pad`. A random filler `decoy.kcv` will essentially never match, so filler files route to `WrongPassphraseError` as before. |
| `unlockVault(envelope, { masterKey })` | unchanged (real-only primitive; still used where the caller knows it wants the real slot). |
| `encodeEnvelope(vault, opts)` | `opts` gains optional `decoy: { vault, masterKey }`. When present: derive decoy `vaultKey` + `kcv`; pad the shorter plaintext per §3.2; encrypt both; write `decoy: { kcv, iv, ct }` for the real decoy. When absent: unchanged. |
| `padPlaintextTo(obj, targetBytes)` | **new, pure helper.** Returns `obj` with a `_pad` string sized so `utf8(JSON.stringify(...)).length === targetBytes`. Exported for tests. |

## 4. Session model (`src/vault-ui.js`)

### 4.1 Unlock routing

The LOCKED view's Unlock handler calls `openVault(loadedEnvelope, { masterKey })`
instead of `unlockVault`. The returned `slot` is stored as `unlockedSlot`.

- `unlockedSlot === 'decoy'`: proceed exactly as a normal unlock — `vault` = the
  decoy contents, `masterKey` = the decoy key. The UNLOCKED view is the ordinary
  list/detail/editor. **No decoy affordances render.** Save re-encrypts this
  vault into the `decoy` slot (see §4.3) and regenerates a random real `ct` of
  matching length (the owner under duress cannot supply the real key, so the real
  vault is preserved *as-is* from `loadedEnvelope` — its `ct` is copied verbatim,
  only the decoy `ct` and a fresh decoy `iv` change, plus `revision`).
- `unlockedSlot === 'real'`: normal UNLOCKED view **plus** the Decoy section
  (§4.2).

### 4.2 Decoy section (real slot only)

In the list footer, below the identity-hint checkbox:

- **No decoy configured** (`loadedEnvelope.decoy.kcv` does not correspond to a
  key we hold — i.e. we opened as real and have no `decoyMasterKey`):
  `Set up decoy` → decoy passphrase + confirm → §3.3 guard → an empty
  `createVault()` becomes `decoyVault`, `decoyMasterKey` is derived and held,
  the view switches to the decoy with a persistent
  `⚠ Editing the DECOY vault` banner and a `[ real ▾ | decoy ▾ ]` toggle.
- **Decoy configured** (we hold `decoyMasterKey` this session, or we can prove
  one exists — see §4.4): `Change decoy passphrase` (re-derive, keep
  `decoyVault` contents) · `Remove decoy` (confirm; next Save writes random
  filler and drops `decoyMasterKey` / `decoyVault`).

Toggling `[ real | decoy ]` swaps which `{ vault, masterKey }` pair the
list/detail/editor operate on. The `⚠` banner shows iff the decoy pair is active.
The idle-lock, dirty bar, and `beforeunload` guard span both.

### 4.3 Save

`saveVault` calls `encodeEnvelope(realVault, { masterKey: realMasterKey, decoy })`
where `decoy` is `{ vault: decoyVault, masterKey: decoyMasterKey }` when a decoy
is configured this session, otherwise omitted. One download, one `revision` bump,
fresh IVs for both slots.

When `unlockedSlot === 'decoy'` (duress), `saveVault` instead re-emits the
envelope with `ct` (real) copied verbatim from `loadedEnvelope`, the decoy slot
re-encrypted from the edited decoy vault, `revision` bumped. `_pad` sizing uses
the copied real `ct` length as the target.

### 4.4 Knowing a decoy exists without the real owner's decoy key

When opened as **real**, we hold `realMasterKey` but not the decoy passphrase, so
we cannot tell whether `decoy.kcv` is a real KCV or random. Therefore:

- After a real unlock, the Decoy section always starts in the **"Set up decoy"**
  state.
- If the user runs `Set up decoy`, we now hold `decoyMasterKey` and the section
  flips to `Change / Remove`.
- To *manage an existing* decoy the user re-enters its passphrase in
  `Set up decoy` (same field). If `computeKcv` of what they typed equals
  `loadedEnvelope.decoy.kcv`, we decrypt the existing `decoy.ct` into `decoyVault`
  (edit it) rather than starting empty; otherwise it is treated as creating a new
  decoy (overwriting on Save, with a confirm).

`wipe()` clears `decoyVault`, `decoyMasterKey`, `unlockedSlot`, and the active
slot back to `real`.

### 4.5 Account picker interaction (Phase 3a)

`vaultBridge.publish(...)` is fed the **currently active** vault's entries: the
real vault's entries when `unlockedSlot === 'real'` and the `real` slot is
active; the decoy's entries when unlocked as decoy. It is **never** fed the
decoy's entries while the real slot is active. Switching the `[ real | decoy ]`
toggle republishes.

## 5. Parent-spec updates

- **§4.7** — add the `_pad` length-matching mechanism and the §3.3 KCV-collision
  guard; state that unlock routing lives in `openVault`.
- **§12**, phase 3 bullet — note decoy authoring is specified in
  `2026-09-01-kunji-phase3b-decoy-authoring-design.md`.

## 6. Files changed

| File | Change |
|---|---|
| `src/vault.js` | + `openVault`, + `padPlaintextTo`; `encodeEnvelope` optional `decoy`; loader strips `_pad`. |
| `src/vault-ui.js` | Unlock via `openVault`; `unlockedSlot`; the Decoy section; `[ real | decoy ]` toggle; `decoyVault` / `decoyMasterKey` state; `saveVault` real+decoy paths; `wipe()` clears decoy state; bridge publish uses the active vault. |
| `src/style.css` | `.v-decoy-banner` (warning colour, reuses `--danger`-ish token), the slot toggle, the decoy section rows. ~20 lines. |
| `src/head.html` | none (Vault tab renders from JS). |
| `docs/specs/2026-09-01-kunji-design.md` | §4.7 + §12 edits above. |
| `tools/check-invariants.mjs` | none. |

## 7. Testing

**Unit — `tests/vault.test.mjs`**
- `openVault`: real → `slot:'real'` + contents; decoy → `slot:'decoy'` + decoy
  contents; neither → `WrongPassphraseError`; corrupted real `ct` + valid decoy →
  opens decoy.
- `encodeEnvelope` with `decoy`: both slots decrypt under their own keys;
  `ct.length === decoy.ct.length` exactly; `_pad` on the shorter plaintext only;
  `_pad` absent from `openVault` output; `decoy.kcv === computeKcv(decoyMasterKey)`.
- `encodeEnvelope` without `decoy`: byte-shape identical to Phase 2 (random
  `decoy`, no `_pad`), asserted against a Phase 2-style expectation.
- `padPlaintextTo`: hits the exact target byte length for several sizes; output
  parses; `_pad` is the only added key.
- Setup guard: decoy key with `computeKcv === real kcv` is rejected.
- Round-trip: real + decoy authored → encode → `parseEnvelope` → `openVault` both
  ways → entries + settings survive both.
- Duress isolation: opening with the decoy key yields nothing computed from the
  real `masterKey`; the real `ct` is untouched by a decoy-slot save.

**Unit — `tests/vault-bridge.test.mjs`** (extends Phase 3a)
- Publishing the active vault: real entries while real-active; decoy entries while
  decoy-active; never decoy entries while real-active.

**Manual browser**
- Real unlock → `Set up decoy` → passphrase → `⚠ DECOY` banner + toggle → add
  filler entries → Save.
- Reopen with real passphrase → real vault; Decoy section offers manage. Reopen
  with decoy passphrase → ordinary vault, filler entries, **no decoy UI at all**.
- Downloaded file: `ct` and `decoy.ct` equal length; `decoy.kcv` 4 bytes; a
  file with a real decoy is not visibly distinguishable from one with random
  filler.
- `Remove decoy` → Save → decoy passphrase no longer unlocks.
- `Change decoy passphrase` → old stops working, contents preserved.
- Account picker: no decoy entries surface on the Generate tab while unlocked as
  real; when unlocked as decoy the picker uses the decoy's entries.
- `npm run verify` green; no console errors; zero network.

## 8. Out of scope

- No change to `deriveVaultKey` / `deriveMasterKey` / the `v1` profile / vectors.
- No separate `revision` / sync metadata for the decoy — one envelope, one
  `revision`.
- No panic gesture, no auto-decoy after N wrong tries, no third/nested vault.
- No automated "is this decoy believable" checks.
- Decoy is not separately exported / QR'd — Phase 3e handles the whole file.
- No decoy concept on the Generate tab; decoy is a vault-file feature only.

## 9. Self-review

- **Placeholders:** `openVault`, `padPlaintextTo`, `encodeEnvelope`'s `decoy`
  branch are specified by contract; the implementation plan supplies exact code
  and frozen examples (Phase 2 pattern). No TBDs.
- **Consistency:** "no tell" (§2) is enforced in §4.1 (decoy-slot unlock renders
  the plain UNLOCKED view) and §4.5 (bridge never leaks decoy entries to Generate
  while real-active). Length indistinguishability (§3.2) is asserted in tests
  (§7). The duress-safety claim rests only on AES-GCM key separation, not on UI
  hiding.
- **Scope:** two new pure helpers + one changed pure function + Vault-tab wiring.
  No envelope-shape change, no `v` bump, no dependency. Fits one plan.
- **Ambiguity:** unlock routing order (real before decoy) is explicit; managing
  an existing decoy vs creating a new one is disambiguated by KCV match (§4.4);
  the duress save path (real `ct` copied verbatim) is spelled out (§4.3).
- **Risk noted:** if a user sets the same string as real and decoy passphrase the
  §3.3 guard blocks it at setup; a post-hoc real-passphrase change that collided
  with an existing decoy is out of scope (real-passphrase change itself is not a
  Phase 3b feature).
