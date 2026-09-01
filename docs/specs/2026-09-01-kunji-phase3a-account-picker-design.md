# Kunji Phase 3a — Generate-tab account picker

**Date:** 2026-09-01
**Status:** Draft for review
**Authors:** grd + friend
**Parent spec:** `docs/specs/2026-09-01-kunji-design.md` (§5.3 "Multiple accounts on one site")
**Depends on:** Phase 2 vault (`src/vault.js`, `src/vault-ui.js`), shipped on `main`.

---

## 1. Purpose

When a site has more than one account in the vault (three Google identities, a
personal and a work GitHub, …), the user should not have to remember the exact
`account` string they filed it under. If the vault is unlocked this session and
the `site` they type on the **Generate** tab matches one or more vault entries,
Kunji offers a picker: choose the account and the Generate form fills itself with
that entry's `account` and derivation parameters (`counter`, `rules`, `length`).

This finishes the Phase 2 vault ↔ generator integration. It is the first of five
independent Phase 3 sub-projects (picker, decoy authoring, PWA/service worker,
sync merge, QR); each has its own spec.

## 2. Model

**Overlay / parameter lookup.** The Generate tab keeps its existing flow and its
own crypto. Derivation still uses the identity + master passphrase typed on the
Generate tab. The vault is consulted **only** to look up which accounts exist for
a site and what parameters an entry stores. No key, passphrase, or ciphertext
crosses between the tabs.

The picker is active **only while a vault is unlocked in the Vault tab this
session**. With no vault, a locked vault, or zero matches, the Generate tab is
byte-for-byte the Phase 1 experience.

### 2.1 Consistency

A picked `password` entry derives byte-identically to that entry's Vault-tab
detail view **if and only if** the Generate tab's identity + passphrase match the
vault's. The picker still fills fields when the Generate tab's KCV indicator is
not green (it is only form-fill, no crypto), but then shows the hint
*"verify your passphrase above to match your vault."*

## 3. Architecture

### 3.1 New module: `src/vault-bridge.js`

No DOM. One import (`entriesForSite` from `vault.js`). Module-level singleton:

```js
let current = null; // array of entry objects while a vault is unlocked, else null

export function publish(entriesOrNull) {
  current = Array.isArray(entriesOrNull) ? entriesOrNull.map((e) => ({ ...e })) : null;
}
export function clear() { publish(null); }
export function forSite(rawSite) {
  return current ? entriesForSite(current, rawSite) : [];
}
export function isActive() { return current !== null; }
```

`publish` stores a **shallow copy of each entry** so later vault mutations do not
mutate the bridge's view and the caller cannot reach into bridge state.

### 3.2 Pure helpers in `src/vault.js`

```js
// Every entry whose site matches rawSite under the shared normalisation.
// Empty/whitespace rawSite -> []. Order of `entries` is preserved.
export function entriesForSite(entries, rawSite) { … }

// For a pick: a `password` entry resolves to itself; an `sso` entry resolves to
// the underlying entry it points at (site+account === entry.via.*), or null when
// that entry is not in the vault.
export function resolveEntryForPick(entries, entry) { … }
```

Both are pure, deterministic, no `crypto`, no DOM. `entriesForSite` uses
`normaliseInput` from `derive.js` (NFKC + trim + lowercase) on both sides.

### 3.3 Wiring

- **`src/vault-ui.js`** calls `vaultBridge.publish(vault.entries)` on unlock
  success, at the end of every mutation path (add / update / delete — the same
  sites that call `markDirty`), and after `saveVault`. It calls
  `vaultBridge.clear()` inside `wipe()` (so lock, idle-lock, `beforeunload`,
  "open a different file" all clear it).
- **`src/app.js` / `initGenerateTab`** owns a `pickedEntry` closure variable
  (`null` or `{ counter, rules, length }`), a `renderPicker()` function, and the
  pick / clear-on-edit wiring (§4, §5).

### 3.4 Build order

`tools/build.mjs` `JS_ORDER` becomes:
`encoding → webcrypto → derive → vault → vault-bridge → app → vault-ui`.
(`vault-bridge.js` imports from `vault.js`, and both `app.js` and `vault-ui.js`
use it, so it sits after `vault.js` and before `app.js`.)

## 4. Matching & pick semantics

### 4.1 Match

`entriesForSite` returns every entry with
`normaliseInput(entry.site) === normaliseInput(rawSite)` — exact normalised
equality. No substring, no fuzzy, no "did you mean". Empty `rawSite` ⇒ `[]`.

### 4.2 Threshold

The picker renders whenever **≥ 1** entry matches. A single match is a
one-row picker. The picker never fills the form on its own — the parent spec's
"rather than guessing" is read as *always ask*, and a one-tap fill for the
single-match case is within that intent. Zero matches, or `!vaultBridge.isActive()`
⇒ nothing renders.

### 4.3 Picking a `password` entry

1. `account` field ← `entry.account`.
2. `pickedEntry ← { counter: entry.counter, rules: entry.rules, length: entry.length }`.
3. The picked chip (§5) appears; `length` / `rules` inputs show the picked values
   in a muted "filled" style (still editable).
4. `generate()` derives with `counter: pickedEntry.counter ?? 1` and, when
   `pickedEntry` is set, `rules: pickedEntry.rules`, `length: pickedEntry.length`.
5. The result caption (existing entropy line) gains `· counter N` when
   `counter ≠ 1`.

### 4.4 Picking an `sso` entry

Run `resolveEntryForPick(entries, entry)`.

- **Underlying entry found:** rewrite **both** `site` and `account` to the
  underlying entry's values; `pickedEntry` ← its `{ counter, rules, length }`;
  derive that password. Note under the result:
  *"via <news.example.com> — this is your <google.com> password."*
- **Not found:** rewrite `site` / `account` to `entry.via.site` / `entry.via.account`;
  `pickedEntry ← null` (defaults: `standard` / `20` / counter `1`); note:
  *"linked <google.com> entry not in vault — using defaults."*

### 4.5 Pick lifecycle

`pickedEntry` is cleared, the chip removed, and `length` / `rules` returned to
their normal style on any of:

- an `input` event in the `site` **or** `account` field,
- clicking the picked chip's `✕`,
- switching away from the Generate tab,
- `vaultBridge.clear()` (vault locked / wiped).

If vault entries change while a pick is active, the picker list re-renders on the
next `site` interaction; the stale `pickedEntry` is kept until the user edits a
field or re-picks. It only affects the *next* Generate, so this is acceptable.

## 5. UI

A block with id `genPicker`, between the `account` field and the length/rules
`.row`, `hidden` unless `renderPicker()` has ≥ 1 match. Reuses existing tokens
(`.v-row`, `.v-chip`, `.v-meta`, `--blue`, `--muted`).

```
  Site or app  [ google.com                    ]
  Account      [ me@gmail.com              ✕  ]     ✕ = clear pick (only when picked)
  ┌ from your vault ─────────────────────────┐
  │  me@gmail.com          standard · 20     │
  │  work                  max-symbols · 32  │
  │  old                   standard · 20 · #2│     · #N only when counter ≠ 1
  │  news "me"             via google.com    │     sso row
  └─────────────────────────────────────────┘
  Length [ 20 ]   Rules [ standard ]
```

- **Header** `from your vault`, 12 px, `--muted`.
- **Rows** are `.v-row`-style, full-width, ≥ 44 px, keyboard-navigable
  (`role="listbox"` / `option`, ↑/↓ + Enter, Esc collapses).
- **Row content:** account name; then for `password` entries the param chips
  `rules · length` (`· #N` appended when `counter ≠ 1`); for `sso` entries
  `via <site>` in place of chips.
- **On pick:** `account` fills, an `✕` clear-chip appears at the field's right
  edge, the picker collapses to the chosen row (tap it or `✕` to reopen / clear),
  `Length` / `Rules` show muted "filled" style.
- **Notes** (SSO redirect note, "verify your passphrase" hint) render in the
  existing small muted line under the result — no new components.
- **No animation.** The block toggles instantly on `site` change. Honors
  `prefers-reduced-motion` by simply having none.
- **Locked / absent / 0 matches:** `#genPicker` stays `hidden`; the Generate tab
  is pixel-identical to Phase 1.

## 6. Files changed

| File | Change |
|---|---|
| `src/vault.js` | + `entriesForSite(entries, rawSite)`, + `resolveEntryForPick(entries, entry)` — pure, no state. Import `normaliseInput` (already exported from `derive.js`; add to the existing import or import in place). |
| `src/vault-bridge.js` | **new**, ~20 lines. `publish` / `clear` / `forSite` / `isActive`. Imports `entriesForSite` from `./vault.js`. No DOM. |
| `tools/build.mjs` | `JS_ORDER`: insert `src/vault-bridge.js` after `src/vault.js`, before `src/app.js`. |
| `src/vault-ui.js` | `vaultBridge.publish(vault.entries)` on unlock, after add/update/delete, after `saveVault`; `vaultBridge.clear()` in `wipe()`. ~5 one-line call sites. |
| `src/app.js` | `initGenerateTab`: `pickedEntry` var; `renderPicker()` on `site` `change` + debounced `input` and on Generate-tab activation; pick handler (fill, set `pickedEntry`, SSO redirect via `resolveEntryForPick`); clear-on-edit; `generate()` reads picked `counter` / `rules` / `length`; caption + note text. |
| `src/head.html` | `<div id="genPicker" hidden></div>` between the `account` field and the length/rules `.row`. |
| `src/style.css` | `.gen-picker` + row reuse, a `.picked` field modifier, the clear-chip. ~15 lines. |
| `tools/check-invariants.mjs` | none (already scans all of `src/`). |

## 7. Testing

**Unit — `tests/vault.test.mjs` (append)**
- `entriesForSite`: exact normalised match; case + whitespace + NFKC fold on both
  sides; no match ⇒ `[]`; empty / whitespace `rawSite` ⇒ `[]`; multi-match keeps
  input order; does not mutate `entries`.
- `resolveEntryForPick`: `password` entry ⇒ itself; `sso` entry ⇒ the underlying
  entry (matched on normalised `via.site` + `via.account`); `sso` with no
  matching underlying entry ⇒ `null`.

**Unit — `tests/vault-bridge.test.mjs` (new)**
- `isActive()` false before any `publish`; true after `publish([...])`; false
  after `clear()`.
- `forSite` returns `[]` when inactive; returns matches when active.
- The stored list is a copy: mutating the array passed to `publish`, or an entry
  object in it, does not change a later `forSite` result.

**Unit — `tests/build.test.mjs` (append)**
- Built HTML contains `==== src/vault-bridge.js ====`, positioned after
  `src/vault.js` and before `src/app.js`.

**Manual browser regression**
- Multi-account site → picker lists all matches → pick → Generate → value equals
  the Vault-tab detail derive for that entry (identity + passphrase match).
- Counter-≠1 entry: row shows `· #N`, caption shows `counter N`, derived value
  matches a terminal `derivePassword` with that counter.
- SSO entry: pick rewrites site + account to the underlying entry, derives that
  password, shows the "via …" note; SSO with a deleted target shows the
  "using defaults" note.
- Edit `site` (or `account`) after a pick → chip clears, `Length`/`Rules` styling
  resets, counter reverts to 1 on the next Generate.
- Lock the vault (and idle-lock, and reload) → `#genPicker` disappears.
- No vault / vault never unlocked → Generate tab identical to Phase 1; every
  Phase 1 `tests/app.test.mjs` and `tests/vectors.test.mjs` case still passes.
- `npm run verify` green; DevTools: no console errors, zero network requests.

## 8. Out of scope

- No changes to `derive.js`, the `v1` profile, or any frozen vector.
- No visible **counter field** on the Generate tab. Picked counter is silent;
  manual rotation without a vault stays a Vault-tab task.
- No write-back to the vault from the Generate tab. The pick is read-only.
- No fuzzy / substring site matching, no suggestions.
- No changes to reveal / copy timers.
- The bridge is session memory only — never persisted, never `localStorage`,
  never serialised.

## 9. Self-review

- **Placeholders:** the two `vault.js` helpers are specified by contract; their
  bodies are small and deterministic — the implementation plan will give exact
  code and a couple of frozen examples, matching the Phase 2 pattern. No TBDs.
- **Consistency:** the "overlay, no crypto crosses" rule in §2 is upheld
  everywhere — the bridge (§3.1) carries only entry metadata copies; derivation
  (§4.3) stays on the Generate tab's own key. §4.4's SSO redirect only rewrites
  form fields, never keys.
- **Scope:** one module + two pure helpers + wiring in two existing files. No
  schema change, no crypto change, no new dependency. Fits a single plan.
- **Ambiguity:** "match" is pinned to exact normalised equality (§4.1); the
  ≥1 threshold and "never auto-fill" are stated explicitly (§4.2); the pick
  lifecycle enumerates every clear trigger (§4.5).
