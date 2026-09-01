# Kunji Phase 3d — Sync-conflict detection and per-entry merge

**Date:** 2026-09-01
**Status:** Draft for review
**Authors:** grd + friend
**Parent spec:** `docs/specs/2026-09-01-kunji-design.md` (§5.2 data model, §7.3 "Vault sync between a user's own devices")
**Depends on:** Phase 2 vault (`src/vault.js`, `src/vault-ui.js`), shipped on `main`.

---

## 1. Purpose

Kunji is transport-agnostic: it reads and writes one encrypted blob and the user
moves it around (Syncthing, a private git repo, manual file/QR). Two devices
edited while both offline produce two divergent copies. This phase lets the user
**merge** a second copy into the loaded one instead of choosing which to throw
away — additions kept, deletions honoured via tombstones, per-entry
last-writer-wins, with a one-screen review before anything is applied.

One of five independent Phase 3 sub-projects; its own spec.

## 2. Schema change — tombstones (additive)

Deleting an entry must survive a later merge with a device that still has it.

- `removeEntry(vault, id)` no longer splices. It replaces the entry in
  `entries[]` with a **tombstone**: `{ id, deleted: true, updatedAt: <ISO now> }`
  and **nothing else**. The tombstone stays in `entries[]` **permanently** (no
  compaction). Vault files are tiny; a permanent tombstone guarantees a delete
  beats an arbitrarily stale device.
- The envelope `v` is **not** bumped. `unlockVault`'s shape check is unchanged:
  tombstones are still objects in the `entries` array. `makeEntry` never produces
  one.
- **Every consumer of entries filters tombstones out.** New helper
  `visibleEntries(vault)` = `vault.entries.filter((e) => !e.deleted)`, used by:
  - the Vault-tab list / detail / editor,
  - `entriesForSite` (Phase 3a) — excludes tombstones,
  - `vaultBridge.publish(...)` — publishes `visibleEntries(vault)`.
- `updateEntry` is unchanged; it is never called on a tombstoned id (the UI can't
  reach one). Merge is the only code that inspects `deleted`.

**Parent-spec §5.2** gains: an entry object is either a full entry (Phase 2
schema) **or** a tombstone `{ id, deleted: true, updatedAt }`.

## 3. Pure merge functions (`src/vault.js`)

### 3.1 `mergeVaults(local, incoming)` → `{ vault, summary }`

`local` and `incoming` are decrypted vaults `{ entries, settings, revision, lastWriter }`
(the caller passes `revision`/`lastWriter` from each envelope).

Index both `entries` by `id`. For each `id` in the union:

| Case | Result | Bucket |
|---|---|---|
| id in `local` only | keep local entry | `unchanged` (or local-only) |
| id in `incoming` only | take incoming entry | `added` |
| both, deep-equal | keep local | `unchanged` |
| both live, differ | newer `updatedAt` wins (whole entry) | `updated` |
| local live, incoming tombstone, tombstone newer | tombstone | `deletedByRemote` |
| local tombstone, incoming live, entry newer | entry (resurrected) | `updated` |
| live vs tombstone, live side newer | live entry | `updated` |
| both tombstones | keep newer `updatedAt` | `unchanged` |

Ties on `updatedAt`: break by `lastWriter` string comparison; still tied ⇒ keep
`local`. Deterministic for any input pair, and **commutative in outcome**
(`mergeVaults(a,b).vault` deep-equals `mergeVaults(b,a).vault`; only the
`summary` bucket labels swap `*ByRemote` ↔ `*ByLocal`).

- **`settings`:** taken from whichever side has the higher `revision`; tie ⇒
  `local`.
- **Order:** merged `entries` = local order first (each id resolved as above),
  then incoming-only ids appended in incoming order.
- **`summary`** = `{ added: id[], updated: id[], deletedByRemote: id[], deletedByLocal: id[], unchanged: number }`.
  `deletedByLocal` = ids where the local tombstone won over a live incoming entry.

`mergeVaults` does not set `revision` — the caller does (§4.3).

### 3.2 `classifyIncoming(localEnv, localVault, inEnv, inVault)` → string

- `inEnv.kcv !== localEnv.kcv` → `'wrong-passphrase'`
- `mergeVaults(local, incoming).vault` deep-equals `localVault` (entries+settings)
  → `'same'` (incoming adds nothing)
- merged deep-equals `inVault` **and** `inEnv.revision >= localEnv.revision`
  → `'fast-forward'`
- otherwise → `'diverged'`

Pure; no crypto, no DOM.

## 4. Vault-tab wiring (`src/vault-ui.js`)

### 4.1 Open a file while `state === 'UNLOCKED'`

Parse it (`parseEnvelope`). Decrypt with the **current** `masterKey`
(`unlockVault` / `openVault`). Then `classifyIncoming(loadedEnvelope, vault, inEnv, inVault)`:

| Result | Dialog |
|---|---|
| `wrong-passphrase` | "That file uses a different passphrase — can't compare." · **[Replace (re-unlock)]** · **[Cancel]** |
| `same` | "That copy has nothing new." · **[OK]** (stay) |
| `fast-forward` | "That copy is newer (rev N) and already has everything you do." · **[Use it]** · **[Cancel]** |
| `diverged` | "That copy (rev N) and yours (rev M) both have changes." · **[Merge]** · **[Replace with that copy]** · **[Cancel]** |

`[Merge]` and `[Use it]` route to the merge summary screen (§4.2). `[Replace …]`
and the Phase 2 unsaved-changes guard behave as today.

### 4.2 Merge summary screen

Reached by `[Merge]` / `[Use it]` above, or by the **`Merge another copy…`**
button added to the unlocked list footer (which opens its own file picker and
always lands here, even for `fast-forward`).

```
  ‹ Cancel                              Apply merge
  Merging rev 7 into your rev 5

  Added from that copy        3   ▸
  Updated (newer wins)        2   ▸
  Deleted by that copy        1   ▸
  Deleted here (kept deleted) 0
  Unchanged                  40
```

Each `▸` bucket expands to the affected entry names (for tombstones: the id and
its `updatedAt`, since the name is gone). **Apply merge** →
`vault = merged`, `dirty = true`, `mergedFromRevision = max(localRev, inRev)`,
`view = 'list'`, re-render. Nothing is written until the user Saves.

### 4.3 Save after a merge

`saveVault`'s `prevRevision` becomes
`mergedFromRevision ?? Number(loadedEnvelope.revision) ?? 0`, so the saved
`revision = mergedFromRevision + 1` and `lastWriter` = this device's `writerId`.
After a successful save: `mergedFromRevision = null`; `loadedEnvelope` adopts the
new envelope (Phase 2 behaviour).

### 4.4 Decoy interaction (Phase 3b)

Merge operates on the **active** vault only (real or decoy). Importing a file
merges its real slot into an active real vault, or its decoy slot into an active
decoy vault; the inactive slot is untouched. If `classifyIncoming` is run, it
compares like-for-like slots.

## 5. Parent-spec updates

- **§5.2** — document the tombstone shape (§2).
- **§7.3** — "field-level last-writer-wins" → "**entry-level** last-writer-wins by
  `updatedAt`, ties broken by `lastWriter`"; tombstones are kept permanently;
  conflict handling is **import-driven** (the app opens files the user picks; it
  cannot scan a directory for `*.sync-conflict-*` siblings).
- **§12**, phase 3 bullet — sync merge is specified in
  `2026-09-01-kunji-phase3d-sync-merge-design.md`.

## 6. Files changed

| File | Change |
|---|---|
| `src/vault.js` | `removeEntry` → tombstone; + `visibleEntries`, + `mergeVaults`, + `classifyIncoming`. |
| `src/vault-ui.js` | list/detail/editor use `visibleEntries`; open-while-unlocked routes through `classifyIncoming`; the merge summary screen; `Merge another copy…` footer button; `mergedFromRevision` state; `saveVault` revision base; bridge publishes `visibleEntries`. |
| `src/style.css` | `.v-merge-*` (summary rows, expand, bucket counts). ~20 lines. |
| `tests/vault.test.mjs` | update `removeEntry` expectation; + `visibleEntries`, `mergeVaults`, `classifyIncoming` suites. |
| `docs/specs/2026-09-01-kunji-design.md` | §5.2, §7.3, §12 edits. |
| `tools/check-invariants.mjs` | none. |

## 7. Testing

**Unit — `tests/vault.test.mjs`**
- `removeEntry`: the id is replaced by `{ id, deleted:true, updatedAt }`, no other
  keys; `entries.length` is unchanged; a second `removeEntry` on the same id is
  idempotent. (Rewrites the Phase 2 "drops by id" test.)
- `visibleEntries`: filters `deleted`, keeps order, doesn't mutate.
- `mergeVaults`:
  - add-only (incoming has a new id) → `added`, both originals intact.
  - update: incoming entry newer → taken; local newer → kept; equal → `unchanged`.
  - delete wins: incoming tombstone newer than local live entry → tombstone,
    `deletedByRemote`.
  - resurrect: incoming live entry newer than local tombstone → entry, `updated`.
  - both tombstones → newer kept.
  - tie on `updatedAt` → `lastWriter` order decides; still tied → local — assert
    determinism by running both argument orders.
  - `settings` follows the higher `revision`.
  - order stability: local ids first in local order, incoming-only appended.
  - outcome commutativity: `mergeVaults(a,b).vault` deep-equals
    `mergeVaults(b,a).vault`.
- `classifyIncoming`: `wrong-passphrase` (kcv differs), `same` (identical),
  `fast-forward` (incoming = superset, higher revision), `diverged` (each has a
  unique change).

**Manual browser**
- Device A: unlock, add "Router", delete "OldThing", Save → `a.json` (rev 6).
- Device B (fresh reload): unlock the *original*, add "NAS", Save → `b.json` (rev 6).
- Open `a.json`, unlock, then Open `b.json` → `diverged` dialog → Merge →
  summary shows Added 1 (NAS), Deleted by that copy 0, Deleted here 1 (OldThing)…
  → Apply → Save → reopen: has Router + NAS, no OldThing.
- Fast-forward: from rev 6 open a rev 8 file that includes everything → "Use it".
- Wrong-passphrase import → the "different passphrase" dialog, no merge offered.
- `Merge another copy…` button always reaches the summary, even for a stale file
  (shows all-zero buckets + Unchanged N).
- Account picker / bridge never surface tombstoned entries.
- `npm run verify` green; no console errors; zero network.

## 8. Out of scope

- No per-field timestamps, vector clocks, or CRDT. Entry-level LWW only.
- No automatic directory / sync-conflict-sibling scanning — import is
  user-driven file open.
- No interactive per-entry conflict resolution UI — the summary is
  review-then-apply, take-it-or-cancel.
- No envelope `v` bump; no change to `deriveVaultKey` / the `v1` profile /
  vectors.
- No QR as a merge transport — Phase 3e.
- Tombstone compaction is explicitly *not* implemented (kept forever).

## 9. Self-review

- **Placeholders:** `mergeVaults` and `classifyIncoming` are fully specified by
  the §3 tables; the plan supplies exact code and frozen example pairs. No TBDs.
- **Consistency:** the "tombstones filtered everywhere" rule (§2) is enforced via
  the single `visibleEntries` helper wired into every consumer (§2, §6); the
  merge never bypasses it because it operates on raw `entries` deliberately.
  "Nothing written until Save" (§4.2) matches Phase 2's manual-download model.
- **Scope:** one changed function + two new pure functions + one helper + Vault-
  tab wiring. Additive schema, no `v` bump, no dependency. Fits one plan.
- **Ambiguity:** every merge case is enumerated with a deterministic winner (§3.1
  table + tie-break); `classifyIncoming`'s four outcomes are mutually exclusive
  and ordered; the revision math after merge is pinned (§4.3).
- **Compat note:** `removeEntry` changing shape is an intentional, unreleased-
  code evolution; the Phase 2 test is rewritten, not broken in spirit.
