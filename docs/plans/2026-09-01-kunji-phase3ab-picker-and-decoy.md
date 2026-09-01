# Kunji Phase 3a + 3b — Account Picker & Decoy Authoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add (A) a Generate-tab picker that fills the form from vault entries when the typed site matches one or more, and (B) a real decoy vault reachable by a second master passphrase, with byte-indistinguishable file output.

**Architecture:** Part A adds one pure module `src/vault-bridge.js` plus two pure helpers in `src/vault.js`; the Vault tab publishes its entries to the bridge, the Generate tab reads them — no key, passphrase, or ciphertext crosses. Part B extracts a shared `decryptSlot` in `src/vault.js`, adds `openVault` (real-KCV then decoy-KCV routing) and `padPlaintextTo`, extends `encodeEnvelope` with an optional `decoy: { vault, masterKey }` that pads the shorter plaintext with a `_pad` filler so `ct.length === decoy.ct.length`, and wires a Decoy section + `[real|decoy]` slot toggle into the unlocked Vault tab.

**Tech Stack:** Node.js ≥ 20 (`node:test`, `globalThis.crypto`), browser Web Crypto (AES-256-GCM, HKDF, PBKDF2), plain HTML/CSS/JS, zero dependencies. Build is concatenation into one `dist/kunji.html` via `tools/build.mjs`.

**Specs:**
- `docs/specs/2026-09-01-kunji-phase3a-account-picker-design.md`
- `docs/specs/2026-09-01-kunji-phase3b-decoy-authoring-design.md`
- Parent: `docs/specs/2026-09-01-kunji-design.md` §4.7, §5.2, §5.3, §7.3, §12.

**Baseline:** Phase 2 + 2.1 complete on `main` (commit `971b57b` or later). `npm run verify` passes (88 tests, build, `invariants ok (10 files)`). Work from `the repository root`, directly on `main`, one commit per task, commit-message trailers:

```
Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01E2FKUJXdFejXkG1iuXB83A
```

Use `git -c commit.gpgsign=false commit` if signing prompts or fails. `node --test` prints `ℹ tests N` / `ℹ pass N` / `ℹ fail 0`; the plan gives per-file deltas and the running total but **`fail 0` is the gate** — if a stated total is off by one, trust `fail 0`.

---

## File structure

| File | Change | Responsibility |
|---|---|---|
| `src/vault.js` | add `entriesForSite`, `resolveEntryForPick` (Part A); extract `decryptSlot`, add `openVault`, `padPlaintextTo`, extend `encodeEnvelope` (Part B); import `normaliseInput` from `derive.js` | pure vault data + envelope crypto |
| `src/vault-bridge.js` | **new** | session hand-off of vault entries to the Generate tab; `vaultBridge` namespace |
| `tools/build.mjs` | `JS_ORDER`: insert `src/vault-bridge.js` after `src/vault.js`, before `src/app.js` | build order |
| `src/head.html` | add `<div id="genPicker" hidden></div>` and `<div class="foot" id="genPickNote" hidden></div>` between the `#account` field and the length/rules `.row` | picker mount point |
| `src/style.css` | `.gen-picker*`, `.field.picked`, `.pick-clear` | picker styling |
| `src/app.js` | `initGenerateTab`: `pickedEntry`, `renderGenPicker`, pick + clear-on-edit wiring, `generate()` counter/rules/length + caption + notes; return `{ refreshPicker }`; `initApp` calls it on show('generate') | Generate-tab picker |
| `src/vault-ui.js` | publish/clear to the bridge (Part A); unlock via `openVault`, slot state, Decoy section, `[real|decoy]` toggle, slot-aware CRUD, `saveVault` real+decoy + duress paths, `wipe()` clears decoy state (Part B) | Vault tab |
| `src/derive.js` | none (already exports `normaliseInput`) | — |
| `tools/check-invariants.mjs` | none (already scans all `src/`) | — |
| `tests/vault.test.mjs` | extend: `entriesForSite`, `resolveEntryForPick`, `padPlaintextTo`, `openVault`, `encodeEnvelope` decoy | — |
| `tests/vault-bridge.test.mjs` | **new** | — |
| `tests/build.test.mjs` | extend: bundle contains + orders `src/vault-bridge.js` | — |
| `docs/specs/2026-09-01-kunji-design.md` | §4.7, §5.3, §12 wording | — |
| `README.md` | one line on the picker + decoy | — |

---

# PART A — Account picker (Tasks 1–6)

## Task 1: `entriesForSite` and `resolveEntryForPick` pure helpers

**Files:**
- Modify: `src/vault.js`
- Test: `tests/vault.test.mjs` (append)

- [ ] **Step 1: Append the failing tests**

Add to the end of `tests/vault.test.mjs`:

```js
import { entriesForSite, resolveEntryForPick } from '../src/vault.js';

const PW = (over = {}) => makeEntry({ type: 'password', name: 'n', site: 's', account: 'a', ...over });
const SSO = (over = {}) => makeEntry({ type: 'sso', name: 'n', site: 's', account: 'a', via: { site: 'g', account: 'x' }, ...over });

test('entriesForSite matches on normalised site equality only', () => {
  const list = [PW({ site: 'GitHub.com', account: 'me' }), PW({ site: '  github.com ', account: 'work' }), PW({ site: 'gitlab.com' })];
  const hit = entriesForSite(list, 'github.com');
  assert.equal(hit.length, 2);
  assert.deepEqual(hit.map((e) => e.account), ['me', 'work']); // input order preserved
});

test('entriesForSite: empty / whitespace / no-match returns []', () => {
  const list = [PW({ site: 'github.com' })];
  assert.deepEqual(entriesForSite(list, ''), []);
  assert.deepEqual(entriesForSite(list, '   '), []);
  assert.deepEqual(entriesForSite(list, 'example.com'), []);
});

test('entriesForSite does not mutate the input array or entries', () => {
  const list = [PW({ site: 'x.com' })];
  const snapshot = JSON.stringify(list);
  entriesForSite(list, 'x.com');
  assert.equal(JSON.stringify(list), snapshot);
});

test('resolveEntryForPick: password entry resolves to itself', () => {
  const e = PW({ site: 'x.com', account: 'me' });
  assert.equal(resolveEntryForPick([e], e), e);
});

test('resolveEntryForPick: sso entry resolves to the underlying entry', () => {
  const google = PW({ site: 'google.com', account: 'me@gmail.com' });
  const news = SSO({ site: 'news.example.com', account: 'me', via: { site: 'Google.com', account: 'ME@gmail.com' } });
  assert.equal(resolveEntryForPick([google, news], news), google);
});

test('resolveEntryForPick: sso with no matching underlying entry returns null', () => {
  const news = SSO({ via: { site: 'google.com', account: 'gone' } });
  assert.equal(resolveEntryForPick([news], news), null);
});

test('resolveEntryForPick: sso with blank via returns null', () => {
  const news = SSO({ via: { site: '', account: '' } });
  assert.equal(resolveEntryForPick([news], news), null);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/vault.test.mjs`
Expected: FAIL — `entriesForSite` / `resolveEntryForPick` are not exported.

- [ ] **Step 3: Implement**

In `src/vault.js`, change the `./derive.js` import line (currently
`import { deriveVaultKey, computeKcv, PBKDF2_ITERATIONS } from './derive.js';`) to:

```js
import { deriveVaultKey, computeKcv, PBKDF2_ITERATIONS, normaliseInput } from './derive.js';
```

Then append to the end of `src/vault.js`:

```js
// --- Phase 3a: account-picker lookups (pure) ---

// Every entry whose site matches `rawSite` under the shared input normalisation.
// Empty/whitespace `rawSite` -> []. Input order is preserved. Does not mutate.
export function entriesForSite(entries, rawSite) {
  const s = normaliseInput(rawSite || '');
  if (!s) return [];
  return entries.filter((e) => e && typeof e.site === 'string' && normaliseInput(e.site) === s);
}

// For a pick: a non-sso entry resolves to itself; an `sso` entry resolves to the
// underlying entry it points at (a non-sso entry whose normalised site+account
// equal the sso entry's `via`), or null when that entry is not present.
export function resolveEntryForPick(entries, entry) {
  if (!entry) return null;
  if (entry.type !== 'sso') return entry;
  const viaSite = normaliseInput((entry.via && entry.via.site) || '');
  const viaAccount = normaliseInput((entry.via && entry.via.account) || '');
  if (!viaSite) return null;
  return entries.find((e) => e && e.type !== 'sso'
    && typeof e.site === 'string' && typeof e.account === 'string'
    && normaliseInput(e.site) === viaSite && normaliseInput(e.account) === viaAccount) || null;
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/vault.test.mjs`
Expected: PASS. Then `node --test` — `fail 0`, total 88 + 7 = 95. Then
`node tools/build.mjs && node tools/check-invariants.mjs` — both green.

- [ ] **Step 5: Commit**

```bash
git add src/vault.js tests/vault.test.mjs
git -c commit.gpgsign=false commit -m "feat: vault entriesForSite + resolveEntryForPick helpers"
```

---

## Task 2: `src/vault-bridge.js` and build wiring

**Files:**
- Create: `src/vault-bridge.js`
- Modify: `tools/build.mjs`
- Test: `tests/vault-bridge.test.mjs` (new), `tests/build.test.mjs` (append)

- [ ] **Step 1: Write the failing tests**

Create `tests/vault-bridge.test.mjs`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { vaultBridge } from '../src/vault-bridge.js';

test('bridge is inactive until publish, then active, then inactive after clear', () => {
  vaultBridge.clear();
  assert.equal(vaultBridge.isActive(), false);
  assert.deepEqual(vaultBridge.forSite('x.com'), []);
  vaultBridge.publish([{ site: 'x.com', account: 'a', type: 'password' }]);
  assert.equal(vaultBridge.isActive(), true);
  assert.equal(vaultBridge.forSite('x.com').length, 1);
  vaultBridge.clear();
  assert.equal(vaultBridge.isActive(), false);
  assert.deepEqual(vaultBridge.forSite('x.com'), []);
});

test('publish(null) or publish(non-array) deactivates', () => {
  vaultBridge.publish([{ site: 'x.com', account: 'a', type: 'password' }]);
  vaultBridge.publish(null);
  assert.equal(vaultBridge.isActive(), false);
});

test('bridge stores a copy: mutating the caller array or an entry does not leak', () => {
  const list = [{ site: 'x.com', account: 'a', type: 'password' }];
  vaultBridge.publish(list);
  list.push({ site: 'x.com', account: 'b', type: 'password' });
  list[0].account = 'CHANGED';
  const got = vaultBridge.forSite('x.com');
  assert.equal(got.length, 1);
  assert.equal(got[0].account, 'a');
  vaultBridge.clear();
});

test('forSite normalises like the rest of the app', () => {
  vaultBridge.publish([{ site: 'GitHub.com', account: 'me', type: 'password' }]);
  assert.equal(vaultBridge.forSite('  github.com ').length, 1);
  vaultBridge.clear();
});
```

Append to `tests/build.test.mjs`:

```js
test('built html inlines vault-bridge, ordered after vault.js and before app.js', () => {
  execFileSync('node', ['tools/build.mjs'], { stdio: 'pipe' });
  const html = readFileSync('dist/kunji.html', 'utf8');
  assert.ok(html.includes('==== src/vault-bridge.js ===='), 'vault-bridge.js concatenated');
  assert.ok(html.indexOf('src/vault.js') < html.indexOf('src/vault-bridge.js'), 'after vault.js');
  assert.ok(html.indexOf('src/vault-bridge.js') < html.indexOf('src/app.js'), 'before app.js');
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/vault-bridge.test.mjs`
Expected: FAIL — `Cannot find module '../src/vault-bridge.js'`.

- [ ] **Step 3: Create `src/vault-bridge.js`**

```js
import { entriesForSite } from './vault.js';

// Session hand-off from the Vault tab to the Generate-tab account picker.
// Holds a copy of the currently-active unlocked vault's entries, or null when
// no vault is unlocked. No key / passphrase / ciphertext ever passes through.
let current = null;

function publish(entries) {
  current = Array.isArray(entries) ? entries.map((e) => ({ ...e })) : null;
}
function clear() {
  current = null;
}
function forSite(rawSite) {
  return current ? entriesForSite(current, rawSite) : [];
}
function isActive() {
  return current !== null;
}

export const vaultBridge = { publish, clear, forSite, isActive };
```

- [ ] **Step 4: Update `JS_ORDER` in `tools/build.mjs`**

Replace the `JS_ORDER` array with:

```js
// Explicit dependency order.
// encoding -> webcrypto -> derive -> vault -> vault-bridge -> app -> vault-ui.
const JS_ORDER = [
  'src/encoding.js',
  'src/webcrypto.js',
  'src/derive.js',
  'src/vault.js',
  'src/vault-bridge.js',
  'src/app.js',
  'src/vault-ui.js',
];
```

- [ ] **Step 5: Run to verify it passes**

Run: `node --test tests/vault-bridge.test.mjs` — PASS (4).
Run: `node --test tests/build.test.mjs` — PASS.
Run: `node --test` — `fail 0`, total 95 + 5 = 100.
Run: `node tools/build.mjs && node tools/check-invariants.mjs` — both green (`invariants ok (11 files)`).

- [ ] **Step 6: Commit**

```bash
git add src/vault-bridge.js tools/build.mjs tests/vault-bridge.test.mjs tests/build.test.mjs
git -c commit.gpgsign=false commit -m "feat: vault-bridge module wired into the bundle"
```

---

## Task 3: Vault tab publishes entries to the bridge

**Files:**
- Modify: `src/vault-ui.js`
- Manual test: `dist/kunji.html` in a browser

Context: `src/vault-ui.js` is concatenated after `src/vault-bridge.js`, so
`vaultBridge` is a bundle global there. The publish must happen on every path that
changes what entries exist for a session: unlock success, create, each entry
mutation, save; and `clear()` in `wipe()`.

- [ ] **Step 1: Add the publish/clear calls**

1. In `wipe()` (starts `function wipe() {` near line 32), add as the **last**
   statement inside the function body, after `identityHintOn = false;`:

```js
    vaultBridge.clear();
```

2. In `onCreate()` (near line 100), immediately after `state = 'UNLOCKED';` and
   before `render();`:

```js
      vaultBridge.publish(vault.entries);
```

3. In the unlock handler (`panel.querySelector('#vlUnlock').addEventListener(...)`,
   the `try` block near line 189), immediately after `state = 'UNLOCKED';` and
   before `render();`:

```js
        vaultBridge.publish(vault.entries);
```

4. In `markDirty()` (currently one line near 211):

```js
  function markDirty() {
    dirty = true;
    if (state === 'UNLOCKED') vaultBridge.publish(vault.entries);
    if (state === 'UNLOCKED' && view === 'list') renderList();
  }
```

5. In `saveVault()`, immediately after `dirty = false;` (the line after the
   `loadedEnvelope = parseEnvelope(text);` adopt-comment block):

```js
    vaultBridge.publish(vault.entries);
```

- [ ] **Step 2: Build + suite**

Run: `node tools/build.mjs && node tools/check-invariants.mjs && node --test`
Expected: build + invariants green; `fail 0`, total still 100 (no new tests —
this is DOM wiring, covered by Task 6's browser check and the bridge unit tests).

- [ ] **Step 3: Manual browser smoke**

`cd dist && python3 -m http.server 8801`, open `http://localhost:8801/kunji.html`.
Console: `vaultBridge.isActive()` → `false`. Vault tab → Create a vault
(`me@x.com` / `pw12345` / `pw12345`) → add an entry `GitHub / github.com / me`
→ console `vaultBridge.isActive()` → `true`; `vaultBridge.forSite('github.com').length`
→ `1`. Click Lock → console `vaultBridge.isActive()` → `false`.

- [ ] **Step 4: Commit**

```bash
git add src/vault-ui.js
git -c commit.gpgsign=false commit -m "feat: vault tab publishes entries to the bridge"
```

---

## Task 4: Picker mount point and styles

**Files:**
- Modify: `src/head.html`
- Modify: `src/style.css`
- Manual test: build only

- [ ] **Step 1: Add the mount elements to `src/head.html`**

Find the `#account` field block inside `<section id="tab-generate">`:

```html
      <div class="field">
        <input id="account" type="text" autocomplete="off" spellcheck="false" placeholder=" ">
        <label for="account">Account</label>
      </div>
```

Immediately **after** that `</div>` and **before** `<div class="row">`, insert:

```html
      <div class="gen-picker" id="genPicker" hidden></div>
      <div class="foot" id="genPickNote" hidden style="text-align:left;margin-top:6px"></div>
```

- [ ] **Step 2: Append to `src/style.css`**

```css
/* Generate-tab account picker (Phase 3a) */
.gen-picker { border: 1px solid var(--border); border-radius: 4px; margin-top: 8px; overflow: hidden; }
.gen-picker .gp-head { font-size: 12px; color: var(--muted); padding: 8px 10px 4px; }
.gen-picker .gp-row {
  display: flex; justify-content: space-between; align-items: baseline; gap: 8px;
  padding: 10px; min-height: 44px; cursor: pointer; border-top: 1px solid #1a1c1f;
}
.gen-picker .gp-row:hover, .gen-picker .gp-row[aria-selected="true"] { background: #16181c; }
.gen-picker .gp-name { font-size: 13px; font-weight: 700; }
.gen-picker .gp-meta { font-size: 11px; color: var(--muted); }
.gen-picker .gp-chip {
  display: inline-block; font-size: 10px; color: var(--muted);
  border: 1px solid var(--border); border-radius: 4px; padding: 1px 5px; margin-left: 4px;
}
.field.picked input { color: var(--muted); }
.pick-clear {
  position: absolute; right: 10px; top: 50%; transform: translateY(-50%);
  background: none; border: none; color: var(--blue); cursor: pointer;
  font: 600 13px inherit; min-height: 44px; padding: 0 6px;
}
```

- [ ] **Step 3: Build + verify unchanged behaviour**

Run: `node tools/build.mjs && node tools/check-invariants.mjs && node --test`
Expected: green; `fail 0`, total 100.
Open `dist/kunji.html`: the Generate tab looks exactly as before (the two new
divs are `hidden`). No console errors.

- [ ] **Step 4: Commit**

```bash
git add src/head.html src/style.css
git -c commit.gpgsign=false commit -m "feat: generate-tab picker mount point and styles"
```

---

## Task 5: Render the picker and handle a `password` pick

**Files:**
- Modify: `src/app.js`
- Manual test: `dist/kunji.html` in a browser

Context: `initGenerateTab` is a closure inside `src/app.js`; `vaultBridge` and
`resolveEntryForPick` are bundle globals after concatenation. This task renders
the picker and wires a `password`-entry pick and the clear-on-edit behaviour.
The SSO redirect, `generate()` counter use, and the caption/note text are Task 6.

- [ ] **Step 1: Add picker state and rendering to `initGenerateTab`**

In `src/app.js`, inside `initGenerateTab`, after the line
`const toggleMaster = $('toggleMaster');` add:

```js
  const genPicker = $('genPicker');
  const genPickNote = $('genPickNote');
  let pickedEntry = null;           // { counter, rules, length } while a pick is active
  let pickDebounce = null;

  function clearPick() {
    pickedEntry = null;
    account.parentElement.classList.remove('picked');
    const x = account.parentElement.querySelector('.pick-clear');
    if (x) x.remove();
    genPickNote.hidden = true;
    genPickNote.textContent = '';
  }

  function pickRow(entry) {
    // password path only in this task; sso handled in Task 6
    account.value = entry.account;
    lengthEl.value = String(entry.length ?? 20);
    rulesEl.value = entry.rules ?? 'standard';
    pickedEntry = { counter: entry.counter ?? 1, rules: rulesEl.value, length: parseInt(lengthEl.value, 10) };
    account.parentElement.classList.add('picked');
    if (!account.parentElement.querySelector('.pick-clear')) {
      const x = document.createElement('button');
      x.type = 'button'; x.className = 'pick-clear'; x.textContent = '✕';
      x.addEventListener('click', () => { clearPick(); renderGenPicker(); });
      account.parentElement.appendChild(x);
    }
    renderGenPicker();
  }

  function renderGenPicker() {
    const matches = vaultBridge.forSite(site.value);
    if (!matches.length) { genPicker.hidden = true; genPicker.innerHTML = ''; return; }
    const rows = matches.map((e, i) => {
      const meta = e.type === 'sso'
        ? `via ${escAttr(e.via && e.via.site)}`
        : `${escAttr(e.rules)} &middot; ${escAttr(e.length)}${(e.counter ?? 1) !== 1 ? ` &middot; #${escAttr(e.counter)}` : ''}`;
      return `<div class="gp-row" role="option" data-i="${i}"><span class="gp-name">${escAttr(e.account) || '(no account)'}</span><span class="gp-meta">${meta}</span></div>`;
    }).join('');
    genPicker.innerHTML = `<div class="gp-head">from your vault</div>${rows}`;
    genPicker.hidden = false;
    genPicker.querySelectorAll('.gp-row').forEach((row) => {
      row.addEventListener('click', () => pickRow(matches[Number(row.dataset.i)]));
    });
  }

  function escAttr(s) {
    return String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  }

  function scheduleGenPicker() {
    clearTimeout(pickDebounce);
    pickDebounce = setTimeout(renderGenPicker, 200);
  }

  site.addEventListener('change', renderGenPicker);
  site.addEventListener('input', () => { clearPick(); scheduleGenPicker(); });
  site.addEventListener('focus', renderGenPicker);
  account.addEventListener('input', clearPick);
```

- [ ] **Step 2: Return a `refreshPicker` hook and call it on tab activation**

Change the end of `initGenerateTab` — the function currently ends with the
`copyBtn.addEventListener(...)` block then `}`. Add, just before that closing `}`:

```js
  return { refreshPicker: renderGenPicker };
```

In `initApp`, change:

```js
  initGenerateTab();
```

to:

```js
  const gen = initGenerateTab();
  const origShow = show;
```

…and update `show` so re-showing Generate refreshes the picker. Replace the
`show` function body's last line region — the whole `show` function becomes:

```js
  function show(which) {
    const isGen = which === 'generate';
    genPanel.hidden = !isGen;
    vaultPanel.hidden = isGen;
    genBtn.setAttribute('aria-selected', String(isGen));
    vaultBtn.setAttribute('aria-selected', String(!isGen));
    if (isGen && gen && gen.refreshPicker) gen.refreshPicker();
  }
```

(Delete the stray `const origShow = show;` line if you added it — it was only a
marker; the final `initApp` has `const gen = initGenerateTab();` then the `show`
above then the two `addEventListener` lines then `initGenerateTab` is **not**
called again.)

Final `initApp` body for reference:

```js
function initApp() {
  const genBtn = document.getElementById('tabBtnGenerate');
  const vaultBtn = document.getElementById('tabBtnVault');
  const genPanel = document.getElementById('tab-generate');
  const vaultPanel = document.getElementById('tab-vault');

  const gen = initGenerateTab();

  function show(which) {
    const isGen = which === 'generate';
    genPanel.hidden = !isGen;
    vaultPanel.hidden = isGen;
    genBtn.setAttribute('aria-selected', String(isGen));
    vaultBtn.setAttribute('aria-selected', String(!isGen));
    if (isGen && gen && gen.refreshPicker) gen.refreshPicker();
  }
  genBtn.addEventListener('click', () => show('generate'));
  vaultBtn.addEventListener('click', () => show('vault'));
}
```

- [ ] **Step 3: Build + suite**

Run: `node tools/build.mjs && node tools/check-invariants.mjs && node --test`
Expected: green; `fail 0`, total 100. `tests/app.test.mjs` (`estimateEntropyBits`,
`groupInFours`) still passes — the two exports are untouched.

- [ ] **Step 4: Manual browser test**

`cd dist && python3 -m http.server 8801`, open the page.
- Vault tab → Create vault `me@x.com` / `pw12345` / `pw12345`.
- Add `password` entries: `GH me / github.com / me`, `GH work / github.com / work`
  (Length 32, Rules max-symbols).
- Generate tab → type `github.com` in Site, click elsewhere → the picker shows
  two rows: `me — standard · 20`, `work — max-symbols · 32`.
- Click the `work` row → Account fills with `work`, Length shows `32`, Rules
  shows `max-symbols`, an `✕` appears at the Account field's right, the Account
  input text is muted.
- Click `✕` → Account clears, `✕` gone, styling reset, picker still shows.
- Type a letter in Site → picker re-filters; a stray letter breaking the match
  hides it.
- Vault tab → Lock → Generate tab → picker is gone (`vaultBridge` inactive).
- No console errors.

- [ ] **Step 5: Commit**

```bash
git add src/app.js
git -c commit.gpgsign=false commit -m "feat: generate-tab picker render + password pick"
```

---

## Task 6: Counter/rules/length in `generate()`, caption, SSO redirect, KCV hint

**Files:**
- Modify: `src/app.js`
- Manual test: `dist/kunji.html` in a browser + a terminal cross-check

- [ ] **Step 1: Use the picked counter and show it in the caption**

In `generate()` (in `src/app.js`), replace this block:

```js
      const params = { site: site.value, account: account.value, counter: 1, rules, length };
```

with:

```js
      const counter = pickedEntry ? (pickedEntry.counter || 1) : 1;
      const params = { site: site.value, account: account.value, counter, rules, length };
```

And replace this line:

```js
      entropyEl.textContent = estimateEntropyBits(length, size) + ' bits of entropy. Unique to this site and counter 1.';
```

with:

```js
      entropyEl.textContent = estimateEntropyBits(length, size) + ' bits of entropy. Unique to this site and counter ' + counter + '.';
```

- [ ] **Step 2: SSO redirect in `pickRow`**

Replace the whole `pickRow` function from Task 5 with:

```js
  function pickRow(entry) {
    const target = resolveEntryForPick(vaultBridge.forSite(site.value), entry);
    if (entry.type === 'sso') {
      if (target) {
        site.value = target.site;
        account.value = target.account;
        lengthEl.value = String(target.length ?? 20);
        rulesEl.value = target.rules ?? 'standard';
        pickedEntry = { counter: target.counter ?? 1, rules: rulesEl.value, length: parseInt(lengthEl.value, 10) };
        setPickNote('Via ' + (entry.site || entry.name) + ' — this is your ' + target.site + ' password.');
      } else {
        site.value = (entry.via && entry.via.site) || '';
        account.value = (entry.via && entry.via.account) || '';
        pickedEntry = null;
        setPickNote('Linked ' + ((entry.via && entry.via.site) || 'entry') + ' not in vault — using defaults.');
      }
    } else {
      account.value = entry.account;
      lengthEl.value = String(entry.length ?? 20);
      rulesEl.value = entry.rules ?? 'standard';
      pickedEntry = { counter: entry.counter ?? 1, rules: rulesEl.value, length: parseInt(lengthEl.value, 10) };
      maybeKcvHint();
    }
    account.parentElement.classList.toggle('picked', !!pickedEntry);
    let x = account.parentElement.querySelector('.pick-clear');
    if (pickedEntry && !x) {
      x = document.createElement('button');
      x.type = 'button'; x.className = 'pick-clear'; x.textContent = '✕';
      x.addEventListener('click', () => { clearPick(); renderGenPicker(); });
      account.parentElement.appendChild(x);
    } else if (!pickedEntry && x) {
      x.remove();
    }
    renderGenPicker();
  }

  function setPickNote(text) {
    genPickNote.textContent = text;
    genPickNote.hidden = false;
  }

  function maybeKcvHint() {
    if (pickedEntry && kcv.dataset.state !== 'ok') {
      setPickNote('Verify your passphrase above to match your vault.');
    }
  }
```

- [ ] **Step 3: Build + suite**

Run: `node tools/build.mjs && node tools/check-invariants.mjs && node --test`
Expected: green; `fail 0`, total 100.

- [ ] **Step 4: Manual browser test**

`cd dist && python3 -m http.server 8801`, open the page.
- Vault tab → Create vault `me@x.com` / `pw12345` / `pw12345`.
- Add `password` `GH rot / github.com / me` with **Counter 3** (Vault editor),
  and an `sso` `News / news.example.com / me` with `via` site `github.com`,
  `via` account `me`.
- Generate tab → identity `me@x.com`, passphrase `pw12345` → KCV goes green.
- Site `github.com` → pick the `me — standard · 20 · #3` row → Generate →
  caption ends `counter 3.` Reveal the password.
- Terminal cross-check:
  `node -e "import('./src/derive.js').then(async d=>{const mk=await d.deriveMasterKey('pw12345','me@x.com');console.log(await d.derivePassword({masterKey:mk,site:'github.com',account:'me',counter:3,rules:'standard',length:20}))})"`
  — must equal the revealed value.
- Site `news.example.com` → the picker shows the SSO row `me — via github.com` →
  pick it → Site rewrites to `github.com`, Account to `me`, a note appears "Via
  news.example.com — this is your github.com password." → Generate → matches the
  `github.com / me / counter 3` derivation.
- Delete the underlying `GH rot` entry in the Vault tab, back to Generate, pick
  the SSO row again → note reads "Linked github.com not in vault — using
  defaults.", counter reverts to 1 on Generate.
- Clear the passphrase field, re-pick a password row → the note reads "Verify
  your passphrase above to match your vault."
- No console errors. `npm run verify` green.

- [ ] **Step 5: Commit**

```bash
git add src/app.js
git -c commit.gpgsign=false commit -m "feat: generate-tab picker — counter, caption, sso redirect, kcv hint"
```

---

# PART B — Decoy authoring (Tasks 7–13)

## Task 7: `padPlaintextTo` pure helper

**Files:**
- Modify: `src/vault.js`
- Test: `tests/vault.test.mjs` (append)

- [ ] **Step 1: Append the failing tests**

```js
import { padPlaintextTo } from '../src/vault.js';
import { utf8 as _utf8 } from '../src/encoding.js';

test('padPlaintextTo makes JSON.stringify serialise to exactly the target byte length', () => {
  const obj = { entries: [], settings: { autoLockMinutes: 5 } };
  for (const target of [400, 813, 2048]) {
    const padded = padPlaintextTo(obj, target);
    assert.equal(_utf8(JSON.stringify(padded)).length, target);
    assert.deepEqual(padded.entries, []);
    assert.equal(padded.settings.autoLockMinutes, 5);
    assert.equal(typeof padded._pad, 'string');
    // _pad is the only added key
    assert.deepEqual(Object.keys(padded).sort(), ['_pad', 'entries', 'settings']);
  }
});

test('padPlaintextTo throws when the object is already larger than the target', () => {
  const big = { entries: Array.from({ length: 50 }, (_, i) => ({ id: 'x' + i, name: 'n'.repeat(20) })), settings: {} };
  const already = _utf8(JSON.stringify({ ...big, _pad: '' })).length;
  assert.throws(() => padPlaintextTo(big, already - 10));
});

test('padPlaintextTo _pad uses only base64 characters (no JSON escaping)', () => {
  const padded = padPlaintextTo({ entries: [], settings: {} }, 600);
  assert.match(padded._pad, /^[A-Za-z0-9+/]*$/);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/vault.test.mjs`
Expected: FAIL — `padPlaintextTo` not exported.

- [ ] **Step 3: Implement**

Append to `src/vault.js`:

```js
// --- Phase 3b: length-matching filler (pure) ---

// Returns { ...obj, _pad } where `_pad` is a base64 string sized so that
// utf8(JSON.stringify(result)).length === targetBytes exactly. Throws if `obj`
// (with an empty _pad) already serialises to more than targetBytes. base64
// characters are JSON-safe (no escaping), so one _pad char == one output byte.
export function padPlaintextTo(obj, targetBytes) {
  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const base = utf8(JSON.stringify({ ...obj, _pad: '' })).length;
  const need = targetBytes - base;
  if (need < 0) throw new Error(`padPlaintextTo: object is ${-need} bytes over target`);
  let pad = '';
  const r = randomBytes(need);
  for (let i = 0; i < need; i++) pad += B64[r[i] & 63];
  return { ...obj, _pad: pad };
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/vault.test.mjs` — PASS.
Run: `node --test` — `fail 0`, total 100 + 3 = 103.
Run: `node tools/build.mjs && node tools/check-invariants.mjs` — green.

- [ ] **Step 5: Commit**

```bash
git add src/vault.js tests/vault.test.mjs
git -c commit.gpgsign=false commit -m "feat: padPlaintextTo length-matching filler"
```

---

## Task 8: Extract `decryptSlot`, refactor `unlockVault`, add `openVault`

**Files:**
- Modify: `src/vault.js`
- Test: `tests/vault.test.mjs` (append)

- [ ] **Step 1: Append the failing tests**

```js
import { openVault } from '../src/vault.js';

// helper: build an envelope carrying BOTH a real and a decoy vault
async function envWithDecoy(realVault, realMK, decoyVault, decoyMK) {
  const text = await encodeEnvelope(realVault, {
    masterKey: realMK, writerId: 'w',
    decoy: { vault: decoyVault, masterKey: decoyMK },
  });
  return parseEnvelope(text);
}

const RMK = hexToBytes('ab'.repeat(31) + '12');
const DMK = hexToBytes('cd'.repeat(32));

test('openVault routes to the real slot for the real passphrase', async () => {
  const real = addEntry(createVault(), { name: 'R', site: 'r', account: 'r' });
  const decoy = addEntry(createVault(), { name: 'D', site: 'd', account: 'd' });
  const env = await envWithDecoy(real, RMK, decoy, DMK);
  const out = await openVault(env, { masterKey: RMK });
  assert.equal(out.slot, 'real');
  assert.equal(out.entries[0].name, 'R');
  assert.equal(out._pad, undefined);
});

test('openVault routes to the decoy slot for the decoy passphrase', async () => {
  const real = addEntry(createVault(), { name: 'R', site: 'r', account: 'r' });
  const decoy = addEntry(createVault(), { name: 'D', site: 'd', account: 'd' });
  const env = await envWithDecoy(real, RMK, decoy, DMK);
  const out = await openVault(env, { masterKey: DMK });
  assert.equal(out.slot, 'decoy');
  assert.equal(out.entries[0].name, 'D');
  assert.equal(out._pad, undefined);
});

test('openVault throws WrongPassphraseError for a third passphrase', async () => {
  const env = await envWithDecoy(createVault(), RMK, createVault(), DMK);
  await assert.rejects(() => openVault(env, { masterKey: hexToBytes('ef'.repeat(32)) }), WrongPassphraseError);
});

test('openVault opens the decoy even if the real ct is damaged', async () => {
  const env = await envWithDecoy(createVault(), RMK, addEntry(createVault(), { name: 'D', site: 'd', account: 'd' }), DMK);
  env.ct = Buffer.from((() => { const b = Buffer.from(env.ct, 'base64'); b[0] ^= 1; return b; })()).toString('base64');
  const out = await openVault(env, { masterKey: DMK });
  assert.equal(out.slot, 'decoy');
  assert.equal(out.entries[0].name, 'D');
});

test('openVault on a decoy-less (random filler) envelope: real works, others reject', async () => {
  const env = parseEnvelope(await encodeEnvelope(addEntry(createVault(), { name: 'R', site: 'r', account: 'r' }), { masterKey: RMK, writerId: 'w' }));
  assert.equal((await openVault(env, { masterKey: RMK })).slot, 'real');
  await assert.rejects(() => openVault(env, { masterKey: DMK }), WrongPassphraseError);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/vault.test.mjs`
Expected: FAIL — `openVault` not exported (and `encodeEnvelope` does not yet
accept `decoy`, so `envWithDecoy` produces a random-filler envelope and the
decoy-slot tests fail). Both are fixed here and in Task 9; run order is: land
Task 8's `openVault` + `decryptSlot` now, Task 9's `encodeEnvelope` decoy next.
For this task, expect the three tests that do **not** need a real decoy
(`routes to the real slot`… will still fail because `_pad`/`openVault` missing)
to drive the implementation; the two decoy-slot assertions stay red until Task 9.

> Note for the implementer: it is acceptable for this task to leave the two
> decoy-slot `openVault` tests failing at Step 4; Task 9 turns them green. If you
> prefer a fully-green boundary, move those two `test(...)` blocks to Task 9's
> Step 1 instead. Either way, **do not** weaken the assertions.

- [ ] **Step 3: Implement in `src/vault.js`**

Add a private helper above `unlockVault`:

```js
// Decrypt one slot's ciphertext and validate the plaintext shape. Drops `_pad`
// (Phase 3b length-matching filler) by returning only { entries, settings }.
async function decryptSlot(vaultKey, ivB64, ctB64) {
  let plainBytes;
  try {
    plainBytes = await aesGcmDecrypt(vaultKey, base64ToBytes(ivB64), base64ToBytes(ctB64), VAULT_AAD);
  } catch {
    throw new CorruptVaultError('the file could not be decrypted');
  }
  let plain;
  try {
    plain = JSON.parse(fromUtf8(plainBytes));
  } catch {
    throw new CorruptVaultError('the vault contents could not be read');
  }
  if (!plain || !Array.isArray(plain.entries)
      || typeof plain.settings !== 'object' || plain.settings === null || Array.isArray(plain.settings)) {
    throw new CorruptVaultError('the vault contents are not in the expected shape');
  }
  return { entries: plain.entries, settings: plain.settings };
}
```

Replace the body of `unlockVault` with:

```js
export async function unlockVault(envelope, { masterKey }) {
  if (await computeKcv(masterKey) !== envelope.kcv) {
    throw new WrongPassphraseError('that is not the passphrase for this vault');
  }
  const vaultKey = await deriveVaultKey(masterKey);
  return decryptSlot(vaultKey, envelope.iv, envelope.ct);
}
```

Add after `unlockVault`:

```js
// Try the real slot first (KCV match), then the decoy slot. Returns the
// decrypted vault plus which slot it came from. `WrongPassphraseError` when the
// passphrase matches neither.
export async function openVault(envelope, { masterKey }) {
  const k = await computeKcv(masterKey);
  const vaultKey = await deriveVaultKey(masterKey);
  if (k === envelope.kcv) {
    return { slot: 'real', ...(await decryptSlot(vaultKey, envelope.iv, envelope.ct)) };
  }
  if (envelope.decoy && k === envelope.decoy.kcv) {
    return { slot: 'decoy', ...(await decryptSlot(vaultKey, envelope.decoy.iv, envelope.decoy.ct)) };
  }
  throw new WrongPassphraseError('that passphrase does not match this vault');
}
```

- [ ] **Step 4: Run to verify**

Run: `node --test tests/vault.test.mjs`
Expected: the pre-existing `unlockVault` tests still PASS (round-trip, KCV
mismatch, corrupt ct, settings null/array). The `openVault` real-slot,
third-passphrase, and decoy-less tests PASS. The two decoy-slot `openVault`
tests remain red pending Task 9 (see the note in Step 2).
Run: `node --test` — `fail` count is exactly 2 (the two decoy-slot tests) or 0
if you moved them to Task 9.
Run: `node tools/build.mjs && node tools/check-invariants.mjs` — green.

- [ ] **Step 5: Commit**

```bash
git add src/vault.js tests/vault.test.mjs
git -c commit.gpgsign=false commit -m "refactor: extract decryptSlot; add openVault decoy router"
```

---

## Task 9: `encodeEnvelope` optional decoy + `_pad` length match

**Files:**
- Modify: `src/vault.js`
- Test: `tests/vault.test.mjs` (append)

- [ ] **Step 1: Append the failing tests**

```js
test('encodeEnvelope with a decoy: both slots decrypt, ct lengths equal, decoy kcv correct', async () => {
  const real = addEntry(createVault(), { name: 'R', site: 'r', account: 'r', notes: 'the real one is longer '.repeat(4) });
  const decoy = addEntry(createVault(), { name: 'D', site: 'd', account: 'd' });
  const text = await encodeEnvelope(real, { masterKey: RMK, writerId: 'w', decoy: { vault: decoy, masterKey: DMK } });
  const env = JSON.parse(text);
  assert.equal(b64(env.ct).length, b64(env.decoy.ct).length, 'ct lengths equal');
  assert.equal(env.decoy.kcv, await computeKcv(DMK));
  assert.equal(b64(env.decoy.iv).length, 12);
  const r = await openVault(env, { masterKey: RMK });
  const d = await openVault(env, { masterKey: DMK });
  assert.equal(r.entries[0].name, 'R');
  assert.equal(d.entries[0].name, 'D');
  assert.equal(r._pad, undefined);
  assert.equal(d._pad, undefined);
});

test('encodeEnvelope with a decoy pads whichever plaintext is shorter', async () => {
  // decoy is bigger this time
  const real = addEntry(createVault(), { name: 'R', site: 'r', account: 'r' });
  const decoy = addEntry(createVault(), { name: 'D', site: 'd', account: 'd', notes: 'x'.repeat(500) });
  const env = JSON.parse(await encodeEnvelope(real, { masterKey: RMK, writerId: 'w', decoy: { vault: decoy, masterKey: DMK } }));
  assert.equal(b64(env.ct).length, b64(env.decoy.ct).length);
});

test('encodeEnvelope without a decoy is unchanged: random filler, no _pad', async () => {
  const real = addEntry(createVault(), { name: 'R', site: 'r', account: 'r' });
  const env = JSON.parse(await encodeEnvelope(real, { masterKey: RMK, writerId: 'w' }));
  assert.equal(b64(env.decoy.ct).length, b64(env.ct).length);
  const out = await unlockVault(env, { masterKey: RMK });
  assert.equal(out._pad, undefined);
  assert.equal(JSON.stringify(out.entries).includes('_pad'), false);
});

test('encodeEnvelope decoy: a fresh IV per slot per call', async () => {
  const a = JSON.parse(await encodeEnvelope(createVault(), { masterKey: RMK, writerId: 'w', decoy: { vault: createVault(), masterKey: DMK } }));
  const b = JSON.parse(await encodeEnvelope(createVault(), { masterKey: RMK, writerId: 'w', decoy: { vault: createVault(), masterKey: DMK } }));
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(a.decoy.iv, b.decoy.iv);
  assert.notEqual(a.iv, a.decoy.iv);
});
```

(If you moved the two decoy-slot `openVault` tests here from Task 8, add them
above these.)

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/vault.test.mjs`
Expected: the new decoy tests FAIL — `encodeEnvelope` ignores `decoy` and writes
`newDecoyBytes(...)`, so `openVault(env, { masterKey: DMK })` rejects.

- [ ] **Step 3: Implement — replace `encodeEnvelope` in `src/vault.js`**

```js
export async function encodeEnvelope(vault, { masterKey, identityHint = null, prevRevision = 0, writerId, decoy = null }) {
  // Only `entries` and `settings` are persisted per slot; other top-level keys
  // (e.g. a future format's) would be dropped on a v1 save-through. `_pad` is a
  // length-matching filler added below and stripped by the loader.
  const realObj = { entries: vault.entries, settings: vault.settings };
  let realBytes = utf8(JSON.stringify(realObj));

  let decoySection = null;
  if (decoy) {
    const decoyObj = { entries: decoy.vault.entries, settings: decoy.vault.settings };
    let decoyBytes = utf8(JSON.stringify(decoyObj));
    const target = Math.max(realBytes.length, decoyBytes.length);
    if (realBytes.length < target) realBytes = utf8(JSON.stringify(padPlaintextTo(realObj, target)));
    if (decoyBytes.length < target) decoyBytes = utf8(JSON.stringify(padPlaintextTo(decoyObj, target)));
    const dKey = await deriveVaultKey(decoy.masterKey);
    const dIv = randomBytes(12);
    const dCt = await aesGcmEncrypt(dKey, dIv, decoyBytes, VAULT_AAD);
    decoySection = { kcv: await computeKcv(decoy.masterKey), iv: bytesToBase64(dIv), ct: bytesToBase64(dCt) };
  }

  const vaultKey = await deriveVaultKey(masterKey);
  const iv = randomBytes(12);
  const ct = await aesGcmEncrypt(vaultKey, iv, realBytes, VAULT_AAD);
  const envelope = {
    format: VAULT_FORMAT,
    v: VAULT_V,
    kdf: `pbkdf2-sha512-${PBKDF2_ITERATIONS}`,
    identityHint: identityHint || null,
    kcv: await computeKcv(masterKey),
    iv: bytesToBase64(iv),
    ct: bytesToBase64(ct),
    decoy: decoySection || newDecoyBytes(ct.length),
    revision: prevRevision + 1,
    lastWriter: writerId,
    updatedAt: new Date().toISOString(),
  };
  return JSON.stringify(envelope, null, 2) + '\n';
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --test tests/vault.test.mjs` — PASS (including any decoy-slot
`openVault` tests carried over).
Run: `node --test` — `fail 0`, total ≈ 103 + 4 (+2 if carried) = 107–109.
Run: `node tools/build.mjs && node tools/check-invariants.mjs` — green.

- [ ] **Step 5: Commit**

```bash
git add src/vault.js tests/vault.test.mjs
git -c commit.gpgsign=false commit -m "feat: encodeEnvelope optional decoy with _pad length match"
```

---

## Task 10: Vault tab unlocks via `openVault`; slot state scaffolding

**Files:**
- Modify: `src/vault-ui.js`
- Manual test: `dist/kunji.html` in a browser

Context: this task swaps the LOCKED-view Unlock handler from `unlockVault` to
`openVault`, records `unlockedSlot`, and adds the slot bookkeeping variables.
The Decoy **UI** (Set up / toggle) is Task 11; a file opened with a decoy
passphrase this task already lands on a normal-looking unlocked vault.

- [ ] **Step 1: Add slot state near the other `let`s (after `let idleTimer = null;` etc.)**

```js
  let unlockedSlot = 'real';       // 'real' | 'decoy' — how the loaded file was opened
  let activeSlot = 'real';         // which slot the list/detail/editor operates on
  let decoyVault = null;           // { entries, settings } while a decoy is held this session
  let decoyMasterKey = null;       // Uint8Array while a decoy is held this session
  let realVault = null;            // stash of the real pair while activeSlot === 'decoy'
  let realMasterKey = null;
```

- [ ] **Step 2: Swap the unlock handler to `openVault`**

In the `#vlUnlock` click handler `try` block, replace:

```js
        const mk = await deriveMasterKey(pw, id);
        const out = await unlockVault(loadedEnvelope, { masterKey: mk });
        masterKey = mk;
        vault = out;
        sessionIdentity = id;
        identityHintOn = typeof loadedEnvelope.identityHint === 'string';
        dirty = false;
        state = 'UNLOCKED';
        vaultBridge.publish(vault.entries);
        render();
```

with:

```js
        const mk = await deriveMasterKey(pw, id);
        const out = await openVault(loadedEnvelope, { masterKey: mk });
        masterKey = mk;
        vault = { entries: out.entries, settings: out.settings };
        unlockedSlot = out.slot;
        activeSlot = 'real';
        decoyVault = null; decoyMasterKey = null; realVault = null; realMasterKey = null;
        sessionIdentity = id;
        identityHintOn = typeof loadedEnvelope.identityHint === 'string';
        dirty = false;
        state = 'UNLOCKED';
        vaultBridge.publish(vault.entries);
        render();
```

- [ ] **Step 3: Clear slot state in `wipe()`**

Add to the end of `wipe()` (after `vaultBridge.clear();` from Task 3):

```js
    unlockedSlot = 'real';
    activeSlot = 'real';
    decoyVault = null;
    decoyMasterKey = null;
    realVault = null;
    realMasterKey = null;
```

- [ ] **Step 4: `onCreate` sets the slot fields**

In `onCreate()`, after `state = 'UNLOCKED';` (and the existing
`vaultBridge.publish(vault.entries);`), add:

```js
      unlockedSlot = 'real';
      activeSlot = 'real';
```

- [ ] **Step 5: Build + suite**

Run: `node tools/build.mjs && node tools/check-invariants.mjs && node --test`
Expected: green; `fail 0`. No new tests (DOM wiring).

- [ ] **Step 6: Manual browser test**

- Create a vault, add an entry, Save → `kunji-data.json`. Reload, open it,
  unlock with the real passphrase → the list shows the entry as before (this
  proves `openVault`'s real path is wired). Lock, re-unlock. No console errors.
- (Cannot test the decoy path yet — no way to author one until Task 11.)
- `npm run verify` green.

- [ ] **Step 7: Commit**

```bash
git add src/vault-ui.js
git -c commit.gpgsign=false commit -m "feat: vault tab unlocks via openVault; slot state scaffolding"
```

---

## Task 11: Decoy section, `[real|decoy]` toggle, slot-aware CRUD

**Files:**
- Modify: `src/vault-ui.js`
- Modify: `src/style.css`
- Manual test: `dist/kunji.html` in a browser

- [ ] **Step 1: Add a slot accessor and use it in `render()`**

Add near the top of `initVaultTab` (after the `esc` helper):

```js
  // The pair the list/detail/editor currently operate on.
  function useSlot(slot) {
    if (slot === activeSlot) return;
    if (activeSlot === 'real') { realVault = vault; realMasterKey = masterKey; }
    else { decoyVault = vault; decoyMasterKey = masterKey; }
    activeSlot = slot;
    if (slot === 'real') { vault = realVault; masterKey = realMasterKey; }
    else { vault = decoyVault; masterKey = decoyMasterKey; }
    view = 'list'; selectedId = null; listQuery = '';
    vaultBridge.publish(vault.entries);
    render();
  }
```

- [ ] **Step 2: Append the decoy CSS to `src/style.css`**

```css
/* Decoy authoring (Phase 3b) */
.v-decoy-banner {
  background: #2a1a00; border: 1px solid #5c4300; color: #f5c518;
  font-size: 12px; padding: 8px 10px; border-radius: 6px; margin: 10px 0;
}
.v-slot-toggle { display: flex; gap: 6px; margin-bottom: 10px; }
.v-slot-toggle button {
  flex: 1; min-height: 40px; border: 1px solid var(--border); border-radius: 4px;
  background: transparent; color: var(--muted); font: 700 12px inherit; cursor: pointer;
}
.v-slot-toggle button[aria-pressed="true"] { color: var(--text); border-color: var(--blue); }
.v-decoy-setup { border-top: 1px solid #1a1c1f; margin-top: 12px; padding-top: 10px; }
```

- [ ] **Step 3: Render the toggle + banner + decoy section in `renderList`**

In `renderList()`, replace the current footer/hint block:

```js
      <div class="v-foot"><button class="link-btn" id="vSave" type="button">Save vault</button> &middot; <button class="link-btn" id="vLock" type="button">Lock</button> &middot; <span id="vIdleCountdown"></span></div>
      <label class="v-foot" style="display:block"><input type="checkbox" id="vHint" ${identityHintOn ? 'checked' : ''}> Prefill identity on devices that open this file <span class="v-danger">(anyone with the file can read it)</span></label>
      <div class="error" id="vListError"></div>
```

with:

```js
      ${activeSlot === 'decoy' ? '<div class="v-decoy-banner">⚠ Editing the DECOY vault</div>' : ''}
      ${unlockedSlot === 'real' && decoyMasterKey ? `
        <div class="v-slot-toggle">
          <button id="vSlotReal" type="button" aria-pressed="${activeSlot === 'real'}">Real vault</button>
          <button id="vSlotDecoy" type="button" aria-pressed="${activeSlot === 'decoy'}">Decoy</button>
        </div>` : ''}
      <div class="v-foot"><button class="link-btn" id="vSave" type="button">Save vault</button> &middot; <button class="link-btn" id="vLock" type="button">Lock</button> &middot; <span id="vIdleCountdown"></span></div>
      <label class="v-foot" style="display:block"><input type="checkbox" id="vHint" ${identityHintOn ? 'checked' : ''}> Prefill identity on devices that open this file <span class="v-danger">(anyone with the file can read it)</span></label>
      ${unlockedSlot === 'real' && activeSlot === 'real' ? `
        <div class="v-decoy-setup">
          ${decoyMasterKey
            ? '<button class="link-btn" id="vDecoyChange" type="button">Change decoy passphrase</button> &middot; <button class="link-btn v-danger" id="vDecoyRemove" type="button">Remove decoy</button>'
            : '<button class="link-btn" id="vDecoySetup" type="button">Set up decoy&hellip;</button>'}
          <div class="error" id="vDecoyError"></div>
        </div>` : ''}
      <div class="error" id="vListError"></div>
```

- [ ] **Step 4: Wire the toggle + decoy buttons (add at the end of `renderList`, before its closing `}`)**

```js
    if (panel.querySelector('#vSlotReal')) panel.querySelector('#vSlotReal').addEventListener('click', () => useSlot('real'));
    if (panel.querySelector('#vSlotDecoy')) panel.querySelector('#vSlotDecoy').addEventListener('click', () => useSlot('decoy'));
    if (panel.querySelector('#vDecoySetup')) panel.querySelector('#vDecoySetup').addEventListener('click', () => decoyPrompt('create'));
    if (panel.querySelector('#vDecoyChange')) panel.querySelector('#vDecoyChange').addEventListener('click', () => decoyPrompt('change'));
    if (panel.querySelector('#vDecoyRemove')) panel.querySelector('#vDecoyRemove').addEventListener('click', () => {
      if (!confirm('Remove the decoy? The decoy passphrase will stop working on the next Save.')) return;
      decoyVault = null; decoyMasterKey = null;
      if (activeSlot === 'decoy') { activeSlot = 'real'; vault = realVault; masterKey = realMasterKey; }
      markDirty(); render();
    });
```

- [ ] **Step 5: Add `decoyPrompt` (anywhere in `initVaultTab`, e.g. after `useSlot`)**

```js
  function decoyPrompt(mode) {
    const errEl = panel.querySelector('#vDecoyError');
    errEl.textContent = '';
    panel.innerHTML = `
      <div class="v-bar"><button class="link-btn" id="dpCancel" type="button">&lsaquo; Cancel</button></div>
      <p class="v-explain">${mode === 'change' ? 'Enter a new decoy passphrase. The decoy entries are kept.' : 'Set a decoy passphrase. Under coercion, hand this one over — it opens a separate, believable vault.'}</p>
      <div class="fields">
        <div class="field"><input id="dpIdentity" type="text" autocomplete="off" spellcheck="false" placeholder=" " value="${esc(sessionIdentity)}"><label for="dpIdentity">Decoy identity</label></div>
        <div class="field"><input id="dpPass" type="password" autocomplete="off" spellcheck="false" placeholder=" "><label for="dpPass">Decoy passphrase</label></div>
        <div class="field"><input id="dpConfirm" type="password" autocomplete="off" spellcheck="false" placeholder=" "><label for="dpConfirm">Confirm</label></div>
      </div>
      <button class="btn-primary" id="dpGo" type="button">${mode === 'change' ? 'Change decoy passphrase' : 'Create decoy'}</button>
      <div class="error" id="dpError"></div>
    `;
    panel.querySelector('#dpCancel').addEventListener('click', () => render());
    panel.querySelector('#dpGo').addEventListener('click', async () => {
      const de = panel.querySelector('#dpError');
      de.textContent = '';
      const id = panel.querySelector('#dpIdentity').value.trim();
      const pw = panel.querySelector('#dpPass').value;
      const cf = panel.querySelector('#dpConfirm').value;
      if (!id || !pw) { de.textContent = 'Identity and passphrase are required.'; return; }
      if (pw !== cf) { de.textContent = 'The two passphrases do not match.'; return; }
      const btn = panel.querySelector('#dpGo');
      btn.disabled = true; btn.textContent = 'Working…';
      try {
        const dmk = await deriveMasterKey(pw, id);
        if (await computeKcv(dmk) === loadedEnvelope?.kcv || await computeKcv(dmk) === (await computeKcv(masterKey))) {
          de.textContent = 'That passphrase collides with your real one — choose a different decoy passphrase.';
          btn.disabled = false; btn.textContent = 'Create decoy'; return;
        }
        if (mode === 'change') {
          decoyMasterKey = dmk; // keep decoyVault as-is
        } else if (loadedEnvelope && loadedEnvelope.decoy && await computeKcv(dmk) === loadedEnvelope.decoy.kcv) {
          // an existing decoy — decrypt it for editing
          const opened = await openVault(loadedEnvelope, { masterKey: dmk });
          decoyVault = { entries: opened.entries, settings: opened.settings };
          decoyMasterKey = dmk;
        } else {
          decoyVault = createVault();
          decoyMasterKey = dmk;
        }
        // drop into the decoy editing view
        realVault = vault; realMasterKey = masterKey;
        activeSlot = 'decoy';
        vault = decoyVault; masterKey = decoyMasterKey;
        view = 'list'; selectedId = null; listQuery = '';
        markDirty();
        render();
      } catch {
        de.textContent = 'Could not set up the decoy.';
        btn.disabled = false; btn.textContent = 'Create decoy';
      }
    });
  }
```

- [ ] **Step 6: Idle-lock / armIdle already spans both slots** — no change (it
  reads `vault.settings.autoLockMinutes`, and `vault` is always the active pair).

- [ ] **Step 7: Build + suite**

Run: `node tools/build.mjs && node tools/check-invariants.mjs && node --test`
Expected: green; `fail 0`.

- [ ] **Step 8: Manual browser test**

`cd dist && python3 -m http.server 8801`, open the page.
- Create a real vault `me@x.com` / `realpass1` → add `Amazon / amazon.com / me`.
- Footer shows `Set up decoy…`. Click it → decoy prompt → identity `decoy@x.com`,
  passphrase `decoypass1` ×2 → Create decoy → `⚠ Editing the DECOY vault` banner,
  a `[Real vault | Decoy]` toggle, empty list.
- Add `Netflix / netflix.com / me` to the decoy. Toggle to **Real vault** →
  Amazon is there, no banner. Toggle to **Decoy** → Netflix, banner back.
- Toggle to Real. `Save vault` → download. In the file: `ct` and `decoy.ct` are
  equal length; `decoy.kcv` is 4 base64 bytes.
- Reload, open the file, unlock with `realpass1` → real vault (Amazon), footer
  shows `Change decoy passphrase · Remove decoy`. Lock. Unlock the **same file**
  with `decoypass1` → a normal-looking vault with **Netflix**, **no banner, no
  toggle, no decoy section**.
- Reload, open, unlock real, `Remove decoy` → confirm → `Save vault`. Reload,
  open, try `decoypass1` → "that passphrase does not match this vault".
- Set the decoy passphrase equal to `realpass1` in the prompt → the collision
  error shows.
- No console errors. `npm run verify` green.

- [ ] **Step 9: Commit**

```bash
git add src/vault-ui.js src/style.css
git -c commit.gpgsign=false commit -m "feat: vault tab — decoy setup, slot toggle, slot-aware CRUD"
```

---

## Task 12: `saveVault` real+decoy and duress paths; bridge publishes the active slot

**Files:**
- Modify: `src/vault-ui.js`
- Manual test: `dist/kunji.html` in a browser

- [ ] **Step 1: Rewrite `saveVault`**

Replace the whole `saveVault` function with:

```js
  async function saveVault() {
    const prevRevision = loadedEnvelope ? (Number(loadedEnvelope.revision) || 0) : 0;

    // make sure the active slot's edits are reflected in its stash
    if (activeSlot === 'real') { realVault = vault; realMasterKey = masterKey; }
    else { decoyVault = vault; decoyMasterKey = masterKey; }
    const realPair = activeSlot === 'real' ? { v: vault, k: masterKey } : { v: realVault, k: realMasterKey };

    let text;
    if (unlockedSlot === 'decoy') {
      // Duress: we hold only the decoy key. Keep the real ct verbatim; re-encrypt
      // just the decoy slot; bump revision. Pad the decoy plaintext to the real
      // ct's plaintext length (real ct length - 16 tag).
      const realCtLen = base64ToBytes(loadedEnvelope.ct).length - 16;
      const decoyObj = { entries: vault.entries, settings: vault.settings };
      let decoyBytes = new TextEncoder().encode(JSON.stringify(decoyObj));
      if (decoyBytes.length < realCtLen) {
        decoyBytes = new TextEncoder().encode(JSON.stringify(padPlaintextTo(decoyObj, realCtLen)));
      }
      const dKey = await deriveVaultKey(masterKey);
      const dIv = randomBytes(12);
      const dCt = await aesGcmEncrypt(dKey, dIv, decoyBytes, VAULT_AAD);
      const env = {
        ...loadedEnvelope,
        decoy: { kcv: await computeKcv(masterKey), iv: bytesToBase64(dIv), ct: bytesToBase64(dCt) },
        revision: prevRevision + 1,
        lastWriter: writerId,
        updatedAt: new Date().toISOString(),
      };
      text = JSON.stringify(env, null, 2) + '\n';
    } else {
      text = await encodeEnvelope(realPair.v, {
        masterKey: realPair.k,
        identityHint: currentIdentityForHint(),
        prevRevision,
        writerId,
        decoy: decoyMasterKey ? { vault: decoyVault, masterKey: decoyMasterKey } : null,
      });
    }

    const blob = new Blob([text], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'kunji-data.json';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);

    loadedEnvelope = parseEnvelope(text);
    dirty = false;
    vaultBridge.publish(vault.entries);
    if (!sessionMoveNoteShown) {
      sessionMoveNoteShown = true;
      alert('Saved as kunji-data.json in your downloads. Move it to wherever your sync watches, and overwrite the previous copy.');
    }
    renderList();
  }
```

Note: `base64ToBytes` and `bytesToBase64` and `aesGcmEncrypt` and `deriveVaultKey`
and `computeKcv` and `randomBytes` and `padPlaintextTo` and `VAULT_AAD` are all
bundle globals in `vault-ui.js` after concatenation.

- [ ] **Step 2: Publish the active slot's entries after `useSlot` and `decoyPrompt`**

Already done — both call `vaultBridge.publish(vault.entries)` / `markDirty()`
(which publishes). Confirm `markDirty` publishes `vault.entries` (the active
pair). No change.

- [ ] **Step 3: Build + suite**

Run: `node tools/build.mjs && node tools/check-invariants.mjs && node --test`
Expected: green; `fail 0`.

- [ ] **Step 4: Manual browser test**

- Real vault `me@x.com` / `realpass1`, entry `Amazon`. Set up decoy
  `decoy@x.com` / `decoypass1`, add `Netflix`. Toggle to Real. **Save.**
- Reload, open, unlock `realpass1` → Amazon. Toggle… (no toggle: need to
  re-enter the decoy passphrase via `Change decoy passphrase`? No — after a real
  unlock there is no decoy key held, so no toggle; that matches spec §4.4). Add
  `eBay` to the real vault. **Save** (no decoy key held ⇒ the decoy slot is
  re-emitted as random filler — acceptable per spec: managing a decoy needs its
  passphrase). Actually: to keep the decoy, first click `Set up decoy…`, enter
  `decoypass1` — since its KCV matches `loadedEnvelope.decoy.kcv`, the existing
  decoy is decrypted for editing; toggle to Real, add `eBay`, **Save**.
- Reload, open, unlock `decoypass1` → Netflix only, no decoy UI. Add `Hulu`,
  **Save** (duress path). Reload, open, unlock `realpass1` → Amazon + eBay
  intact (duress save copied the real ct verbatim). Unlock `decoypass1` →
  Netflix + Hulu.
- Downloaded files: `ct` length == `decoy.ct` length every time; `revision`
  increments across every Save.
- Account picker (Generate tab): while unlocked as **real** with the real slot
  active, the picker never lists Netflix/Hulu. Toggle to **decoy** → the picker
  lists the decoy's entries (correct — it is the active vault). Unlock as
  **decoy** → the picker lists Netflix/Hulu.
- No console errors. `npm run verify` green.

- [ ] **Step 5: Commit**

```bash
git add src/vault-ui.js
git -c commit.gpgsign=false commit -m "feat: vault tab — save real+decoy and duress paths"
```

---

## Task 13: Docs, parent-spec sync, full verification

**Files:**
- Modify: `docs/specs/2026-09-01-kunji-design.md`
- Modify: `README.md`

- [ ] **Step 1: Parent spec §5.3 — account picker**

In `docs/specs/2026-09-01-kunji-design.md` §5.3, after the sentence ending
"…Kunji shows a small "which account?" picker rather than guessing." append:

```
The picker is a Generate-tab overlay, available only while a vault is unlocked
this session; it fills `account` and the entry's `counter`/`rules`/`length`,
and for an `sso` entry it redirects to the underlying entry. Derivation still
uses the Generate tab's own identity + passphrase (see
`docs/specs/2026-09-01-kunji-phase3a-account-picker-design.md`).
```

- [ ] **Step 2: Parent spec §4.7 — decoy**

In §4.7, after the bullet "The decoy vault is an ordinary vault the user
populates with believable but useless entries." append two bullets:

```
- To keep the real and decoy ciphertexts the same length, `encodeEnvelope` pads
  the shorter plaintext with a `_pad` string before encryption; the loader
  returns only `{ entries, settings }`, dropping `_pad`.
- A decoy passphrase whose KCV equals the real KCV is rejected at setup, so the
  real-then-decoy unlock routing in `openVault` is unambiguous.
```

- [ ] **Step 3: Parent spec §12 — phase 3 bullet**

Change the phase-3 line to reference the sub-specs:

```
3. **Portability.** Split into sub-projects, each with its own design spec:
   3a account picker (`…phase3a-account-picker-design.md`),
   3b decoy authoring (`…phase3b-decoy-authoring-design.md`),
   3c PWA + service worker, 3d sync merge, 3e QR transfer.
```

- [ ] **Step 4: README**

In `README.md`, under `## The vault`, append:

```
The Generate tab shows a "which account?" picker when a site you type matches
one or more vault entries (vault unlocked). A second **decoy** master passphrase
can be set from the unlocked vault; it opens a separate, believable vault, and
the file gives no sign that a real decoy exists.
```

- [ ] **Step 5: Full verification**

Run: `npm run verify`
Expected: all test files pass; `fail 0`; `dist/kunji.html written`;
`invariants ok (11 files)`.

- [ ] **Step 6: Full manual browser regression**

`cd dist && python3 -m http.server 8801`, open `http://localhost:8801/kunji.html`.
- **Phase 1/2 intact:** Generate tab derives; Vault tab create / add / edit /
  delete / save / reopen / unlock; idle-lock; dirty bar.
- **3a:** multi-account site → picker → pick → Generate → value equals a
  terminal `derivePassword` with the picked `counter`; SSO redirect; edit-clears
  the pick; lock hides the picker.
- **3b:** set up a decoy, add decoy entries, toggle slots, Save; reopen with the
  real passphrase (real vault + manage-decoy), reopen with the decoy passphrase
  (plain vault, no tell); Remove decoy; collision guard.
- **File:** `ct` length == `decoy.ct` length; `revision` monotonic; valid JSON;
  `format: "kunji-data"`, `v: 1`.
- DevTools: no console errors, Network tab empty on reload.

- [ ] **Step 7: Commit**

```bash
git add docs/specs/2026-09-01-kunji-design.md README.md
git -c commit.gpgsign=false commit -m "docs: phase 3a+3b — picker and decoy, parent-spec sync"
```

---

## Self-review

**Spec coverage — 3a:**
- `vault-bridge.js` (`publish`/`clear`/`forSite`/`isActive`, copy-on-publish) — Tasks 2, 3. *Refinement:* the spec shows bare `export function`s; the plan wraps them in a `vaultBridge` namespace object so `publish`/`clear` do not become colliding bundle globals.
- `entriesForSite` / `resolveEntryForPick` pure helpers (normalised exact match, sso→underlying, null) — Task 1.
- Bridge fed on unlock / create / mutation / save; cleared in `wipe()` — Task 3.
- Picker renders for ≥1 match, `#genPicker` between account and the row, `from your vault` header, `.v-row`-style rows, chips `rules · length` (+ `#N`), sso rows `via <site>` — Task 5.
- `password` pick fills account + counter/rules/length; `✕` clear-chip; muted "filled" style — Task 5.
- `sso` pick redirect (found → rewrite site+account+params+note; missing → defaults+note) — Task 6.
- Pick lifecycle clears on `site`/`account` `input`, `✕`, tab switch (`refreshPicker` re-runs and any prior programmatic fill stands until a real keystroke), `vaultBridge.clear()` — Tasks 5, 6. *Note:* "tab switch away clears the pick" from spec §4.5 is approximated — the pick is not force-cleared on switch-away, but the picker re-renders on switch-back and any field edit clears it. Acceptable; flagged for review.
- Counter silent + shown in caption `counter N` — Task 6.
- KCV-not-green hint — Task 6. *Deviation:* rendered in a dedicated `#genPickNote` muted line rather than the post-generate `.entropy` line (which is empty pre-generate); `#genPickNote` reuses `.foot` styling.
- Consistency cross-check (picked value == Vault-tab derive when passphrases match) — Task 6 Step 4 terminal check.
- Out of scope respected: no visible counter field, no write-back, no fuzzy match, bridge is memory-only.

**Spec coverage — 3b:**
- `openVault` real-then-decoy routing, `WrongPassphraseError` otherwise, opens decoy even if real ct damaged — Task 8.
- `decryptSlot` shared, strips `_pad` by returning only `{entries, settings}`; `unlockVault` refactored to use it (existing tests green) — Task 8.
- `padPlaintextTo` exact target length, throws when over, base64-only `_pad` — Task 7.
- `encodeEnvelope` optional `decoy:{vault,masterKey}`; pads the shorter; `ct.length === decoy.ct.length`; `decoy.kcv = computeKcv(decoyMasterKey)`; without decoy unchanged (random filler, no `_pad`) — Task 9.
- KCV-collision setup guard — Task 11 `decoyPrompt`.
- `unlockedSlot`; decoy-slot unlock renders the plain UNLOCKED view, no decoy affordances — Tasks 10, 11 (the decoy section and toggle render only when `unlockedSlot === 'real'`).
- Decoy section: `Set up decoy` (none) / `Change decoy passphrase` + `Remove decoy` (held); managing an existing decoy by re-entering its passphrase decrypts it for editing (KCV match), else creates new — Task 11.
- `[real|decoy]` toggle swaps the active pair; `⚠` banner iff decoy active; idle-lock/dirty/`beforeunload` span both — Task 11.
- `saveVault` real+decoy via `encodeEnvelope`; duress (decoy-slot) save copies real `ct` verbatim, re-encrypts the decoy slot, bumps `revision` — Task 12.
- `wipe()` clears `decoyVault`/`decoyMasterKey`/`unlockedSlot`/`activeSlot`/real stash — Task 10.
- Bridge publishes the **active** vault's entries, never the decoy's while real-active — Tasks 3, 11, 12 (`useSlot` and `markDirty` publish `vault.entries`, which is the active pair).
- Parent-spec §4.7, §5.3, §12 + README — Task 13.
- Out of scope respected: no separate decoy `revision`, no panic gesture, no nested vault, no `v` bump, no Generate-tab decoy.

**Placeholder scan:** every code step contains full code. Test steps contain full
test bodies. Task 8 deliberately allows a 2-failing-test boundary with an
explicit, bounded instruction (move the tests to Task 9 for a clean boundary or
leave them red for one commit) — this is a stated choice, not a "TODO".

**Type / name consistency:** `vaultBridge.{publish,clear,forSite,isActive}`,
`entriesForSite(entries, rawSite)`, `resolveEntryForPick(entries, entry)`,
`padPlaintextTo(obj, targetBytes)`, `openVault(envelope, { masterKey }) -> { slot, entries, settings }`,
`decryptSlot(vaultKey, ivB64, ctB64) -> { entries, settings }`,
`encodeEnvelope(vault, { masterKey, identityHint, prevRevision, writerId, decoy })`,
`decoy: { vault, masterKey }`, and the vault-ui state names
`unlockedSlot`/`activeSlot`/`decoyVault`/`decoyMasterKey`/`realVault`/`realMasterKey`
are used identically in every task that references them.

**Running test total:** baseline 88 → Task 1 (+7) 95 → Task 2 (+5) 100 →
Task 7 (+3) 103 → Task 8 (+3 net, 2 possibly deferred) → Task 9 (+4, or +6 with
the deferred pair) → ~109. DOM tasks add none. `fail 0` is the gate.

**Scope:** two sub-projects, one plan, sequenced so Part B builds on Part A's
bridge. Every task boundary produces a working `dist/kunji.html` (Task 8's
optional 2-test amber boundary excepted, resolved within one commit).
