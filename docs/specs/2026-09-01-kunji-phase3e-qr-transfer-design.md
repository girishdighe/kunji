# Kunji Phase 3e — QR export / import (in-app camera scanner)

**Date:** 2026-09-01
**Status:** Draft for review
**Authors:** grd + friend
**Parent spec:** `docs/specs/2026-09-01-kunji-design.md` (§7.3 "Vault sync … manual QR/file transfer", §7.4 CSP)
**Depends on:** Phase 2 vault (`src/vault.js`, `src/vault-ui.js`). Merge routing on
import reuses Phase 3d (`classifyIncoming`) when that phase has shipped; until then
import always goes to the LOCKED view.

---

## 1. Purpose

Move an encrypted vault between two devices that share no file-sync and no
network — e.g. a laptop and a new iPhone. One device shows the vault as a QR
code (animated for anything past one frame); the other scans it with its camera,
in-app, and lands on the unlock screen.

The QR **codec is hand-rolled and dependency-free** (ISO/IEC 18004), consistent
with §1 / §7.4 "no third-party libraries, auditable by reading".

One of five independent Phase 3 sub-projects; its own spec.

## 2. What crosses the QR

The **exact `kunji-data.json` envelope text** (the same bytes `Save vault`
downloads), base64-encoded, split into frames. Nothing is decrypted for
transfer; the QR carries ciphertext. No per-entry or partial payloads.

## 3. New pure modules

All three live directly after `src/encoding.js` in `JS_ORDER` (they need only
`encoding.js`). None touch the DOM. None are network-capable. The invariant
scanner's forbidden list (`fetch(`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`,
external `src`/`link`, `@import`, `https?://`) is **unchanged** — `getUserMedia`
and `navigator.mediaDevices` are not on it and are used only in `vault-ui.js`.

### 3.1 `src/qr.js` — encoder

```js
// Smallest QR version that fits `bytes` at the given ECC level, byte mode only.
// Returns the module grid as row-major booleans (true = dark), no quiet zone.
export function qrMatrix(bytes, { ecc = 'M' } = {}) -> boolean[][]
export const QR_CAPACITY // table: capacity[version][ecc] in data bytes (byte mode)
```

Implements: mode+length header, data codeword assembly, Reed–Solomon ECC over
GF(256) (primitive `0x11d`), block interleaving for larger versions, function
patterns (finders, separators, timing, alignment, dark module), format-info and
version-info strings, all 8 data masks with the standard penalty score to pick
the mask. No Kanji/ECI/structured-append inside a single symbol.

### 3.2 `src/qr-decode.js` — decoder

```js
// image: { data: Uint8ClampedArray (RGBA or grayscale), width, height }
// Returns the decoded byte payload, or null if no readable code is found.
export function decodeQr(image) -> Uint8Array | null
```

Pipeline: luminance → adaptive (local-mean) threshold → connected-component scan
for the three finder patterns (1:1:3:1:1 ratio) → estimate module size, rotation,
and the fourth corner from alignment patterns → homography sample of every module
centre → read format info (try both copies, correct with its BCH) → derive
version (explicit version info for v ≥ 7, else from grid size) → unmask →
de-interleave blocks → Reed–Solomon correct (return `null` if any block exceeds
its correction budget) → concatenate data codewords → parse the byte-mode
segment → payload. Single symbol per image; picks the largest/clearest if
several are present.

### 3.3 `src/qr-transfer.js` — framing

```js
export function splitTransfer(text, { frameBytes }) -> string[]
export function joinTransfer(frames: string[]) -> { text } | { need: number[] } | { error: string }
```

Frame wire format (one QR byte-mode payload per frame):

```
KQR1 <seq> <total> <nonce> <base64 slice of the whole payload>
```

- `KQR1` — literal tag + version.
- `seq` — 0-based frame index; `total` — frame count; both decimal.
- `nonce` — 6 base64url chars, random per *transfer*, identical on every frame of
  that transfer. Frames whose nonce disagrees with the first accepted frame are
  rejected (stops mixing a stale earlier transfer).
- The base64 slice is a contiguous piece of `base64(utf8(text))`; concatenating
  slices `0..total-1` in order and base64-decoding yields `text`.

`splitTransfer` sizes each slice so the whole frame string fits `frameBytes`
(the byte-mode capacity of the chosen QR version/ECC minus the header).
`joinTransfer` returns `{ text }` once all `total` seqs for one nonce are present,
`{ need: [...] }` while frames are missing, `{ error }` for malformed/none.

## 4. Transfer parameters

- **Frame QR:** version ≤ 10, ECC **M**. `frameBytes` = `QR_CAPACITY[10]['M']`
  minus the header length. One frame ⇒ a static code.
- **Animation:** frames cycle at ~4 fps, looping until the user closes the panel.
- **Cap:** if `splitTransfer` would produce `total > 60`, the export panel
  refuses: *"This vault is too large for a QR transfer — use Save vault (file) or
  Syncthing."* (~60 × ~200 B ≈ 12 KB base64 ≈ a very large vault.)

## 5. UI (`src/vault-ui.js`)

### 5.1 Export — "Show as QR"

A button in the unlocked list footer (real slot; and the decoy slot when active —
it exports whichever envelope `saveVault` would write). Opens a panel with:
the current (animated) QR, a `frame k / N` caption when `N > 1`, a note
*"scan this with the other device's camera"*, and **Done**. It renders from
`splitTransfer(encodeEnvelope(...))` — i.e. the up-to-date envelope, including
any unsaved edits, with a fresh `revision` just like a save (but no download).

Drawing: `qrMatrix` → a `<canvas>` (or CSS-grid of divs) with a 4-module quiet
zone, integer module scale, `image-rendering: pixelated`. No colour but black on
the card background.

### 5.2 Import — "Scan QR…"

A button on the NO_VAULT screen beside "Open vault file…", and in the unlocked
footer (to pull in another copy). Opens a panel with a `<video>` preview, a
`collected / total` line, a *"point at the other device"* hint, and **Cancel**.

Flow:
1. `navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })`.
   Denied / unavailable → *"Camera unavailable — use Open vault file instead."*
2. On each `requestAnimationFrame`, draw the video to an offscreen `<canvas>`
   downscaled to ~480 px on the long edge, `getImageData`, `decodeQr`.
3. Non-null result → `joinTransfer(collectedFrames)`.
   - `{ need }` → update the caption, keep scanning.
   - `{ text }` → stop the camera (`track.stop()`), then:
     - if `state !== 'UNLOCKED'`: `parseEnvelope(text)` → LOCKED view (as a file
       open would).
     - if `state === 'UNLOCKED'`: decrypt with the current key and route through
       Phase 3d `classifyIncoming` (`same` / `fast-forward` / `diverged` /
       `wrong-passphrase`). Before Phase 3d ships: treat as "open a different
       file" with the unsaved-changes guard.
4. Cancel or panel close → `track.stop()` always.

### 5.3 Lifecycle

The camera track is stopped on: success, Cancel, tab switch away from Vault,
`wipe()` (lock / idle-lock), and `beforeunload`. No frame image or decoded text
is persisted; `collectedFrames` lives only in the panel's closure.

## 6. CSP / permissions

Expectation: **no CSP change.** `getUserMedia` is not governed by `connect-src`
(it opens no network connection); a `<video>` populated via `srcObject` is not a
`media-src` URL fetch. The implementation plan MUST verify this in Chrome,
Safari, and Firefox with the real single-file build. **Only if** a browser is
found to enforce `media-src` on `srcObject` do both build CSPs gain
`media-src 'self' blob:` — and `connect-src` is still never added, so the app
stays network-incapable. An installed PWA additionally needs the camera allowed
by the platform's permission prompt; nothing in the manifest blocks it.

## 7. Parent-spec updates

- **§7.3** — flesh out "manual QR/file transfer": in-app camera scanner,
  animated multi-frame export, the `KQR1` frame format, the ~60-frame ceiling.
- **§7.4** — add the conditional `media-src 'self' blob:` note (only if browser
  testing requires it); state the QR codec is first-party and auditable.
- **§12**, phase 3 bullet — QR export/import is specified in
  `2026-09-01-kunji-phase3e-qr-transfer-design.md`.

## 8. Files changed

| File | Change |
|---|---|
| `src/qr.js` | **new** — encoder (§3.1). |
| `src/qr-decode.js` | **new** — decoder (§3.2). |
| `src/qr-transfer.js` | **new** — `KQR1` framing (§3.3). |
| `tools/build.mjs` | `JS_ORDER`: `qr.js`, `qr-decode.js`, `qr-transfer.js` after `encoding.js`. |
| `src/vault-ui.js` | "Show as QR" + "Scan QR…" panels, camera lifecycle, import routing (§5). |
| `src/style.css` | `.qr-panel`, `.qr-canvas`, `.qr-cam` (video sizing), progress line. ~30 lines. |
| `tools/gen-qr-fixtures.mjs` | **new** — emits frozen encoder outputs to `tests/fixtures/qr/`. |
| `tests/qr.test.mjs` | **new** — encoder vs fixtures. |
| `tests/qr-decode.test.mjs` | **new** — render-then-decode round-trips, RS recovery. |
| `tests/qr-transfer.test.mjs` | **new** — split/join. |
| `tests/build.test.mjs` | + the three qr modules appear in the bundle, ordered after `encoding.js`. |
| `tools/check-invariants.mjs` | none. |
| `docs/specs/2026-09-01-kunji-design.md` | §7.3, §7.4, §12 edits. |

## 9. Testing

**Unit — `tests/qr.test.mjs`**
- `qrMatrix` matches frozen fixtures for: the ISO worked example `01234567`
  (numeric is out of scope, so use its byte-mode equivalent), `"HELLO WORLD"`,
  a 200-byte random string at ECC L/M/Q/H, and a payload that forces block
  interleaving (v ≥ 6).
- Version auto-selection: the smallest version whose capacity ≥ payload is
  chosen; over the largest capacity → throws.
- Mask choice is deterministic (same input → same grid) and matches the fixture.

**Unit — `tests/qr-decode.test.mjs`**
- For each of ~8 (version, ecc) pairs: `qrMatrix(bytes)` → render to an
  RGBA grid with a 4-module quiet zone at integer scale (×3, ×5) → `decodeQr`
  → equals `bytes`.
- Rotate the rendered grid 90°/180°/270° → still decodes.
- Flip up to `(RS budget − 1)` modules in one block → still decodes; flip
  `budget + 1` → `null`.
- Pure noise / blank image → `null` (no throw).

**Unit — `tests/qr-transfer.test.mjs`**
- `splitTransfer` then `joinTransfer` (in order, shuffled) → original text.
- Single-frame case (`total === 1`).
- Missing one frame → `{ need: [k] }`.
- A frame with a different `nonce` mixed in → ignored, not an error.
- Malformed frame (`no KQR1`) → `{ error }`.
- `frameBytes` respected: every produced frame string ≤ `frameBytes`.

**Unit — `tests/build.test.mjs`**
- Bundle contains `==== src/qr.js ====`, `==== src/qr-decode.js ====`,
  `==== src/qr-transfer.js ====`, all positioned after `src/encoding.js` and
  before `src/vault.js`.

**Manual browser (over `https://localhost` or a LAN TLS name — camera needs a
secure context)**
- Device A: unlock a small vault → **Show as QR** → single static code.
  Device B: **Scan QR…** → grant camera → code read → LOCKED view → unlock →
  entries present.
- Device A: a vault large enough for 5–10 frames → animated loop. Device B scans
  → `collected / total` climbs → completes out of camera-shake order → unlock.
- Import while already unlocked → routes to the merge dialog (Phase 3d) / the
  "different file" guard (pre-3d).
- Camera permission denied → the fallback message; "Open vault file" still works.
- Cancel mid-scan, tab-switch, and idle-lock all stop the camera (check the OS
  camera indicator goes off).
- `dist/kunji.html` opened from `file://`: Show-as-QR works; Scan requires a
  secure context and shows the fallback if the browser blocks camera on
  `file://`.
- `npm run verify` green; DevTools Network tab empty throughout.

## 10. Out of scope

- No QR payload smaller than the whole envelope (no single-entry QR).
- No import from a still photo / uploaded image file — camera only (the
  `decodeQr(ImageData)` primitive would support it later).
- No decoding in a Web Worker — main thread, downscaled frames.
- No `structured append` across native QR symbols — framing is the `KQR1` layer.
- No new dependency; no `connect-src`; `dist/kunji.html` stays a single file.
- Vaults over ~60 frames are refused for QR (documented fallback to file /
  Syncthing).

## 11. Self-review

- **Placeholders:** the three module contracts are pinned; `qr.js` / `qr-decode.js`
  follow ISO/IEC 18004 and are validated against frozen fixtures and
  render-then-decode round-trips — the plan lands `qr.js` first with its fixture
  test, then `qr-decode.js` against it. No TBDs in the contract or test plan.
- **Consistency:** §2 (ciphertext only crosses) holds — export serialises the
  envelope, never plaintext; import ends at `parseEnvelope` / `classifyIncoming`,
  same as a file open. §3's "not network-capable" holds — the modules import only
  `encoding.js`; the scanner uses `getUserMedia`, which the invariant list does
  not need to forbid because it opens no connection. §6's CSP claim is explicitly
  marked "verify in browsers", with a bounded fallback that still omits
  `connect-src`.
- **Scope:** three self-contained pure modules + Vault-tab camera wiring. No
  crypto change, no `v` bump, no envelope-shape change. Large but single-purpose;
  fits one plan, with `qr.js` → `qr-decode.js` → `qr-transfer.js` → UI as the
  internal order.
- **Ambiguity:** the frame format (§3.3) is byte-exact; the import routing
  branches on `state` and (post-3d) `classifyIncoming`; the camera-stop triggers
  are enumerated (§5.3).
- **Risk noted:** the hand-rolled `decodeQr` is the single largest and riskiest
  unit in all of Phase 3. It is gated by round-trip tests against our own
  encoder and by real-camera manual runs on three browsers before this phase is
  called done.
