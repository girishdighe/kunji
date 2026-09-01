# Architecture

How Kunji is put together, for people who want to audit it or build on it. Pair
this with the per-feature design docs in [`docs/specs/`](specs/).

## Design constraints (the non-negotiables)

1. **One file.** The whole tool ships as a single `kunji.html`. No runtime
   dependencies, no separate assets.
2. **No network, ever.** Enforced three ways: a `default-src 'none'` CSP, the
   `check-invariants.mjs` source scan, and the absence of any networking code.
3. **Nothing persisted without an explicit user action.** The only artifact
   Kunji writes is the vault file the user chooses to save, and it is ciphertext.
4. **v1 derivation output is immutable.** Frozen by `tests/vectors/v1.json`.
   Changes ship as new profile ids.
5. **Standard primitives only**, all via the platform `crypto.subtle`. No
   third-party crypto.

Everything below serves these.

## Runtime shape

`kunji.html` is: `<head>` (CSP + inlined CSS) → DOM skeleton → one `<script>`
containing every module concatenated in dependency order. On load:

- `app.js` wires the **Generate** tab.
- `vault-ui.js` wires the **Vault** tab (lazily — nothing crypto happens until
  you unlock).
- `readout.js` starts the decorative header display.

There is no framework, no virtual DOM, no state container. Each tab module owns
its DOM subtree and a few module-scoped variables. Secrets live in local
variables and typed arrays and are dropped when the tab re-renders or locks.

## The generator (`derive.js`)

The heart of the tool. Given `identity, passphrase, site, account, counter,
rules, length`:

```
identity'      = NFKC( trim( lower( identity ) ) )          # also site, account
masterKey      = PBKDF2-HMAC-SHA512( passphrase, identity', 600_000 )   → 32 bytes
KCV            = base64( HMAC-SHA256( masterKey, "kunji/kcv/v1" )[0:4] )
entrySeed      = HKDF-SHA256( ikm=masterKey, salt="kunji/v1",
                              info="gen|site|account|counter|rules|length", L=64 )
keystream      = SHACAL-ish CTR stream keyed by entrySeed         # makeKeystream()
password chars = rejection-sample keystream into CHARSETS[rules], length times
                 then enforceClasses() guarantees each required character class
                 appears, without weakening the sample
```

- **Rejection sampling** (`sampleIndex`) discards bytes `>= 256 - (256 % n)` so
  every character in the set is equally likely — no modulo bias.
- **`enforceClasses`** only *adds* a missing class by replacing a position that
  isn't the sole carrier of another required class; it draws the replacement from
  the same keystream, so the result stays deterministic and full-entropy.
- **Profiles.** `PROFILES` in `derive.js` is a registry keyed by id. `v1` is
  `{ deriveMasterKey: PBKDF2-SHA512 @ 600k, ... }`. A future `v2` is one more
  object; entries record which profile made them, so old passwords never move.
  Requirements for `v2` live in
  [`specs/2026-09-01-kunji-v2-profile-requirements.md`](specs/2026-09-01-kunji-v2-profile-requirements.md).

The **KCV** is shown in the UI purely as a typo check on identity+passphrase. It
is 4 bytes of an HMAC over a fixed label; it commits to the master key without
revealing anything that shortcuts a passphrase guess beyond what any password
verifier would.

## The vault (`vault.js`, `vault-bridge.js`, `vault-ui.js`)

The vault stores entry *parameters*, notes, TOTP secrets and recovery codes —
**never a derived password**.

### File format (`kunji-data.json`)

Pretty-printed JSON envelope:

```jsonc
{
  "format": "kunji-vault",
  "v": <int>,
  "kdf": "pbkdf2-sha512-600000",
  "revision": <int>,          // bumped each save; drives merge
  "lastWriter": "<writerId>", // which device wrote this revision
  "kcv": "<base64>",          // KCV of the REAL master key
  "iv":  "<base64>",
  "ct":  "<base64>",          // AES-256-GCM( vaultKey, iv, realPlaintext, AAD )
  "decoy": {                  // present only if a decoy is configured
    "kcv": "<base64>",        // KCV of the DECOY master key
    "iv":  "<base64>",
    "ct":  "<base64>"
  }
}
```

- `vaultKey = HKDF-SHA256(masterKey, "kunji/v1", "vault-key", 32)`.
- Each slot's plaintext is **padded to a fixed block multiple** before
  encryption, so ciphertext length does not reveal how many entries a slot holds
  — a vault with a decoy is indistinguishable from one without, by size.
- **Unlock** recomputes the KCV from the entered passphrase and compares:
  matches `kcv` → real slot; matches `decoy.kcv` → decoy slot; neither → generic
  failure, no partial data. There is no flag that says "a decoy exists".

### Merge (`vault.js`)

Entries carry per-field edit timestamps and a stable id. Deletes leave a
**tombstone** (id + deletion time) instead of dropping the entry, so an old copy
can't resurrect it. Merging two decrypted vaults is a deterministic per-entry
"newest edit wins", classified for the UI as added / updated / deleted-here /
deleted-there / unchanged. `revision` + `lastWriter` detect fast-forward vs.
divergence. Full rules: [`specs/2026-09-01-kunji-phase3d-sync-merge-design.md`](specs/2026-09-01-kunji-phase3d-sync-merge-design.md).

## Crypto helpers (`webcrypto.js`, `encoding.js`)

`webcrypto.js` is a thin promise wrapper over `crypto.subtle` exposing
`pbkdf2Sha512`, `hkdfSha256`, `hmacSha256` (and SHA-1 HMAC for TOTP), plus
`aesGcmEncrypt/Decrypt`. `tests/webcrypto.test.mjs` checks each against its
published RFC known-answer vector (RFC 5869 HKDF, RFC 4231 HMAC, McGrew GCM,
PBKDF2 against `node:crypto`). `encoding.js` is byte/base64/utf8 plumbing with no
dependencies.

## TOTP (`totp.js`)

RFC 6238, `HMAC-SHA1`, 30-second step, 6 digits. Accepts a bare base32 secret or
a full `otpauth://totp/...` URI. Computed locally in the entry detail view; the
countdown is `requestAnimationFrame`-driven. Checked against RFC 6238 appendix B.

## Passkey unlock (`webauthn.js`, `passkey-store.js`)

Installed-PWA only (needs a stable origin for WebAuthn). On enrol, Kunji creates
a discoverable credential with the **PRF extension**, derives
`wrapKey = HKDF-SHA256(prfSecret, "kunji/v1", "passkey-wrap", 32)`, and stores
`AES-GCM(wrapKey, masterKey)` alongside the credential id and PRF salt. On
unlock, WebAuthn returns the same `prfSecret`, the wrap key is rederived, and the
master key is unwrapped. The authenticator's biometric never reaches the page;
the wrapped blob is useless without that authenticator. The passphrase path is
always retained.

## QR transfer (`qr.js`, `qr-decode.js`, `qr-transfer.js`)

Moves the whole encrypted envelope between two devices with no shared channel.
`qr-transfer.js` chunks the envelope across numbered frames with a header
(total, index, checksum); the sender animates them, the receiver reassembles and
verifies before handing off to the normal unlock flow. Only ciphertext is ever
on screen. Fixtures in `tests/vectors/qr/`.

## The PWA build (`tools/pwa/`)

`build.mjs` emits `dist/pwa/` for installability: `sw.js` (app-shell cache),
`manifest.webmanifest`, generated icons, and a registration snippet. The CSP
gains `worker-src 'self'` and nothing else. `sw.js` is the **only** file
permitted `fetch`/`caches`, and only to serve the pinned local shell — the
`check-invariants.mjs` relaxed pass enforces that and forbids `connect-src` and
any external origin.

## The header wordmark and readout (`readout.js`, `src/head.html`)

Cosmetic, and built to respect the constraints. The "Kunji" wordmark is an
**inline SVG** of Hanken Grotesk ExtraBold glyph outlines (`fill="currentColor"`)
— a real web font would need a `<link>` or an `@font-face` URL, both of which the
invariant scan and CSP forbid. `readout.js` draws a split-flap status display on
a `<canvas>` from a `requestAnimationFrame` loop: no timers, no storage, no
network, honours `prefers-reduced-motion`, and reads the theme's CSS variables so
it tracks the palette. Design study:
[`docs/readout-studies.html`](readout-studies.html).

## Tests and CI

- `npm test` — `node:test` suites: unit, crypto KATs, frozen `v1` vectors, QR
  round-trips, vault merge classification, envelope round-trip.
- `npm run check` — the invariant scan.
- `.github/workflows/ci.yml` — on every push/PR and weekly: test + check +
  build-twice-and-compare-hash + working-tree-clean.
- `.github/workflows/verify-release.yml` — per tag: independent rebuild,
  signature check, and hash match against `releases/v<version>.txt`.
