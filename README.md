# Kunji

Offline, in-house password tool. One memorised master passphrase plus a site and
account name produce a unique strong password, recomputed on demand. Nothing is
stored or sent. See `docs/specs/2026-09-01-kunji-design.md` for the design and
`docs/plans/` for implementation plans.

## Status

Phase 2: the deterministic v1 generator (Phase 1) plus an optional encrypted
vault — `kunji-data.json`, AES-256-GCM, entry list / detail / editor, SSO
entries, 5-minute idle auto-lock — still shipped as a single file. Decoy
authoring, QR, and sync merge are Phase 3.

## Build

    node tools/build.mjs

Produces `dist/kunji.html`, a single self-contained file. Open it directly in any
modern browser (Chrome, Safari, Firefox, Edge) on any OS, or add it to your home
screen. It makes no network requests.

## Test

    npm test          # unit tests
    npm run check     # no-network invariant scan
    npm run verify    # both, plus a build

## The vault

Open the Vault tab, create a vault or open a `kunji-data.json` file, unlock it
with the same identity + master passphrase that drives the generator. The file
is one AES-256-GCM blob; it holds no derived passwords, only entry parameters,
notes, TOTP secrets and recovery codes. "Save vault" downloads a fresh copy —
move it wherever your sync tool watches.

## The v1 profile is frozen

`tests/vectors/v1.json` locks the derivation output. Any code change that alters a
generated password fails `tests/vectors.test.mjs`. Improvements ship as a new
profile id, never by changing v1.

## Crypto

Standard primitives via the platform `crypto.subtle` (PBKDF2-SHA512, HKDF-SHA256,
HMAC-SHA256). No third-party libraries, no build step beyond file concatenation.
