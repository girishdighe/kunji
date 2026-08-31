# Kunji

Offline, in-house password tool. One memorised master passphrase plus a site and
account name produce a unique strong password, recomputed on demand. Nothing is
stored or sent. See `docs/specs/2026-09-01-kunji-design.md` for the design and
`docs/plans/` for implementation plans.

## Status

Phase 1: deterministic v1 derivation and the UI, shipped as a single file. No
saved vault yet (Phase 2).

## Build

    node tools/build.mjs

Produces `dist/kunji.html`, a single self-contained file. Open it directly in any
modern browser (Chrome, Safari, Firefox, Edge) on any OS, or add it to your home
screen. It makes no network requests.

## Test

    npm test          # unit tests
    npm run check     # no-network invariant scan
    npm run verify    # both, plus a build

## The v1 profile is frozen

`tests/vectors/v1.json` locks the derivation output. Any code change that alters a
generated password fails `tests/vectors.test.mjs`. Improvements ship as a new
profile id, never by changing v1.

## Crypto

Standard primitives via the platform `crypto.subtle` (PBKDF2-SHA512, HKDF-SHA256,
HMAC-SHA256). No third-party libraries, no build step beyond file concatenation.
