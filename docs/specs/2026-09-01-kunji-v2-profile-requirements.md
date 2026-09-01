# v2 profile — requirements

A future `v2` KDF profile must meet this contract before it can be registered in
`PROFILES` (`src/derive.js`).

## Interface

    deriveMasterKey(passphrase: string, normalisedIdentity: string)
      -> Promise<Uint8Array(32)>

Deterministic. `normalisedIdentity` is already NFKC + trim + lowercase (the
registry wrapper applies `normaliseInput`). No salt input beyond the identity; no
cost knobs in the signature — cost is baked into the profile object.

## Primitive

Memory-hard. Argon2id (RFC 9106) preferred; scrypt (RFC 7914) acceptable; a
browser-native Argon2 if one ships in `crypto.subtle`. Pure JavaScript, zero
dependencies. WASM only if `tools/check-invariants.mjs` and the CSP still pass —
today they would not, so effectively pure JS.

## CI gate

Every applicable RFC test vector passes (a committed `tests/vectors/v2.json` in
the same shape as `v1.json`, plus the primitive's own KAT file). Output drift
fails the vector test exactly as a v1 change does.

## Cost target

<= ~1.5 s for one derivation on the slowest supported device (an older Android
tablet). `p = 1` — JavaScript is single-threaded.

## Registration

One object added to `PROFILES`: `{ id, label, deriveMasterKey, kdfTag }` with a
unique `kdfTag` (e.g. `argon2id-m65536-t3-p1`). No change to `src/derive.js`
Steps 2–6 (HKDF entry seed, HMAC keystream, rejection sampling, class
enforcement — all SHA-256, profile-agnostic).

## Migration

Per entry: set `entry.profile = 'v2'`, re-derive, change the password at the
site. A whole-vault re-key (re-encrypt the envelope under a v2 master key, new
`kdf` tag) is a separate explicit action. Never automatic, never global. A vault
may hold v1 and v2 entries simultaneously; the envelope stays on its original
profile until an explicit re-key.
