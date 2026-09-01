# Kunji Phase 5b + 5c — Passkey Unlock & Live TOTP Design

> Two independent sub-projects of the Phase 5 line
> (`docs/specs/2026-09-01-kunji-design.md` §12.5), combined into one spec/plan
> because both are additive Vault-tab features that share no code. Depends on:
> Phases 1–4 (shipped on `main`). 5a (profile seam) is not a prerequisite for
> either but may land first.

---

# PART B — Passkey unlock (5b)

## B1. Goal

A second way to unlock a vault on a device the user has already unlocked once
with the passphrase: register a **passkey** (WebAuthn credential with the PRF
extension), and thereafter unlock with the platform biometric/PIN instead of
retyping the master passphrase. The passkey **recovers the full `masterKey`**, so
a passkey unlock is functionally identical to a passphrase unlock — Generate tab,
KCV, decoy routing, and re-encryption on save all work unchanged.

## B2. Threat model & the §10 amendment

**What the passkey protects:** the wrapped `masterKey` on disk is useless without
the platform authenticator, which requires user verification (biometric/PIN) on
every `navigator.credentials.get()`. The PRF secret never leaves the
authenticator.

**What it does not protect against:** an attacker who has the unlocked device
*and* can satisfy the authenticator (your finger/face/PIN). That attacker can
equally watch you type the passphrase — equivalent exposure, not a regression.

**Decoy interaction (documented, not solved):** a registered passkey is a signal
that a real vault exists on this device — like any saved credential. Passkey
registration is offered only from an unlocked **real** vault. The duress story
(spec §4.7) assumes the coerced device has no passkey registered; a user under
threat can remove the local record but that is after the fact. 5b does not add a
decoy passkey.

**Spec §10 amendment (approved).** §10 currently reads *"no secret written to
`localStorage` or a service worker cache."* It becomes:

> …no secret written to `localStorage` or a service worker cache, **with one
> exception: a passkey-wrapped master key** (AES-256-GCM, key derived from a
> WebAuthn PRF secret). The wrapped blob is inert without the platform
> authenticator that produced the PRF secret, and it is per-device — it is never
> written to the vault file and never leaves the device.

The service-worker cache exclusion is unchanged — the passkey blob is `localStorage`
only, never cached by `sw.js` (whose asset list is the static shell).

## B3. Components

### B3.1 `src/webauthn.js` (new, pure-ish — wraps `navigator.credentials`)

```
isPasskeySupported() -> Promise<boolean>
    true iff window.PublicKeyCredential exists and
    PublicKeyCredential.isConditionalMediationAvailable is a function AND a probe
    create/get is plausible. Practically: check `window.PublicKeyCredential` and
    `navigator.credentials?.create`. Never throws.

registerPasskey({ rpId, rpName, userId, userName }) -> Promise<{ credentialId: Uint8Array }>
    navigator.credentials.create({ publicKey: {
      challenge: randomBytes(32),           // not verified server-side; freshness only
      rp: { id: rpId, name: rpName },
      user: { id: userId, name: userName, displayName: userName },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { alg: -257 }],
      authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
      extensions: { prf: {} },
    }})
    Rejects if prf is not reported supported in the result's
    getClientExtensionResults().prf.enabled.

getPasskeySecret(credentialId, salt) -> Promise<Uint8Array(32)>
    navigator.credentials.get({ publicKey: {
      challenge: randomBytes(32),
      allowCredentials: [{ type: 'public-key', id: credentialId }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: salt } } },
    }})
    Returns new Uint8Array(result.getClientExtensionResults().prf.results.first).
    Rejects (not returns null) on user cancel / no PRF / wrong credential.
```

`rpId` = the page origin's registrable domain, or `undefined` for `file://` (the
single-file build): when `location.protocol === 'file:'`, WebAuthn is
unavailable — `isPasskeySupported()` returns `false` and the feature is simply
not offered. Passkey unlock is a **PWA-only** convenience (served from an
origin). This is stated in the UI copy and `docs`.

### B3.2 Wrapping (in `src/vault.js`, pure)

```
wrapMasterKey(masterKey, prfSecret) -> Promise<{ iv: Uint8Array(12), ct: Uint8Array }>
    key = HKDF(SHA-256, ikm = prfSecret, salt = utf8("kunji/v1"), info = utf8("passkey-wrap"), 32)
    iv  = randomBytes(12)
    ct  = AES-256-GCM(key, iv, masterKey, aad = utf8("kunji-passkey-v1"))

unwrapMasterKey({ iv, ct }, prfSecret) -> Promise<Uint8Array(32)>
    same key derivation; AES-256-GCM decrypt; throws on tag failure
```

The PRF **salt** is not an argument to `wrapMasterKey` — the UI generates it
(`randomBytes(32)`) at registration, passes it to `getPasskeySecret` to obtain
`prfSecret`, then assembles the store record itself
(`{ credentialId, prfSalt, iv, ct, label, createdAt }`). On every later unlock
the UI reads `prfSalt` from the record and passes it back to `getPasskeySecret`
so the authenticator reproduces the same `prfSecret`.

### B3.3 Device-local store (`src/passkey-store.js`, new)

Thin `localStorage` wrapper. One record per (vault KCV):

```
key:   "kunji.passkey." + <envelope.kcv>          // base64 KCV, so only offered for the matching file
value: JSON { v: 1, credentialId: b64, prfSalt: b64, iv: b64, ct: b64, label: <string>, createdAt: <iso> }

hasPasskey(kcv) -> boolean
loadPasskey(kcv) -> record | null
savePasskey(kcv, record) -> void
removePasskey(kcv) -> void
```

`label` is a human string ("this device", or `navigator.userAgentData` platform
if available) for the "Remove passkey" UI. Wrapped in try/catch — a
`localStorage` failure (private mode, quota) degrades to "no passkey", never
throws.

### B3.4 Vault-tab wiring (`src/vault-ui.js`)

- **LOCKED screen (`renderLocked`):** after `loadedEnvelope` is set, if
  `isPasskeySupported()` and `hasPasskey(loadedEnvelope.kcv)`, render an
  **"Unlock with passkey"** button above the identity/passphrase fields.
  Click → `getPasskeySecret(record.credentialId, record.prfSalt)` →
  `unwrapMasterKey(record, secret)` → `masterKey`. Then the **existing** unlock
  tail runs verbatim: `computeKcv(masterKey) === loadedEnvelope.kcv` guard,
  `openVault(loadedEnvelope, { masterKey })` (real-then-decoy router), set
  `state = 'UNLOCKED'`, `unlockedSlot`, publish the bridge, `render()`.
  On reject (cancel / auth fail): show `#vlError` "Passkey unlock failed — use
  your passphrase" and leave the passphrase path available.
- **UNLOCKED footer (`renderList`), real slot only** (`unlockedSlot === 'real'
  && activeSlot === 'real'`), next to the decoy controls:
  - no record → **"Set up passkey on this device…"** → confirm → `registerPasskey`
    → `wrapMasterKey(masterKey, secret)` → `savePasskey(loadedEnvelope.kcv, …)`.
    Needs `loadedEnvelope` (so: only after at least one save; if `loadedEnvelope`
    is null because the vault was just `createVault`ed and never saved, the
    control says "Save the vault first").
  - record present → **"Remove passkey (this device)"** → confirm →
    `removePasskey`. Note in the confirm text that this only forgets the wrapped
    key; the platform credential must be deleted in OS settings.
- **`wipe()`** does **not** touch the passkey store (it is device-persistent, not
  session state). Locking and re-unlocking with a passkey is the normal path.
- No `beforeunload` / idle-lock changes.

### B3.5 Build / invariants

- `src/webauthn.js`, `src/passkey-store.js` join `JS_ORDER` after `webcrypto.js`,
  before `derive.js` (they depend on nothing but `encoding.js` /
  `webcrypto.js` / globals).
- `check-invariants.mjs` forbids `fetch`, XHR, WebSocket, `sendBeacon`, external
  URLs, `<link>`, `<script src>`, `@import` — **none** of which the new modules
  use. `navigator.credentials` and `localStorage` are not on the list and are not
  network APIs. No invariant change. (The scanner's file count rises by 2.)
- No CSP directive added — WebAuthn needs none.

## B4. Testing (5b)

WebAuthn cannot run under `node:test` (no authenticator). Split accordingly:

- **`tests/passkey.test.mjs`** — the pure crypto:
  - `wrapMasterKey` then `unwrapMasterKey` round-trips a 32-byte key for a given
    32-byte PRF secret.
  - `unwrapMasterKey` with the wrong PRF secret throws (GCM tag failure), does
    not return garbage.
  - the wrap is non-deterministic (fresh IV) but unwrap is stable.
  - `passkey-store`: `savePasskey`/`loadPasskey`/`hasPasskey`/`removePasskey`
    against a `globalThis.localStorage` shim (a `Map`-backed stub the test
    installs); `loadPasskey` on a corrupt JSON value returns `null`, does not
    throw; all four functions no-op safely when `localStorage` throws.
  - key namespacing: a record saved under KCV `A` is invisible to `hasPasskey(B)`.
- **`src/webauthn.js`** — no unit test (browser-only). `isPasskeySupported()`
  gets a trivial test that it returns `false` (not throws) when
  `window`/`navigator.credentials` are absent (the Node environment).
- **Manual (browser, over the PWA origin):** register a passkey from an unlocked
  real vault → lock → "Unlock with passkey" → biometric → unlocked, Generate tab
  works, KCV green. Remove passkey → the button is gone on next lock. `file://`
  build → the passkey controls never appear. A second vault file (different KCV)
  on the same device → its own passkey slot, independent. DevTools → Application →
  Local Storage shows exactly one `kunji.passkey.<kcv>` entry, value is opaque
  base64.

---

# PART C — Live TOTP (5c)

## C1. Goal

The vault already stores an optional `totp` secret per entry; nothing generates
codes from it. 5c generates the rolling code in the entry detail view: current
6/8-digit code, copy button, countdown to the next step. Zero hand-rolled crypto
— HMAC-SHA1/256/512 is `crypto.subtle`; only base32 decoding and RFC 4226
truncation are new code.

## C2. Data model

`entry.totp` today is a bare base32 string or `null`. It becomes **either**:

- `null` (no TOTP), **or**
- a string (legacy — treated as `{ secret: <string>, algorithm: 'SHA-1',
  digits: 6, period: 30 }`), **or**
- an object `{ secret, algorithm, digits, period }` where `algorithm ∈
  {'SHA-1','SHA-256','SHA-512'}`, `digits ∈ {6,7,8}`, `period` a positive
  integer.

`normaliseTotp(value)` (in `src/vault.js`, pure) folds all three into the object
form or `null`. Called by `makeEntry`/`updateEntry` so the in-memory entry always
holds the object form (or `null`); `encodeEnvelope` persists whatever is there.
No vault `format`/`v` bump — this is a backward-additive widening of an optional
field, and the string form is still accepted on load. (Spec §5.2 gains the object
shape; §8's "data-model bumps carry a migration" is not triggered because reading
old data needs no migration.)

## C3. Components

### C3.1 `src/totp.js` (new, pure)

```
base32Decode(str) -> Uint8Array
    RFC 4648 base32, case-insensitive, strips spaces and '=' padding.
    Throws on a non-alphabet character.

hotp(keyBytes, counter /* integer >= 0 */, { algorithm = 'SHA-1', digits = 6 }) -> Promise<string>
    mac = HMAC(algorithm, keyBytes, uint64be(counter))     // 8-byte big-endian counter
    offset = mac[mac.length - 1] & 0x0f
    bin = ((mac[offset] & 0x7f) << 24) | (mac[offset+1] << 16) | (mac[offset+2] << 8) | mac[offset+3]
    return String(bin % 10**digits).padStart(digits, '0')

totp(totpObj, { now = Date.now() } = {}) -> Promise<{ code, secondsRemaining, period }>
    key = base32Decode(totpObj.secret)
    counter = Math.floor(now / 1000 / totpObj.period)
    code = await hotp(key, counter, totpObj)
    secondsRemaining = totpObj.period - Math.floor(now / 1000) % totpObj.period

parseOtpauth(uri) -> { secret, algorithm, digits, period, issuer, account } | null
    Parses otpauth://totp/LABEL?secret=...&algorithm=...&digits=...&period=...&issuer=...
    Uppercases algorithm to SHA-1/SHA-256/SHA-512 form; defaults SHA-1/6/30.
    Returns null (never throws) for a non-otpauth or non-totp URI.
```

`uint64be` — small helper (JS numbers are safe to 2^53; TOTP counters are ~1.8M
now, fine). Add to `src/encoding.js` next to `uint32be`.

`crypto.subtle` HMAC: `importKey('raw', key, {name:'HMAC', hash: algorithm}, …)`
where `algorithm` is `'SHA-1' | 'SHA-256' | 'SHA-512'` — all supported.
`src/webcrypto.js` gains `hmac(algorithm, keyBytes, msgBytes)` (generalising the
existing SHA-256-only `hmacSha256`, which stays as a thin wrapper for the
derivation pipeline so the frozen vectors are untouched).

### C3.2 Vault-tab UI (`src/vault-ui.js`)

- **`renderDetail`** — the current TOTP section (`e.totp ? '•••• copy' : '—'`)
  becomes, when `e.totp` is set:
  - the live code, grouped `XXX XXX` (or `XXXX XXXX` for 8), monospace;
  - a **copy** button (clipboard write + the existing `clipboardClearSeconds`
    auto-clear, same helper the password copy uses);
  - a thin countdown bar or `Ns` text to the next step; a `setInterval` (1 s)
    recomputes `totp()` and updates the bar; cleared when the detail view is left
    (track the interval id like the existing `revealTimer`, clear in the
    view-change paths and in `wipe()`).
  - if `base32Decode` throws (a malformed stored secret), show
    "TOTP secret is not valid base32" instead of a code.
- **`renderEditor`** — the `#edTotp` field stays a single text input labelled
  "TOTP secret or otpauth:// URI (optional)". On save:
  - if the value parses as `otpauth://` → `parseOtpauth` → object form;
  - else if non-empty → `{ secret: value.replace(/\s+/g,''), algorithm:'SHA-1',
    digits:6, period:30 }`;
  - else `null`.
  - a non-blocking hint under the field: "doesn't look like base32" when the
    trimmed non-URI value has a char outside `[A-Za-z2-7= ]`.
  - The editor does **not** expose algorithm/digits/period as separate inputs
    (YAGNI — the `otpauth://` paste carries them; hand-entry is the SHA-1/6/30
    common case). A future task can add advanced fields.
- No new CSS beyond a `.v-totp-code` / `.v-totp-bar` pair appended to
  `src/style.css`.

### C3.3 Build / invariants

- `src/totp.js` joins `JS_ORDER` after `webcrypto.js`, before `derive.js`.
- No forbidden patterns; no CSP change; scanner file count +1.

## C4. Testing (5c)

- **`tests/totp.test.mjs`**:
  - `base32Decode` — known vectors (`'JBSWY3DPEHPK3PXP'` → the ASCII of
    `"Hello!\xDE\xAD\xBE\xEF"`; RFC 4648 `'MY======'` → `'f'`), space/pad
    tolerance, throws on `'0189'`.
  - **RFC 4226 Appendix D** — the 10 HOTP values for secret `"12345678901234567890"`,
    counters 0–9, 6 digits: `755224 287082 359152 …`.
  - **RFC 6238 Appendix B** — TOTP for the three algorithms at the published
    timestamps (`59, 1111111109, 1234567890, 2000000000, 20000000000`), 8 digits,
    with the SHA-1/256/512 seeds from the RFC. `totp()` called with an explicit
    `now` = timestamp·1000.
  - `secondsRemaining` boundary: at `now` exactly on a period multiple →
    `period`; one second before → `1`.
  - `parseOtpauth` — a full Google-style URI → all fields; missing params →
    defaults; `otpauth://hotp/...` or `https://...` → `null`.
  - `normaliseTotp` — string / object / null / `{secret}` (partial) all fold to
    the object form or `null`, defaults filled.
- **`tests/vault.test.mjs`** — `makeEntry({ totp: 'ABC...' })` stores the object
  form; `makeEntry({ totp: null })` stores `null`; a round-trip through
  `encodeEnvelope`/`openVault` preserves the object.
- **`tests/webcrypto.test.mjs`** — the generalised `hmac('SHA-1', …)` matches a
  `node:crypto` reference; `hmac('SHA-256', …)` still equals the old
  `hmacSha256`.
- **Manual (browser):** add an entry with a real `otpauth://` URI from an
  authenticator app → detail view shows the same 6-digit code as the app,
  advancing every 30 s; copy works and clears; an entry with a bad secret shows
  the error line; the frozen generator vectors still pass (HMAC-SHA256 path
  untouched).

---

# Cross-cutting

## X1. File structure

| File | 5b | 5c |
|---|---|---|
| `src/webauthn.js` | **new** — `navigator.credentials` + PRF wrapper | — |
| `src/passkey-store.js` | **new** — `localStorage` record CRUD | — |
| `src/totp.js` | — | **new** — base32, HOTP, TOTP, otpauth parse |
| `src/vault.js` | + `wrapMasterKey` / `unwrapMasterKey` | + `normaliseTotp` |
| `src/encoding.js` | — | + `uint64be` |
| `src/webcrypto.js` | — | + `hmac(algorithm, …)` (generalises `hmacSha256`) |
| `src/vault-ui.js` | LOCKED "unlock with passkey"; footer set-up/remove | detail live code + countdown; editor otpauth parse |
| `src/style.css` | — | `.v-totp-*` |
| `tools/build.mjs` | `JS_ORDER` += the 2 modules | `JS_ORDER` += `totp.js` |
| `docs/specs/2026-09-01-kunji-design.md` | §10 amendment; §11 passkey row | §5.2 totp shape |
| `README.md` | "unlock with a passkey (PWA only)" line | "live 2FA codes" line |

## X2. Ordering

5c first (self-contained, no policy change, no browser-only paths), then 5b.
Within 5c: `encoding.uint64be` → `webcrypto.hmac` → `src/totp.js` + tests →
`vault.normaliseTotp` → UI. Within 5b: `vault.wrap/unwrap` + tests →
`passkey-store` + tests → `webauthn.js` → UI → §10 spec amendment → README.

## X3. Non-goals

- Syncing passkeys or TOTP display state across devices (passkeys are
  device-bound by design; TOTP is computed fresh).
- A decoy passkey; multiple passkeys per vault per device.
- Editing TOTP algorithm/digits/period by hand in the editor (only via
  `otpauth://` paste).
- TOTP for the decoy slot gets no special handling — a decoy entry with a random
  secret generates a plausible-looking code, which is fine.
- Conditional-UI / autofill passkey mediation; `file://` passkey support
  (impossible — no origin).

## X4. Open questions

None outstanding. The §10 relaxation is approved (option i).
