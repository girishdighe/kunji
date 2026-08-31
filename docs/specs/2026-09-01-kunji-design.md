# Kunji design spec

**Date:** 2026-09-01
**Status:** Draft for review
**Authors:** grd + friend

---

## 1. Purpose

Kunji is an offline, in-house password tool. It turns one memorised master
passphrase into a unique strong password for every site, recomputed on demand.
It stores no passwords. A small encrypted file covers the cases pure computation
cannot express (custom rules, PINs, 2FA recovery codes, notes).

It must run on Windows, macOS, Android, iOS, and Linux from a single codebase,
work with no network connection, and be simple enough that any reader can audit
a release by reading it.

### Non-goals

- Not a browser autofill extension. Copy/paste only, for v1.
- Not a team or shared-org vault. Family use is handled by an optional shared
  master for a few "break glass" accounts, not by multi-user infrastructure.
- Not a 2FA authenticator app. It can *store* a TOTP secret or recovery codes in
  the encrypted file, but generating live TOTP codes is a later, optional add.
- No account, no server, no sign-up, ever.

---

## 2. Threat model

### Defended

| Threat | Defence |
|---|---|
| Attacker has the data file at rest | File is one AES-256-GCM blob. No passwords in it. Cracking needs the master passphrase through a slow KDF. |
| Attacker has the app file | App is public source, holds no secrets, makes zero network calls (self-imposed CSP). |
| Weak-ish master passphrase, offline guessing | Memory/CPU-hard KDF sets the work factor. Guidance pushes a 5-word+ passphrase. |
| Supply-chain / CDN injection | Nothing is loaded from any network origin. Single file, published SHA-256, reproducible build. |
| Coerced to open the app (duress) | Decoy master passphrase unlocks a prepared fake vault. |
| Typo in master passphrase causing silent wrong password | Key check value (KCV) shows a live "verified" indicator before generating. |
| Lost all devices | Any default-profile entry is recomputable from memory alone (identity + master + site + account). Customised entries recover from the synced/backed-up file. |
| Public project changes an algorithm and breaks existing passwords | Frozen, versioned algorithm profiles. `v1` output can never change. |

### Not defended (stated plainly)

- **A compromised device while you are using it.** Root/admin malware present at
  the moment you type the master passphrase can keylog it, screenshot the output,
  or read process memory. No password tool survives this. Kunji's answer is to
  minimise the surface (offline, tiny, auditable) and add duress protection, not
  to claim immunity.
- **A forgotten master passphrase.** Nothing stored means nothing to recover from.
  Mitigation is the user's choice: memorise it, and optionally keep a sealed
  paper copy in a home safe or with a trusted person.
- **Service-side 2FA lockout.** Kunji reproduces the *password*. If a site also
  demands a code from a lost phone, the password alone will not log you in. Store
  that site's recovery codes in the encrypted file (section 5).
- **Traffic analysis of the decoy.** The decoy is deception, not cryptographic
  hiding. A sophisticated attacker who inspects the file knows a decoy *may*
  exist. Mitigated by always writing a decoy section (random bytes when unused)
  so its presence reveals nothing.

---

## 3. Core concept

```
password = derive(identity, masterPassphrase, site, account, counter, length, rules, profile)
```

- **Deterministic core.** Same inputs, same output, on any device, forever. No
  storage needed for any entry left at default settings.
- **Encrypted overrides.** One local blob, `kunji-data.json`, holds the list of
  entries and their non-default parameters, plus notes, TOTP secrets, and
  recovery codes. Encrypted with a key derived from the same master passphrase.
- **Identity as salt.** `identity` is a memorable string the user picks once (an
  email address, or just a name). It is the KDF salt, so it never has to be
  stored, so recovery needs only things kept in the user's head.

---

## 4. The v1 profile (frozen)

Everything in this section is immutable once v1 ships. Test vectors are committed.
CI fails if any listed value or procedure changes. Future improvements ship as a
new profile id (`v2`, ...), never by editing v1.

### 4.1 Input normalisation

Applied to `identity`, `site`, and `account`:

1. Unicode NFKC normalisation.
2. Trim leading/trailing ASCII whitespace.
3. Lowercase via JavaScript `String.prototype.toLowerCase()` (locale-independent,
   Unicode-defined). Specified concretely so every implementation agrees.

No `www.` stripping, no public-suffix logic. The user types the registered
domain (`github.com`) and stays consistent. The entry list and KCV make drift
visible. UI shows a non-blocking hint.

### 4.2 Numeric inputs

- `counter`: integer >= 1. Default `1`. Bump to rotate one site's password.
- `length`: integer, 8..64 inclusive. Default `20`.
- `rules`: one of the ids in 4.3.

### 4.3 Character sets (exact, frozen)

- `standard` (default):
  `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*+-=?@_`
- `letters-digits`:
  `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`
- `max-symbols`:
  `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*()-_=+[]{};:,.?@`

Required character classes:

- `standard`: >= 1 lowercase, >= 1 uppercase, >= 1 digit, >= 1 symbol.
- `letters-digits`: >= 1 lowercase, >= 1 uppercase, >= 1 digit.
- `max-symbols`: same as `standard`.

### 4.4 Derivation pipeline (v1)

**Step 1: master key.**
`masterKey = PBKDF2(hash = SHA-512, password = utf8(masterPassphrase),
salt = utf8(normalised identity), iterations = 600000, dkLen = 32)`

v1 KDF is PBKDF2-HMAC-SHA512 because it is native in Web Crypto on every target
platform, so v1 ships with zero hand-written crypto. A future `v2` profile
replaces Step 1 with our own Argon2id (RFC 9106), test-vector verified, cost
parameters frozen at that time.

**Step 2: entry seed.**
`entrySeed = HKDF(hash = SHA-256, ikm = masterKey, salt = utf8("kunji/v1"),
info = utf8("gen|" + site + "|" + account + "|" + counter + "|" + rules + "|" + length),
L = 64)`

**Step 3: keystream.**
For block index `i = 0, 1, 2, ...`:
`block(i) = HMAC-SHA256(key = entrySeed, msg = utf8("gen") || uint32be(i))`
Concatenate blocks; consume bytes left to right, pulling more blocks as needed.

**Step 4: character selection (unbiased rejection sampling).**
Let `n = len(charset)`, `limit = 256 - (256 mod n)`.
For each of the `length` positions: read the next keystream byte `b`; if
`b >= limit` discard and read again; otherwise emit `charset[b mod n]`.

**Step 5: guarantee required classes.**
Derive a second stream `fix(i) = HMAC-SHA256(entrySeed, utf8("fix") || uint32be(i))`.
Maintain `used`, the set of positions this step has already written (initially
empty). For each required class not present in the current working string, in the
class order listed in 4.3:

1. Compute `protected`: the set of positions `p` whose character belongs to a
   required class that occurs **exactly once** in the current working string.
   These are the sole carriers of an already-satisfied class and must not be
   overwritten.
2. Read one `fix` byte, map by rejection sampling into `[0, length)` to pick a
   target position. While that position is in `used ∪ protected`, advance
   `(pos + 1) mod length` until a position outside that set is found. (With
   `length >= 8` and at most four required classes, `used` has at most three
   members and `protected` at most three, so a free position always exists and
   the scan terminates.)
3. Read `fix` bytes, rejection-sample into that class's character list, write the
   chosen character at the target position, and add the position to `used`.

Per-class character lists: lowercase `a-z`, uppercase `A-Z`, digit `0-9`, symbol
= the symbol characters present in the active `rules` charset. This changes at
most 4 of `length` positions, never removes an already-present required class,
and is fully deterministic. The Step 6 output therefore always contains every
required class.

**Step 6: output** the resulting `length`-character string.

### 4.5 Key check value

`kcv = base64(HMAC-SHA256(key = masterKey, msg = utf8("kunji/kcv/v1"))[0:4])`

Stored in the file header in cleartext. 32 bits: enough to catch a mistyped
passphrase, not a meaningful help to an offline attacker (the KDF is the work
factor, and any known derived password is an equivalent oracle). The UI shows a
green "verified" dot when the typed passphrase reproduces the stored KCV.

### 4.6 Vault encryption

- `vaultKey = HKDF(SHA-256, ikm = masterKey, salt = utf8("kunji/v1"),
  info = utf8("vault-key"), L = 32)`
- Encrypt the plaintext JSON (section 5) with AES-256-GCM, fresh random 12-byte
  IV per save, `additionalData = utf8("kunji-vault-v1")`.
- Wrong passphrase is detected by GCM tag failure; KCV just makes the feedback
  instant and pre-generate.

### 4.7 Decoy

- The file always contains a `decoy` section: `{ kcv, iv, ct }` with the same
  AES-256-GCM scheme, keyed by `vaultKey` derived from a *different* master
  passphrase (the decoy passphrase). When the user has not set one up, the
  section is filled with random bytes of a plausible length.
- Unlock order: derive key from entered passphrase; if it matches the real KCV,
  load the real vault; else if it matches the decoy KCV, load the decoy vault;
  else reject.
- The decoy vault is an ordinary vault the user populates with believable but
  useless entries.

---

## 5. Data model

### 5.1 File: `kunji-data.json`

```jsonc
{
  "format": "kunji-data",
  "v": 1,
  "kdf": "pbkdf2-sha512-600000",   // profile that produced vaultKey/kcv
  "identityHint": null,             // optional display-only string, opt-in
  "kcv": "aB3d",                    // 4-byte base64
  "iv": "…",                        // 12-byte base64
  "ct": "…",                        // AES-256-GCM ciphertext+tag, base64
  "decoy": { "kcv": "…", "iv": "…", "ct": "…" },
  "revision": 42,                   // monotonic per vault, for sync merge
  "lastWriter": "device-uuid",
  "updatedAt": "2026-09-01T00:00:00Z"
}
```

`identity` itself is never written unless the user ticks "remember identity on
this device", and even then only as `identityHint` for prefill convenience.

### 5.2 Decrypted plaintext

```jsonc
{
  "entries": [
    {
      "id": "uuid",
      "name": "GitHub",
      "site": "github.com",
      "account": "alex-personal",
      "type": "password",
      "profile": "v1",
      "counter": 1,
      "length": 20,
      "rules": "standard",
      "notes": "",
      "totp": null,                 // optional base32 secret string
      "recoveryCodes": [],          // optional array of strings
      "updatedAt": "2026-09-01T00:00:00Z"
    },
    {
      "id": "uuid",
      "name": "Some News Site",
      "site": "news.example.com",
      "account": "alex@example.com",
      "type": "sso",
      "via": { "site": "google.com", "account": "alex@example.com" },
      "notes": "no password, log in with Google",
      "updatedAt": "2026-09-01T00:00:00Z"
    }
  ],
  "settings": {
    "clipboardClearSeconds": 25,
    "revealSeconds": 20,
    "defaultRules": "standard",
    "defaultLength": 20
  }
}
```

### 5.3 Multiple accounts on one site

An entry is identified by `site + account`. Three Google identities are three
entries with `site = "google.com"` and different `account` values, producing
three independent passwords. When the user enters a site that matches more than
one entry, Kunji shows a small "which account?" picker rather than guessing.

Sites you log into *with* Google (OAuth) get `type: "sso"`: no password is
derived, the entry records which identity to use and points at the underlying
Google entry.

---

## 6. Recovery walkthroughs

### 6.1 Lost every device, need a default-profile password (the GitHub case)

1. Get Kunji onto any new device (open the file, or Add to Home Screen). No
   account, no sign-in.
2. Enter: `identity` (known), `master passphrase` (known), `site` = `github.com`
   (known), `account` = your username (known). Leave counter/length/rules at
   defaults.
3. Kunji derives the exact GitHub password. Log in.
4. From there, re-pair Syncthing or import the vault to get customised entries
   back.

Works for every entry left at default settings, with nothing but memory.

### 6.2 Customised entry after total device loss

The non-default parameters live only in `kunji-data.json`. Recovery needs one of:
the Syncthing mesh (another device or a peer still holding it), the periodic git
snapshot, a QR/file export, or a family member's copy. Without any of those, only
the *parameters* of customised entries are lost; defaults still recompute.

### 6.3 Family "break glass"

For a small set of shared accounts, use a shared family master passphrase and a
shared vault file synced to parents' devices. Personal accounts use each
person's own master and are unaffected. Note that recovering a service that has
2FA bound to a lost device also needs that service's recovery codes, which is
exactly what the encrypted `recoveryCodes` field is for.

---

## 7. Distribution and integrity (public project)

Three separated layers. The public repo is layer 1 only.

### 7.1 App code

Public git repository. Maintainers push, users pull or fork. One direction.
Contains no user data.

### 7.2 App onto a device

- **Single file.** Download `kunji.html` from a tagged Release, open locally, Add
  to Home Screen. Updates are a manual re-download when the user chooses.
- **Self-hosted PWA.** Fork the repo, deploy your own GitHub Pages instance,
  install from your own URL.
- **Official Pages deploy.** Provided for convenience, optional.

### 7.3 Vault sync between a user's own devices

App is transport-agnostic. It reads/writes one encrypted blob and offers
import/export (file and QR). Documented options: nothing (single device),
Syncthing (recommended, no cloud), a private git repo separate from the public
one, an existing consumer file-sync (encrypted blob, user's call), or manual
QR/file transfer.

**Conflict handling.** The blob carries `revision`, `lastWriter`, and per-entry
`updatedAt`. On load, if Kunji sees a sync-conflict sibling file or an import
with divergent history, it merges per entry: additions kept, deletions
tombstoned, field-level last-writer-wins, and shows a one-screen summary. Edits
are small and infrequent, so conflicts are rare.

### 7.4 Integrity

- **Reproducible build.** The release file is a documented concatenation of
  source parts. Anyone can rebuild and byte-compare.
- **Published SHA-256** per release, plus a signed git tag.
- **Self-imposed CSP.** The offline single-file build carries
  `Content-Security-Policy: default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'`
  so the running app provably makes no network request (no `connect-src`, so
  fetch/XHR/WebSocket are blocked outright). The installable PWA build adds only
  `worker-src 'self'` so its service worker can serve the cached shell; it still
  omits `connect-src`, so the app logic still cannot reach the network.
- **CI invariant checks.** Grep gate rejects `fetch(`, `XMLHttpRequest`,
  `WebSocket`, `navigator.sendBeacon`, external `src`/`href`, and any import from
  a URL. Test-vector gate rejects any change to `v1` outputs.
- No analytics, no telemetry, stated as a project invariant.

---

## 8. Versioning and compatibility policy

- **Algorithm profiles are immutable.** `v1` = the whole of section 4. Once
  released it never changes.
- **Every entry stores its `profile`.** Derivation always uses that profile's
  frozen path.
- **New profiles are additive.** `v2` (planned: own Argon2id) ships alongside
  `v1`. Migration is explicit and per entry: derive under `v2`, change the
  password at the site, update the stored `profile`. Never automatic, never
  global.
- **App version is independent of profile version.** Any Kunji version derives a
  `v1` entry identically.
- **File `format`/`v` bumps** are for the envelope and data model; they carry a
  migration that never alters how existing entries derive.

---

## 9. Cryptographic implementation policy

- Standard primitives are used exactly to spec and verified against official test
  vectors. We do not design our own algorithms.
- **Web Crypto (`crypto.subtle`) provides** SHA-256, SHA-512, HKDF, PBKDF2,
  AES-256-GCM, HMAC. This is a platform API, not a dependency. It is the primary
  crypto surface for v1.
- **We hand-write only Argon2id**, for the future `v2` profile, from RFC 9106,
  gated on passing every RFC test vector in CI. Until then, `v1` PBKDF2 is the
  shipping KDF.
- No third-party libraries, no bundler, no build step beyond file concatenation.
- All randomness from `crypto.getRandomValues`.

---

## 10. UI spec

Reference: the approved mockup (`scratchpad/kunji-mockup.html`). X.com styling.

- **Palette.** Background `#000000`. Hairline borders `#2F3336`. Primary text
  `#E7E9EA`. Muted text `#8B98A5` (raised from X's `#71767B` to clear WCAG AA at
  small sizes). One accent blue `#1D9BF0` for focus rings and text buttons. One
  green `#00BA7C` for the KCV dot. Primary action is a white pill with near-black
  text, like X's "Next".
- **Type.** System stack: `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
  Helvetica, Arial, sans-serif`. Title 23px/800, body 15px, helper 13px. The
  generated password is `ui-monospace` at 19px, grouped in fours.
- **Layout.** Single centred card, `min(400px, 100%)`, 16px radius, 32px padding,
  hairline border, no shadow. Fields: floating labels, 16px gap within the group,
  24px between sections, one hairline divider before the result.
- **Fields.** Master passphrase (with Show/Hide text button and KCV dot below),
  Site or app, then a two-column row of Length and Rules.
- **Result.** Label, Copy text button, monospace value with a Reveal toggle that
  re-hides after `revealSeconds`, and an entropy line. Entropy is estimated as
  `floor(length * log2(charsetSize))` bits ("N bits, unique to this site and
  counter K").
- **Hygiene.** Master field cleared after generate; clipboard cleared after
  `clipboardClearSeconds`; no secret written to `localStorage` or a service
  worker cache; `autocomplete="off"` and `spellcheck="false"` on secret fields.
- **Accessibility.** A larger-text pass for non-technical users; visible focus
  states; labels tied with `for`/`id`; hit targets >= 44px on touch.
- **Offline.** Service worker caches only the app shell (which is the whole app),
  never vault data. First load works offline thereafter.

---

## 11. Platform support

| Platform | Delivery | Notes |
|---|---|---|
| Windows | Edge/Chrome "Install", or open file | Parents' devices |
| macOS | Chrome/Safari install, or open file | |
| Android phones + tablets | Chrome "Add to Home screen" | Syncthing available |
| iOS / iPadOS | Safari "Add to Home Screen" | No Syncthing on iOS: use QR/file import, or a private git client |
| Linux | Chromium install, or open file | |

WebAuthn/passkey biometric unlock (gating a locally stored wrap of `vaultKey`) is
a later enhancement where the platform supports the PRF extension. Not in v1.

---

## 12. Build phases

1. **v1 core, single file.** Derivation pipeline (section 4) with committed test
   vectors, PBKDF2 KDF, KCV, X-style UI, copy with auto-clear. No persistence
   beyond in-memory. Ships as one auditable `kunji.html`.
2. **Vault.** `kunji-data.json` read/write, AES-256-GCM, entry list, entry
   editor, the account picker, SSO entries, decoy section, import/export as
   encrypted file.
3. **Portability.** QR export/import, sync-conflict detection and per-entry
   merge, service worker for offline install, PWA manifest.
4. **Distribution.** Reproducible build script, release checksums, signed tags,
   CI invariant + test-vector gates, docs for Syncthing / private git / manual.
5. **Later, optional.** Own Argon2id as profile `v2`; WebAuthn biometric unlock;
   live TOTP generation from stored secrets.

---

## 13. Open decisions

- **v1 KDF cost.** PBKDF2-SHA512 at 600000 iterations is the starting figure.
  Confirm against real timing on the slowest target device (an older Android
  tablet) and adjust before freezing v1. Target 0.5..1.5s.
- **`max-symbols` character set.** The listed set includes brackets and
  punctuation some sites reject. Confirm the set before freezing, or add a
  fourth, wider preset.
- **Shared family master.** Decide which specific accounts go in the shared vault
  vs each person's personal vault.
- **`identityHint` default.** Off (nothing stored) vs on (prefill convenience).
  Proposed: off by default, a checkbox to enable per device.
