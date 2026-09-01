# Kunji

Offline, in-house password tool. One memorised master passphrase plus a site and
account name produce a unique strong password, recomputed on demand. Nothing is
stored or sent. See `docs/specs/2026-09-01-kunji-design.md` for the design and
`docs/plans/` for implementation plans.

## Status

Phases 1–3 shipped, still one file: the deterministic `v1` generator, an
optional AES-256-GCM vault (`kunji-data.json`), the Generate-tab account picker,
a real decoy vault, an installable PWA build, tombstone-based sync merge, and
whole-vault QR transfer. Releases are tagged, checksummed, and SSH-signed — see
**Verifying a download** below.

## Build

    node tools/build.mjs

Produces `dist/kunji.html`, a single self-contained file. Open it directly in any
modern browser (Chrome, Safari, Firefox, Edge) on any OS, or add it to your home
screen. It makes no network requests.

`node tools/build.mjs` also writes `dist/pwa/` — an installable copy (service
worker + manifest + icons) whose CSP still blocks all network from the page.
`node tools/build.mjs --no-pwa` writes only the single file.

A tagged release ships three files: `kunji.html`, `kunji.html.sha256`, and
`kunji.html.sig` (an SSH signature). See `docs/RELEASING.md` to cut one.

## Verifying a download

The `allowed_signers` file in this repo lists the maintainer's SSH signing key
(also on their GitHub profile). Given `kunji.html`, `kunji.html.sha256`,
`kunji.html.sig`, and a copy of `allowed_signers`:

    sha256sum -c kunji.html.sha256

    ssh-keygen -Y verify -f allowed_signers \
      -I "$(awk 'NF && $1!~/^#/ {print $1; exit}' allowed_signers)" \
      -n file -s kunji.html.sig < kunji.html

If you cloned the repo instead of downloading the file:

    git config gpg.ssh.allowedSignersFile "$PWD/allowed_signers"
    git verify-tag v<version>

Every published tag is also independently rebuilt by CI, which re-checks the
signature and confirms the rebuilt hash matches `releases/v<version>.txt`.

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

The Generate tab shows a "which account?" picker when a site you type matches
one or more vault entries (vault unlocked). A second **decoy** master passphrase
can be set from the unlocked vault; it opens a separate, believable vault, and
the file gives no sign that a real decoy exists.

Two devices with no shared file-sync can move a vault by QR: **Show as QR** on
one, **Scan QR…** on the other. Large vaults animate across several frames.

An entry with a TOTP secret (paste the base32 or an `otpauth://` URI) shows the
live 6-digit 2FA code and a countdown in its detail view.

On the installed app you can register a **passkey** so a device unlocks the vault
with its fingerprint / PIN instead of the master passphrase. The passphrase
always still works; the passkey is per-device and never leaves it.

## The v1 profile is frozen

`tests/vectors/v1.json` locks the derivation output. Any code change that alters a
generated password fails `tests/vectors.test.mjs`. Improvements ship as a new
profile id, never by changing v1.

## Crypto

Standard primitives via the platform `crypto.subtle` (PBKDF2-SHA512, HKDF-SHA256,
HMAC-SHA256). No third-party libraries, no build step beyond file concatenation.

## More

- Cutting a release: `docs/RELEASING.md`
- Moving a vault between devices: `docs/sync.md`
- Design: `docs/specs/`, implementation plans: `docs/plans/`
