# Security policy

Kunji is a personal open-source project, not an audited commercial product. It
deliberately keeps its attack surface tiny — one offline file, no network, no
dependencies, standard primitives — precisely so that it can be read and checked
by anyone. Please do read it.

## Reporting a vulnerability

**Do not open a public issue, discussion, or PR for anything exploitable.**

Report privately, one of:

- **GitHub → the repo's *Security* tab → *Report a vulnerability*** (private
  advisory). This is preferred.
- If that's unavailable, email the maintainer. The address is on the maintainer's
  GitHub profile and in the git commit history.

Please include: what you found, how to reproduce it, the impact you think it has,
and any suggested fix. You'll get an acknowledgement within a few days. Once a
fix is out, you're credited in the advisory and `CHANGELOG.md` unless you'd
rather not be.

There is no bug bounty.

## Supported versions

Kunji is pre-1.0 and ships from a single line of development. Fixes land on
`main` and in the next tagged release. Older release files are not patched in
place — a released `kunji.html` is immutable by design; you upgrade by
downloading (and verifying) a newer one.

## Threat model

### What Kunji is designed to resist

- **Server compromise / data breach.** There is no server and no stored password
  database. Nothing to breach.
- **Network interception / exfiltration.** The page makes no requests. The CSP is
  `default-src 'none'`; `npm run check` fails the build on any networking code or
  external resource. A malicious network sees nothing.
- **Theft of the vault file.** `kunji-data.json` is one AES-256-GCM blob. It
  contains entry parameters, notes, TOTP secrets and recovery codes — **not** any
  derived password, and **not** the master passphrase. Without the passphrase (or
  an enrolled per-device passkey), an attacker with the file must brute-force a
  PBKDF2-HMAC-SHA512 hash at 600 000 iterations.
- **Coercion to unlock.** The optional [decoy vault](docs/USAGE.md#the-decoy-vault)
  gives a plausible alternative vault behind a second passphrase. The file's size
  and structure don't reveal whether a decoy exists.
- **Ciphertext-size side channel.** Both vault slots are padded to a fixed block
  multiple before encryption, so a vault with a decoy looks the same size as one
  without.
- **Modulo bias in generated passwords.** The generator uses rejection sampling;
  every character in the chosen set is equiprobable.
- **Silent derivation drift.** `tests/vectors/v1.json` fails CI if any code
  change would alter an existing `v1` password.
- **Supply-chain tampering of releases.** Each release file is SHA-256-checksummed
  and SSH-signed by the maintainer's key (`allowed_signers`), and independently
  rebuilt by CI which re-checks the signature and hash.

### What Kunji does **not** protect against

- **A compromised device or browser.** Malware, a malicious extension with page
  access, a keylogger, or an evil-maid attack on your OS can capture your
  passphrase or the generated password as you use it. Kunji runs in that
  environment; it cannot defend it.
- **A weak or reused master passphrase.** The whole scheme rests on this one
  secret. A guessable passphrase is guessable; PBKDF2 slows an offline attack on
  the vault, it does not save a bad passphrase.
- **Shoulder-surfing / screen capture / clipboard scrapers** running with your
  privileges. The 25-second clipboard clear is a convenience, not a control
  against local malware.
- **Losing the passphrase.** There is no recovery, by design. See
  [Backup and recovery](docs/USAGE.md#backup-and-recovery).
- **A forensic adversary who already knows Kunji supports decoys.** Decoys give
  *deniability under compulsion*, not protection against someone who has read
  this document and has time and tools.
- **Phishing / a fake "Kunji".** Only use a file you built yourself or downloaded
  from the official Releases page and
  [verified](README.md#verify-what-you-downloaded).
- **TOTP secrets sharing the vault's fate.** If you store a site's 2FA secret in
  the same vault as its password, one cracked vault yields both factors. That's a
  choice you make per entry.

## Cryptographic summary

| Purpose | Construction |
|---|---|
| Master key (profile `v1`) | `PBKDF2-HMAC-SHA512(passphrase, NFKC/trim/lower(identity), 600000)` → 32 bytes |
| Key check value | `HMAC-SHA256(masterKey, "kunji/kcv/v1")[0:4]`, base64 |
| Per-entry seed | `HKDF-SHA256(masterKey, salt="kunji/v1", info="gen\|site\|account\|counter\|rules\|length", 64B)` |
| Vault key | `HKDF-SHA256(masterKey, "kunji/v1", "vault-key", 32)` |
| Vault encryption | `AES-256-GCM` with associated data; per-save random IV |
| Passkey wrap | `AES-256-GCM` under `HKDF-SHA256(webauthnPrfSecret, "kunji/v1", "passkey-wrap", 32)` |
| TOTP | `HMAC-SHA1`, RFC 6238, 30 s / 6 digits |

All via the platform `crypto.subtle`. Primitives are checked against RFC 5869,
RFC 4231, RFC 6238, and McGrew GCM test vectors in `tests/webcrypto.test.mjs`.
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how they compose.
