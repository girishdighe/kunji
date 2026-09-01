# Kunji

**A password tool that stores nothing and sends nothing.**

Kunji (Hindi/Urdu for *key*) turns one passphrase you remember into a different
strong password for every site — recomputed on the spot, every time, with no
database and no network. It is a single HTML file. Open it in any browser, on
any operating system, online or offline, and it works.

- **Deterministic:** `identity + master passphrase + site + account` always
  produces the same password. Lose the file, download it again — your passwords
  are still there because they were never *anywhere*.
- **Optional vault:** if you'd rather not retype site and account names, an
  encrypted `kunji-data.json` file remembers them (and notes, and 2FA secrets).
  It never contains a single generated password.
- **No moving parts:** no accounts, no servers, no browser extension, no cloud.
  The build step is "concatenate some files". You can read every line.

---

## Table of contents

- [Get Kunji](#get-kunji)
- [Verify what you downloaded](#verify-what-you-downloaded)
- [Use it (5-minute version)](#use-it-5-minute-version)
- [Install it as an app](#install-it-as-an-app)
- [Build from source](#build-from-source)
- [How it keeps its promises](#how-it-keeps-its-promises)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

---

## Get Kunji

**Option A — download a release (recommended).**
Go to the [Releases](../../releases) page and download `kunji.html` from the
latest release. Also grab `kunji.html.sha256`, `kunji.html.sig`, and
`allowed_signers` if you want to verify it (see below).

**Option B — build it yourself.** See [Build from source](#build-from-source).
Two lines and you have an identical file.

Either way you end up with one file, `kunji.html`. Double-click it. That's the
whole install.

## Verify what you downloaded

You do not have to do this, but it takes 20 seconds and proves the file you got
is the file the maintainer signed.

You need four files in one folder: `kunji.html`, `kunji.html.sha256`,
`kunji.html.sig`, and `allowed_signers` (all on the release page; the last is
also in this repo).

```sh
# 1. The file matches its published checksum:
sha256sum -c kunji.html.sha256

# 2. The checksum was signed by the maintainer's key:
ssh-keygen -Y verify -f allowed_signers \
  -I "$(awk 'NF && $1!~/^#/ {print $1; exit}' allowed_signers)" \
  -n file -s kunji.html.sig < kunji.html
```

Both commands should print a success line. If either fails, do not use the file.

Cloned the repo instead of downloading? Verify the tag:

```sh
git config gpg.ssh.allowedSignersFile "$PWD/allowed_signers"
git verify-tag v1.0.0
```

Every published tag is also rebuilt from scratch by CI, which re-checks the
signature and confirms the rebuilt file hashes to the value recorded in
`releases/`. See [`docs/RELEASING.md`](docs/RELEASING.md) for how releases are cut.

## Use it (5-minute version)

Open `kunji.html`. You are on the **Generate** tab.

1. **Identity** — a fixed string that is *yours*, e.g. your email address. Use the
   same one forever. It is a namespace, not a secret.
2. **Master passphrase** — the one strong thing you memorise. Never stored,
   cleared from the field the moment you generate.
3. **Site or app** — where the password is for, e.g. `github.com`.
4. **Account** — which login on that site, e.g. `alice` (leave blank if you only
   have one).
5. **Length / Rules** — how long, and which character classes. Defaults are fine.
6. Press **Generate**. Your password appears. Press **Copy** — the clipboard is
   wiped automatically after 25 seconds.

The little dot under the passphrase is the **key check value**: once identity and
passphrase are filled it turns green and shows a short code. That code depends
only on your identity + passphrase, so if it looks different from what you
usually see, you have a typo — stop before you generate a wrong password.

To change a password in the future, bump the **counter** (in the vault entry, or
by adding a number to the account) — same inputs, new output.

The full walkthrough — vault, decoy vault, cross-device sync, QR transfer, live
2FA codes, passkey unlock — is in **[docs/USAGE.md](docs/USAGE.md)**.

## Install it as an app

`node tools/build.mjs` also produces `dist/pwa/` — the same tool packaged as an
installable Progressive Web App (service worker, offline cache, home-screen
icon). Serve that folder over HTTPS (or `localhost`) once, open it, and use your
browser's **Install** / **Add to Home Screen**. After the first load it runs
fully offline. Its Content-Security-Policy still forbids the page from making any
network request.

`node tools/build.mjs --no-pwa` skips this and writes only the single file.

## Build from source

You need **Node.js 20 or newer**. There are no dependencies to install.

```sh
git clone https://github.com/girishdighe/kunji.git
cd kunji
node tools/build.mjs        # writes dist/kunji.html (+ dist/pwa/)
```

Run the checks:

```sh
npm test            # unit tests, crypto known-answer tests, frozen vectors
npm run check       # scans for any network call or external resource
npm run verify      # all of the above, plus a build
```

The build is deterministic: the same source always produces a byte-identical
`dist/kunji.html`. See **[docs/BUILD.md](docs/BUILD.md)** for the repo layout and
how the single file is assembled, and **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**
for how the pieces fit together.

## How it keeps its promises

- **"Sends nothing."** The page's Content-Security-Policy is `default-src 'none'`
  — no scripts, styles, images, fonts, or connections from anywhere but the file
  itself. `npm run check` fails the build if the source so much as contains the
  string `fetch(`, `XMLHttpRequest`, `http://`, `<script src=`, or `<link>`.
- **"Stores nothing."** No `localStorage`, no cookies, no IndexedDB for secrets.
  The master passphrase is cleared from memory paths after each generate. The
  only thing written to disk is the vault file *you* explicitly save, and it is
  ciphertext.
- **The v1 output is frozen.** `tests/vectors/v1.json` pins the generator's
  output. Any change that would alter an existing password fails the test suite.
  Improvements ship as a new profile id — your `v1` passwords never move.
- **Standard crypto only.** PBKDF2-SHA512, HKDF-SHA256, HMAC-SHA256,
  AES-256-GCM, all via the browser's built-in `crypto.subtle`. No third-party
  crypto code. Known-answer tests check the primitives against the RFC vectors.

## Documentation

| Document | What's in it |
|---|---|
| [docs/USAGE.md](docs/USAGE.md) | Complete user guide: every field, the vault, decoy vault, sync, QR, TOTP, passkeys, backup, FAQ |
| [docs/BUILD.md](docs/BUILD.md) | Building, testing, repo layout, the no-network invariants |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Single-file design, module order, crypto profile, the PWA build |
| [docs/sync.md](docs/sync.md) | Moving a vault between devices in detail |
| [docs/RELEASING.md](docs/RELEASING.md) | Cutting a signed release |
| [docs/specs/](docs/specs/) | Design documents, one per feature |
| [docs/plans/](docs/plans/) | Implementation plans |
| [SECURITY.md](SECURITY.md) | Threat model and how to report a vulnerability |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to propose and land a change |
| [CHANGELOG.md](CHANGELOG.md) | What changed between versions |

## Contributing

Bug reports, questions, and pull requests are welcome. Kunji has hard rules — it
stays one offline file with no network and no external resources — so please read
**[CONTRIBUTING.md](CONTRIBUTING.md)** before opening a PR. In short: discuss
non-trivial changes in an issue first, keep `npm run verify` green, and add tests
for anything that touches derivation or crypto.

## Security

Kunji is a personal project, not an audited product. It uses standard primitives
in straightforward ways, and the whole thing is small enough to read in an
afternoon — please do. To report a vulnerability, see **[SECURITY.md](SECURITY.md)**;
do not open a public issue for anything exploitable.

## License

[MIT](LICENSE). Copyright (c) 2026 Girish Dighe and Kunji contributors.
