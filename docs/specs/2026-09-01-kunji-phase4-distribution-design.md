# Kunji Phase 4 — Distribution & Integrity Design

> Sub-project of the Kunji Phase 4 line in `docs/specs/2026-09-01-kunji-design.md` §12.
> Depends on: Phases 1–3 (all shipped on `main`). Adds no runtime code and does
> not touch `src/` or the build — `dist/kunji.html` stays byte-identical.

## 1. Goal

Make the built `dist/kunji.html` **publicly trustworthy and releasable**: a
downloader can verify the file came from the maintainer and matches a specific
commit; a contributor's change is gated by CI; and the "how do I sync this across
devices" question has a documented answer.

GitHub is the forge: Actions for CI, Releases for the checksummed + signed
artifact, signed tags for provenance.

## 2. Scope

**In scope**

| Deliverable | Purpose |
|---|---|
| `tools/release.mjs` | Local release script: verify → double-build → sha256 → manifest → SSH-sign → version bump → print the tag + `gh release` commands |
| `tests/release.test.mjs` | Unit tests for the script's pure helpers + a full end-to-end run against a temp clone |
| `releases/v<version>.txt` | Tracked per-release manifest (version, date, commit, node, sha256); also the GitHub Release notes body |
| `allowed_signers` | Repo-root file mapping the maintainer's SSH public key to the `git` + `file` namespaces |
| `.github/workflows/ci.yml` | Gates on push / PR / weekly cron |
| `.github/workflows/verify-release.yml` | Rebuild-and-compare + tag-signature check on `v*` tags |
| `docs/RELEASING.md` | The release checklist wrapping `release.mjs`, plus one-time git-signing config |
| `docs/sync.md` | Syncthing / private-git / manual+QR device-sync guide |
| `README.md` edits | Refreshed "Status" / "Build"; new "Verifying a download" and pointers to the two new docs |
| `package.json` | `"version"` becomes meaningful; bumped by `release.mjs` |

**Non-goals**

- GitHub Pages auto-deploy — spec §7.2 calls it "optional, for convenience"; deferred.
- Any signing key held by CI — the release is built, checksummed, signed, and
  tagged on the maintainer's machine. CI only *verifies*.
- Publishing to npm or any package registry; Homebrew / OS package distribution.
- Changing the build. It is already deterministic (pure concatenation + string
  replace, deterministic icon generator, no timestamps, no minification). Phase 4
  *documents and enforces* that; it does not alter it.
- A CHANGELOG format beyond the accumulating `releases/*.txt` manifests.

## 3. Trust model

Three independent checks, any subset of which a downloader can run:

1. **SHA-256** (`kunji.html.sha256`) — the file is intact and is the exact bytes
   named in the release. Protects against corruption and truncation.
2. **SSH artifact signature** (`kunji.html.sig`, verified against `allowed_signers`)
   — the file was signed by the holder of the maintainer's SSH key. This is the
   check that establishes *provenance* and is the reason Phase 4 exists: a bare
   hash on a release page only means "matches what that page says", which is
   circular if the page itself is what you're trusting.
3. **Signed git tag** (`git verify-tag v<version>` against the same
   `allowed_signers`) — for someone cloning rather than downloading: the tagged
   commit is vouched for by the same key, and CI's `verify-release` job has
   independently rebuilt that commit and confirmed the artifact hash.

One SSH key (Ed25519 recommended) covers checks 2 and 3 via the `git` + `file`
namespaces in `allowed_signers`. No second key, no GPG, no keyserver.

### Reproducibility

The claim is: **anyone on Node 24 with a clean checkout of the tagged commit gets
a byte-identical `dist/kunji.html`.** It holds because `tools/build.mjs` is
`readFileSync` of a fixed `JS_ORDER` list + two `String.replace` calls,
`tools/gen-icons.mjs` uses no RNG and fixed PNG filter 0, and `buildPwa()` derives
everything from `sha256(index.html)`. The only external variable is the Node
runtime's behaviour of `node:zlib` (icon deflate) and string handling — hence the
pinned major and the weekly cron that reruns the gates on an unchanged tree to
surface point-release drift.

`dist/pwa/` is **not** part of the release artifact set (the single file is the
release). It is reproducible by the same argument but is not signed or checksummed
in Phase 4.

## 4. Components

### 4.1 `tools/release.mjs`

Node ESM script, no dependencies, run as `node tools/release.mjs <version>`.

**Argument:** `<version>` = `MAJOR.MINOR.PATCH` (no `v` prefix, no pre-release
suffix). Rejected if it fails that shape or is not strictly greater than
`package.json`'s current `version` (semver compare on the three integers).

**Preconditions** — each aborts with exit code 1 and a one-line reason:

- `git status --porcelain` is empty (clean working tree).
- Current branch is `main`.
- `git rev-parse @` equals `git rev-parse @{u}` after a `git fetch` — i.e. `main`
  is in sync with `origin/main` (not ahead, not behind).
- `git config --get gpg.format` is `ssh`.
- `git config --get user.signingkey` is non-empty and the referenced key file exists.
- `ssh-keygen` is on `PATH` and reports a version ≥ 8.2 (`ssh-keygen -Y` support).
- `allowed_signers` exists at repo root and contains a line for the configured
  signing key's public half.

**Steps**

1. **Verify.** Spawn `npm run verify`; abort on non-zero exit. Streams output.
2. **Determinism.** `node tools/build.mjs` once (normal output to `dist/`), record
   `h1 = sha256(dist/kunji.html)`. Re-run `node tools/build.mjs` a second time,
   record `h2`. Abort if `h1 !== h2`.
3. **Checksum.** Write `dist/kunji.html.sha256` containing exactly
   `<h1>  kunji.html\n` (two spaces — `sha256sum -c` format).
4. **Manifest.** Write `releases/v<version>.txt` (tracked path):
   ```
   kunji v<version>
   date:   <new Date().toISOString()>
   commit: <full 40-char git HEAD sha>
   node:   <process.version>
   sha256: <h1>
   ```
   `mkdir -p releases` if needed.
5. **Sign.** `ssh-keygen -Y sign -f <user.signingkey> -n file dist/kunji.html`
   producing `dist/kunji.html.sig`. Then immediately
   `ssh-keygen -Y verify -f allowed_signers -I <signer-identity> -n file
   -s dist/kunji.html.sig < dist/kunji.html` — abort if it does not verify
   (guards against a rotated / wrong `user.signingkey` vs `allowed_signers`).
   `<signer-identity>` is the principal (email) on the matching `allowed_signers`
   line; the script parses it from that file.
6. **Version bump.** Rewrite `package.json` `"version": "<version>"` (preserving
   formatting / trailing newline), and `git add package.json releases/v<version>.txt`.
   No commit.
7. **Print the review block** to stdout:
   ```
   ── release v<version> ────────────────────────────────
   commit  <sha>
   node    <version>
   sha256  <h1>
   assets  dist/kunji.html
           dist/kunji.html.sha256
           dist/kunji.html.sig
           releases/v<version>.txt   (also the release notes)

   Next, run:

     git commit -m "release: v<version>"
     git tag -s v<version> -m "kunji v<version>

   sha256: <h1>"
     git push && git push --tags
     gh release create v<version> \
       dist/kunji.html dist/kunji.html.sha256 dist/kunji.html.sig \
       --title "kunji v<version>" \
       --notes-file releases/v<version>.txt
   ─────────────────────────────────────────────────────
   ```

The script **only** reads, spawns `npm`/`node`/`git`(read-only)/`ssh-keygen`,
writes into `dist/` (gitignored) and `releases/`, and stages `package.json` +
the manifest. It never runs `git commit`, `git tag`, `git push`, or `gh`.

**Pure helpers (unit-tested in isolation):**

- `parseVersion(str) -> [maj, min, patch] | null`
- `compareVersions(a, b) -> -1 | 0 | 1`
- `formatManifest({ version, date, commit, node, sha256 }) -> string`
- `formatSha256Line(hash, filename) -> string`
- `parseSignerIdentity(allowedSignersText, publicKeyLine) -> email | null`

### 4.2 `.github/workflows/ci.yml`

**Triggers:** `push` (branches: `main`), `pull_request`, `schedule`
(`cron: '0 6 * * 1'` — Mondays 06:00 UTC).

**Job `gates`** (`runs-on: ubuntu-latest`):

1. `actions/checkout@v4`
2. `actions/setup-node@v4` with `node-version: '24'` (pin the major; patch floats).
3. `npm test` — the full `node --test --test-concurrency=1` suite (currently 157:
   includes the test-vector gate `tests/vectors.test.mjs` and the crypto
   known-answer tests).
4. `npm run check` — `tools/check-invariants.mjs` over `src/*` + `dist/kunji.html`.
5. **Determinism step:** `node tools/build.mjs`; `H1=$(sha256sum dist/kunji.html)`;
   `rm -rf dist`; `node tools/build.mjs`; `H2=$(sha256sum dist/kunji.html)`;
   `test "$H1" = "$H2"` (compare the hash field only, not the filename column).
6. **Cleanliness step:** `git status --porcelain`; if non-empty, `git diff` and
   `exit 1`. Catches a committed `dist/`, a stale generated fixture
   (`tests/fixtures/qr/*`, `tests/vectors/*`), or an editor artifact.

No dependency cache (there are no dependencies). No matrix. Expected wall time
< 1 minute.

### 4.3 `.github/workflows/verify-release.yml`

**Trigger:** `push` with `tags: ['v*']`.

**Job `verify-tag`** (`runs-on: ubuntu-latest`):

1. `actions/checkout@v4` with `fetch-tags: true`, `ref: ${{ github.ref }}`.
2. **Signature:** `git config gpg.ssh.allowedSignersFile "$GITHUB_WORKSPACE/allowed_signers"`
   then `git verify-tag "${GITHUB_REF_NAME}"`. Fails if the tag is unsigned or
   signed by a key not in `allowed_signers`.
3. `actions/setup-node@v4` (`node-version: '24'`); `npm run verify`.
4. **Manifest match:** read `releases/${GITHUB_REF_NAME}.txt` (present because the
   release commit tracks it); extract the `sha256:` value; compute
   `sha256sum dist/kunji.html` from the fresh build; assert equal. Fail with both
   hashes printed otherwise.
5. (Informational) print the manifest so the run log is a permanent record of
   what that tag built.

This job holds no secrets and creates nothing. It is the independent auditor of
the maintainer's local release.

### 4.4 `allowed_signers`

Repo root, tracked, one line:

```
<maintainer-git-email> namespaces="git,file" <ssh-ed25519-or-rsa> <base64 key> <comment>
```

`namespaces="git,file"` lets the same entry satisfy `git verify-tag` (namespace
`git`) and `ssh-keygen -Y verify -n file` (namespace `file`).

### 4.5 `releases/` directory

Accumulates one `v<version>.txt` per release — a permanent, human-readable ledger
of every shipped build and its provenance data. Small (5 lines each), tracked,
and used verbatim as the GitHub Release notes.

### 4.6 Docs

**`docs/RELEASING.md`** — sections:
1. *One-time setup* — `git config gpg.format ssh`, `git config user.signingkey
   ~/.ssh/<key>`, `git config commit.gpgsign true`, `git config tag.gpgSign true`;
   add the public key to GitHub (Settings → SSH and GPG keys → **New SSH key**,
   type *Signing Key*) for the "Verified" badge; confirm the repo's
   `allowed_signers` line matches.
2. *Cutting a release* — preconditions checklist → `node tools/release.mjs
   <version>` → review the printed block → run the printed commands → open the
   GitHub Release page and confirm the four assets + "Verified" tag → update
   README "Status" line if the phase status changed → done.
3. *If something's wrong* — the script aborted before writing the tag/release, so
   fixing and re-running is safe; nothing is published until you run the printed
   `git push --tags` / `gh release create`.

**`docs/sync.md`** — sections:
1. *What actually syncs* — the single `kunji-data.json` blob; already
   AES-256-GCM encrypted, so the transport never sees plaintext; two devices that
   both edited resolve in-app via **Vault → Merge another copy…** (Phase 3d).
2. *Recommended: Syncthing* — install per device; create one shared folder
   holding `kunji-data.json`; set it **Send & Receive** on every device; note
   that Syncthing's `*.sync-conflict-*` sibling files are exactly what the merge
   screen consumes — open one with "Merge another copy…". **iOS/iPadOS:** no
   Syncthing — use QR transfer or a git client instead.
3. *Private git repo* — a repo **separate from the public one**, containing only
   `kunji-data.json`. `git pull` before editing, `git commit -am … && git push`
   after. Bulletproof, fully manual.
4. *Manual — file or QR* — email / USB the file; or **Show as QR** on one device
   and **Scan QR…** on the other (Phase 3e); large vaults animate across frames.
5. *Whatever you choose* — it only ever moves an encrypted blob; losing the
   channel costs convenience, not data; keep one device's copy as the reference.

**`README.md`** —
- *Status* — rewrite: Phases 1–3 shipped (generator, vault, picker, decoy, PWA,
  sync-merge, QR); releases are tagged, checksummed, and SSH-signed.
- *Build* — unchanged mechanics; add that a tagged release ships `kunji.html` +
  `.sha256` + `.sig`.
- *Verifying a download* (new) — the exact commands:
  ```
  sha256sum -c kunji.html.sha256
  ssh-keygen -Y verify -f allowed_signers -I <maintainer-email> \
             -n file -s kunji.html.sig < kunji.html
  git verify-tag v<version>        # when cloning instead of downloading
  ```
  with a line noting `allowed_signers` is in the repo and the key is also on the
  maintainer's GitHub profile.
- *Releasing* (new, one line) → `docs/RELEASING.md`.
- *Syncing across devices* (new, one line) → `docs/sync.md`.

## 5. Testing

- **`tests/release.test.mjs`**
  - pure helpers: `parseVersion` (valid, `v`-prefixed → null, `1.2` → null,
    `1.2.3-rc1` → null), `compareVersions` (both directions + equal),
    `formatManifest` (exact string), `formatSha256Line` (two-space separator),
    `parseSignerIdentity`.
  - **end-to-end:** in a tmp dir, `git init` a throwaway clone of the repo state,
    generate a throwaway Ed25519 key, write a matching `allowed_signers`, set the
    git signing config, run `release.mjs 9.9.9`, then assert: `dist/kunji.html`,
    `dist/kunji.html.sha256`, `dist/kunji.html.sig`, `releases/v9.9.9.txt` all
    exist; the `.sig` verifies via `ssh-keygen -Y verify`; the `.sha256` line
    matches the file; `package.json` version is `9.9.9`; the script's stdout
    contains the `git tag -s v9.9.9` and `gh release create v9.9.9` lines; exit
    code 0.
  - **precondition failures:** dirty tree, wrong branch, missing
    `user.signingkey`, `allowed_signers` without the key — each asserts exit
    code 1 and the specific message, and asserts **nothing was written** to
    `dist/` / `releases/` / `package.json`.
  - Tests that shell out to `git`/`ssh-keygen` are skipped (not failed) if those
    binaries are unavailable, so the suite still runs in a minimal environment.
    `npm test` on a normal dev/CI machine runs them.
- **Workflows** — validated by their first real runs. `verify-release.yml` gets a
  dry check first: push a `v0.0.1-test` tag on a scratch branch, confirm the job
  passes end to end, delete the tag. Neither workflow is unit-testable locally
  beyond `act`-style tools, which are out of scope.
- **No `src/` or build change** — a test asserting `dist/kunji.html`'s sha256 is
  unchanged from before Phase 4 is part of the first task's checklist (manual,
  recorded in the plan), not an automated test.

## 6. Rollout / task order

1. `tools/release.mjs` + `tests/release.test.mjs`.
2. `allowed_signers` + `docs/RELEASING.md` (incl. the one-time git-signing config).
3. `.github/workflows/ci.yml`.
4. `.github/workflows/verify-release.yml` + create the `releases/` directory
   convention (a `releases/.gitkeep` or the first real manifest).
5. `docs/sync.md`.
6. `README.md` refresh (Status / Build / Verifying / pointers).
7. Cut the real **`v1.0.0`** release as the end-to-end proof — run the checklist,
   confirm CI's `verify-release` job goes green against the pushed tag, confirm
   the four assets and the "Verified" badge on the Release page.

Each task is a single commit. `npm run verify` stays green throughout;
`dist/kunji.html` bytes are unchanged until (and through) the release.

## 7. Open questions

- **GitHub account / repo name** — the actual `owner/repo` and the maintainer's
  git email + SSH signing key are needed for `allowed_signers`, the README
  commands, and `gh`. Placeholder `<maintainer-email>` / `<owner/repo>` in the
  spec; filled in during task 2.
- **First version number** — spec assumes `v1.0.0` (Phases 1–3 complete, v1
  profile frozen). Confirm at release time; `0.x` is the alternative if the
  §13 open decisions (KDF cost, `max-symbols` charset) are considered
  v1-blocking.
