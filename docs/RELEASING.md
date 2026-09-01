# Releasing Kunji

A release is: build → checksum → sign → tag → GitHub Release. `tools/release.mjs`
does the mechanical parts; you run the two publishing commands it prints.

## One-time setup

Kunji uses **SSH signing** — the same key you push with, no GPG.

```sh
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519          # your key
git config commit.gpgsign true
git config tag.gpgsign true
```

Add the **public** key to GitHub as a *Signing Key* (Settings → SSH and GPG keys
→ New SSH key → Key type: **Signing Key**) so tags show "Verified".

Confirm the repo's `allowed_signers` line matches your key:

```sh
ssh-keygen -y -f ~/.ssh/id_ed25519          # prints "ssh-ed25519 AAAA... comment"
grep "$(ssh-keygen -y -f ~/.ssh/id_ed25519 | awk '{print $2}')" allowed_signers
```

The line format is:

```
<your-git-email> namespaces="git,file" ssh-ed25519 <base64> <comment>
```

`namespaces="git,file"` is required — `git` covers `git verify-tag`, `file`
covers `ssh-keygen -Y verify` of the downloaded `kunji.html`.

## Cutting a release

1. `git switch main && git pull` — clean tree, in sync with `origin/main`.
2. `node tools/release.mjs <version>` — e.g. `1.0.0`. It runs `npm run verify`,
   double-builds, checksums, signs, writes `releases/v<version>.txt`, bumps
   `package.json`, and prints a review block.
3. Read the review block. Check the sha256 and commit look right.
4. Run the printed commands, in order:
   - `git commit -m "release: v<version>"`
   - `git tag -s v<version> -m "…"` (the message the script printed, sha256 included)
   - `git push && git push --tags`
   - `gh release create v<version> …` (assets + `--notes-file`)
5. Open the Release page: confirm the tag shows **Verified** and the four assets
   are attached (`kunji.html`, `.sha256`, `.sig`, `releases/v<version>.txt`).
6. If the phase status changed, update the "Status" section of `README.md`.

## If something goes wrong

`tools/release.mjs` writes only into `dist/` (gitignored) and stages
`package.json` + the manifest — it never commits, tags, pushes, or calls `gh`.
Nothing is public until you run the `git push --tags` / `gh release create`
lines. To back out before then: `git restore --staged package.json releases/`,
`git checkout -- package.json`, delete `releases/v<version>.txt`, fix, re-run.

To pull a mistaken tag/release: `git push --delete origin v<version>`,
`git tag -d v<version>`, `gh release delete v<version>`.
