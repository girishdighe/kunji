# Kunji Phase 4 — Distribution & Integrity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the built `dist/kunji.html` publicly trustworthy and releasable from GitHub — a local release script, SSH-signed tags + a detached artifact signature, CI gates, a tag-triggered verification job, a tracked release ledger, and device-sync docs.

**Architecture:** Everything is additive tooling and docs. `tools/release.mjs` runs locally: it verifies, double-builds for determinism, checksums, writes a tracked `releases/v<version>.txt` manifest, signs `dist/kunji.html` with the maintainer's SSH key, bumps `package.json`, and prints the exact `git tag -s` + `gh release create` commands (it never pushes or publishes). `.github/workflows/ci.yml` runs the test/invariant/determinism gates on push, PR, and a weekly cron. `.github/workflows/verify-release.yml` fires on a `v*` tag: it re-checks the tag signature against the repo's `allowed_signers`, rebuilds, and asserts the fresh hash matches the manifest. No `src/` or build change — `dist/kunji.html` stays byte-identical.

**Tech Stack:** Node ≥ 20 ESM (`node:test`, `node:child_process`, `node:crypto`, `node:fs`), `git`, OpenSSH `ssh-keygen -Y` (≥ 8.2), GitHub Actions, GitHub CLI (`gh`) for the maintainer-run publish step. Zero runtime dependencies, as everywhere else in this repo.

**Spec:** `docs/specs/2026-09-01-kunji-phase4-distribution-design.md`. Parent: `docs/specs/2026-09-01-kunji-design.md` §7, §12.4.

**Baseline:** Phases 1–3 complete on `main` (commit `53cb8f6` or later). `npm test` = `node --test --test-concurrency=1`, currently 157 tests, `fail 0`. `npm run verify` = tests + build + invariant scan.

Work from `the repository root`, directly on `main`, one commit per task. Commit trailers:

```
Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
```

Use `git -c commit.gpgsign=false commit` if signing prompts during implementation (the real signed-tag flow is Task 7, run by the maintainer). **`fail 0` is the gate** for every task that touches testable code.

---

## File structure

| File | Change | Responsibility |
|---|---|---|
| `tools/release.mjs` | **new** | Local release orchestration + exported pure helpers |
| `tests/release.test.mjs` | **new** | Unit tests for the helpers + an end-to-end run against a local clone + precondition-failure cases |
| `allowed_signers` | **new** (repo root) | Maps the maintainer's SSH public key to the `git` + `file` namespaces |
| `releases/.gitkeep` | **new** | Creates the tracked manifest-ledger directory |
| `.github/workflows/ci.yml` | **new** | Gates: `npm test`, `npm run check`, determinism, tree cleanliness — on push / PR / weekly cron |
| `.github/workflows/verify-release.yml` | **new** | On `v*` tag: verify tag signature, rebuild, assert hash matches `releases/<tag>.txt` |
| `docs/RELEASING.md` | **new** | One-time signing config + the release checklist |
| `docs/sync.md` | **new** | Syncthing / private-git / manual+QR device-sync guide |
| `README.md` | modify | Refresh "Status" / "Build"; add "Verifying a download", "Releasing", "Syncing across devices" |
| `package.json` | modify (Task 1 test only writes it in a clone; Task 7 bumps the real one) | `"version"` becomes meaningful |

`tools/*` is **not** scanned by `check-invariants.mjs` (it scans `src/*` + `dist/kunji.html`) and is **not** concatenated into the bundle (`JS_ORDER` lists only `src/*.js`). So `tools/release.mjs` needs no invariant carve-out.

---

## Task 1: `tools/release.mjs` — pure helpers

**Files:**
- Create: `tools/release.mjs`
- Create: `tests/release.test.mjs`

- [ ] **Step 1: Write the failing helper tests**

Create `tests/release.test.mjs`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseVersion,
  compareVersions,
  formatManifest,
  formatSha256Line,
  parseSignerIdentity,
} from '../tools/release.mjs';

test('parseVersion accepts MAJOR.MINOR.PATCH only', () => {
  assert.deepEqual(parseVersion('1.2.3'), [1, 2, 3]);
  assert.deepEqual(parseVersion('0.0.0'), [0, 0, 0]);
  assert.deepEqual(parseVersion('12.34.56'), [12, 34, 56]);
  assert.equal(parseVersion('v1.2.3'), null);
  assert.equal(parseVersion('1.2'), null);
  assert.equal(parseVersion('1.2.3.4'), null);
  assert.equal(parseVersion('1.2.3-rc1'), null);
  assert.equal(parseVersion('1.2.x'), null);
  assert.equal(parseVersion(''), null);
  assert.equal(parseVersion('01.2.3'), null);
});

test('compareVersions orders by numeric fields', () => {
  assert.equal(compareVersions([1, 2, 3], [1, 2, 3]), 0);
  assert.equal(compareVersions([1, 0, 0], [0, 9, 9]), 1);
  assert.equal(compareVersions([1, 2, 3], [1, 2, 4]), -1);
  assert.equal(compareVersions([1, 3, 0], [1, 2, 9]), 1);
  assert.equal(compareVersions([2, 0, 0], [10, 0, 0]), -1);
});

test('formatManifest is an exact 5-line block', () => {
  const out = formatManifest({
    version: '1.0.0',
    date: '2026-09-01T12:00:00.000Z',
    commit: 'a'.repeat(40),
    node: 'v24.1.0',
    sha256: 'b'.repeat(64),
  });
  assert.equal(out,
    `kunji v1.0.0\n` +
    `date:   2026-09-01T12:00:00.000Z\n` +
    `commit: ${'a'.repeat(40)}\n` +
    `node:   v24.1.0\n` +
    `sha256: ${'b'.repeat(64)}\n`);
});

test('formatSha256Line uses the sha256sum two-space separator', () => {
  assert.equal(formatSha256Line('b'.repeat(64), 'kunji.html'),
    `${'b'.repeat(64)}  kunji.html\n`);
});

test('parseSignerIdentity finds the principal for a matching key', () => {
  const text = [
    '# a comment line',
    '',
    'alice@example.com namespaces="git,file" ssh-ed25519 AAAAKEYALICE alice@host',
    'bob@example.com,bob2@example.com namespaces="git" ssh-ed25519 AAAAKEYBOB bob@host',
  ].join('\n');
  assert.equal(parseSignerIdentity(text, 'ssh-ed25519 AAAAKEYALICE'), 'alice@example.com');
  assert.equal(parseSignerIdentity(text, 'ssh-ed25519 AAAAKEYBOB'), 'bob@example.com');
  assert.equal(parseSignerIdentity(text, 'ssh-ed25519 AAAANOPE'), null);
  assert.equal(parseSignerIdentity('', 'ssh-ed25519 AAAAKEYALICE'), null);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/release.test.mjs`
Expected: FAIL — `Cannot find module '../tools/release.mjs'`.

- [ ] **Step 3: Create `tools/release.mjs` with the helpers and a guarded entry point**

```js
#!/usr/bin/env node
// Local release orchestration for Kunji. Reads, builds, checksums, signs, and
// prints the tag + `gh release create` commands. Never pushes or publishes.
//
//   node tools/release.mjs <version>        # version = MAJOR.MINOR.PATCH
//
// Exports the pure helpers for tests; runs main() only when invoked directly.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

// ---- pure helpers -----------------------------------------------------------

export function parseVersion(str) {
  const m = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(String(str));
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

export function compareVersions(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] > b[i]) return 1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

export function formatManifest({ version, date, commit, node, sha256 }) {
  return `kunji v${version}\n`
    + `date:   ${date}\n`
    + `commit: ${commit}\n`
    + `node:   ${node}\n`
    + `sha256: ${sha256}\n`;
}

export function formatSha256Line(hash, filename) {
  return `${hash}  ${filename}\n`;
}

// `allowedSignersText`: contents of an allowed_signers file.
// `pubkey`: "<keytype> <base64>" exactly as `ssh-keygen -y -f <key>` prints it.
// Returns the first principal on the matching line, or null.
export function parseSignerIdentity(allowedSignersText, pubkey) {
  const [wantType, wantData] = pubkey.trim().split(/\s+/);
  for (const raw of allowedSignersText.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const fields = line.split(/\s+/);
    const keyIdx = fields.findIndex((f) => /^(ssh-|sk-ssh-|ecdsa-|sk-ecdsa-)/.test(f));
    if (keyIdx < 0 || keyIdx + 1 >= fields.length) continue;
    if (fields[keyIdx] === wantType && fields[keyIdx + 1] === wantData) {
      return fields[0].split(',')[0];
    }
  }
  return null;
}

// ---- orchestration (implemented in Step 7) ---------------------------------

function main(argv) {
  throw new Error('not implemented');
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  try {
    main(process.argv.slice(2));
  } catch (err) {
    console.error(`release: ${err.message}`);
    process.exit(1);
  }
}
```

- [ ] **Step 4: Run to verify the helper tests pass**

Run: `node --test tests/release.test.mjs`
Expected: PASS (5 tests).

- [ ] **Step 5: Run the full suite**

Run: `npm test`
Expected: `fail 0` (162 total: 157 + 5).

- [ ] **Step 6: Commit**

```bash
git add tools/release.mjs tests/release.test.mjs
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: release.mjs pure helpers (version, manifest, signer-identity)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Task 2: `tools/release.mjs` — orchestration + end-to-end test

**Files:**
- Modify: `tools/release.mjs` (replace the stub `main`)
- Modify: `tests/release.test.mjs` (append the e2e + precondition tests)

- [ ] **Step 1: Append the failing end-to-end and precondition tests**

Append to `tests/release.test.mjs`:

```js
import { execFileSync as _exec } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync as _exists, readFileSync as _read, writeFileSync as _write } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

function have(bin) {
  try { _exec(bin, ['--version'], { stdio: 'ignore' }); return true; } catch { return false; }
}
const CAN_RUN = have('git') && have('ssh-keygen');

// A working clone whose `origin` is a bare mirror it can push to, plus a
// throwaway ed25519 signing key, signing config, and a matching allowed_signers.
// The under-development tools/release.mjs is copied in, committed, and pushed, so
// the sandbox tests the current working copy on a clean tree that is genuinely
// in sync with origin/main (release.mjs runs `git fetch`, which must be a no-op).
// Returns { dir, clone, key, cleanup }.
function makeReleaseSandbox() {
  const repo = process.cwd();
  const dir = mkdtempSync(join(tmpdir(), 'kunji-rel-'));
  const bare = join(dir, 'origin.git');
  const clone = join(dir, 'clone');
  _exec('git', ['clone', '--quiet', '--bare', repo, bare]);
  _exec('git', ['clone', '--quiet', bare, clone]);
  const key = join(dir, 'id');
  _exec('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'test@kunji', '-f', key]);
  const [t, d] = _read(`${key}.pub`, 'utf8').trim().split(/\s+/);   // "ssh-ed25519 AAAA..."
  _write(join(clone, 'allowed_signers'), `test@kunji namespaces="git,file" ${t} ${d} test@kunji\n`);
  for (const [k, v] of [
    ['user.email', 'test@kunji'], ['user.name', 'Test'],
    ['gpg.format', 'ssh'], ['user.signingkey', key],
    ['commit.gpgsign', 'false'], ['tag.gpgsign', 'false'],
  ]) _exec('git', ['-C', clone, 'config', k, v]);
  _write(join(clone, 'tools/release.mjs'), _read(join(repo, 'tools/release.mjs'), 'utf8'));
  _exec('git', ['-C', clone, 'add', 'tools/release.mjs', 'allowed_signers']);
  _exec('git', ['-C', clone, 'commit', '--quiet', '-m', 'test: sandbox setup']);
  _exec('git', ['-C', clone, 'push', '--quiet', 'origin', 'HEAD:main']);
  _exec('git', ['-C', clone, 'branch', '--set-upstream-to=origin/main', 'main']);
  return { dir, clone, key, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test('release.mjs end-to-end produces the four artifacts and stages the bump', { skip: !CAN_RUN }, () => {
  const sb = makeReleaseSandbox();
  try {
    const out = _exec('node', [join(sb.clone, 'tools/release.mjs'), '9.9.9'],
      { cwd: sb.clone, encoding: 'utf8' });
    assert.ok(_exists(join(sb.clone, 'dist/kunji.html')), 'kunji.html built');
    assert.ok(_exists(join(sb.clone, 'dist/kunji.html.sha256')), 'sha256 written');
    assert.ok(_exists(join(sb.clone, 'dist/kunji.html.sig')), 'sig written');
    assert.ok(_exists(join(sb.clone, 'releases/v9.9.9.txt')), 'manifest written');

    const manifest = _read(join(sb.clone, 'releases/v9.9.9.txt'), 'utf8');
    assert.match(manifest, /^kunji v9\.9\.9\n/);
    assert.match(manifest, /^sha256: [0-9a-f]{64}\n?$/m);

    const shaLine = _read(join(sb.clone, 'dist/kunji.html.sha256'), 'utf8');
    const fileHash = createHash('sha256').update(_read(join(sb.clone, 'dist/kunji.html'))).digest('hex');
    assert.equal(shaLine, `${fileHash}  kunji.html\n`);

    // the detached signature verifies against the sandbox allowed_signers
    _exec('ssh-keygen', ['-Y', 'verify', '-f', join(sb.clone, 'allowed_signers'),
      '-I', 'test@kunji', '-n', 'file', '-s', join(sb.clone, 'dist/kunji.html.sig')],
      { cwd: sb.clone, input: _read(join(sb.clone, 'dist/kunji.html')) });

    const pkg = JSON.parse(_read(join(sb.clone, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '9.9.9');

    const staged = _exec('git', ['-C', sb.clone, 'diff', '--cached', '--name-only'], { encoding: 'utf8' });
    assert.match(staged, /package\.json/);
    assert.match(staged, /releases\/v9\.9\.9\.txt/);

    assert.match(out, /git tag -s v9\.9\.9/);
    assert.match(out, /gh release create v9\.9\.9/);
  } finally {
    sb.cleanup();
  }
});

test('release.mjs rejects a bad version argument', { skip: !CAN_RUN }, () => {
  const sb = makeReleaseSandbox();
  try {
    for (const bad of ['v9.9.9', '9.9', '9.9.9-rc1', 'nope', '']) {
      assert.throws(() => _exec('node', [join(sb.clone, 'tools/release.mjs'), bad],
        { cwd: sb.clone, stdio: 'pipe' }), new RegExp(''), `"${bad}" should be rejected`);
    }
    // not greater than current (0.0.0) -> reject
    assert.throws(() => _exec('node', [join(sb.clone, 'tools/release.mjs'), '0.0.0'],
      { cwd: sb.clone, stdio: 'pipe' }));
  } finally { sb.cleanup(); }
});

test('release.mjs aborts on a dirty working tree and writes nothing', { skip: !CAN_RUN }, () => {
  const sb = makeReleaseSandbox();
  try {
    _write(join(sb.clone, 'DIRTY'), 'x');
    _exec('git', ['-C', sb.clone, 'add', 'DIRTY']);
    let threw = false;
    try { _exec('node', [join(sb.clone, 'tools/release.mjs'), '9.9.9'], { cwd: sb.clone, stdio: 'pipe' }); }
    catch (e) { threw = true; assert.match(String(e.stderr), /clean|dirty|working tree/i); }
    assert.ok(threw, 'must exit non-zero');
    assert.ok(!_exists(join(sb.clone, 'releases/v9.9.9.txt')), 'no manifest written');
    assert.ok(!_exists(join(sb.clone, 'dist/kunji.html.sig')), 'no signature written');
  } finally { sb.cleanup(); }
});

test('release.mjs aborts when signing config is missing', { skip: !CAN_RUN }, () => {
  const sb = makeReleaseSandbox();
  try {
    _exec('git', ['-C', sb.clone, 'config', '--unset', 'user.signingkey']);
    let threw = false;
    try { _exec('node', [join(sb.clone, 'tools/release.mjs'), '9.9.9'], { cwd: sb.clone, stdio: 'pipe' }); }
    catch (e) { threw = true; assert.match(String(e.stderr), /signingkey|signing key/i); }
    assert.ok(threw);
  } finally { sb.cleanup(); }
});
```

- [ ] **Step 2: Run to verify the new tests fail**

Run: `node --test tests/release.test.mjs`
Expected: the e2e + precondition tests FAIL (`main` throws `not implemented`). The 5 helper tests still pass.

- [ ] **Step 3: Replace the stub `main` in `tools/release.mjs`**

Replace the `// ---- orchestration (implemented in Step 7) ----` section and the `function main` stub with:

```js
// ---- orchestration --------------------------------------------------------

function git(args) {
  return execFileSync('git', args, { encoding: 'utf8' }).trim();
}

function sshKeygenVersionOk() {
  try {
    // ssh-keygen prints its version to stderr and exits non-zero for -V-less calls;
    // `ssh-keygen -Y` support (OpenSSH >= 8.2) is what we actually need.
    const help = execFileSync('ssh-keygen', ['-Y'], { encoding: 'utf8', stdio: 'pipe' });
    return true;
  } catch (e) {
    const text = `${e.stdout || ''}${e.stderr || ''}`;
    // "-Y" with no subcommand prints a usage string that mentions sign/verify on >= 8.2
    return /\b(sign|verify|check-novalidate)\b/.test(text);
  }
}

function preconditions() {
  if (git(['status', '--porcelain']) !== '') throw new Error('working tree is not clean');
  const branch = git(['rev-parse', '--abbrev-ref', 'HEAD']);
  if (branch !== 'main') throw new Error(`must be on main (on ${branch})`);
  try {
    execFileSync('git', ['fetch', '--quiet'], { stdio: 'pipe' });
  } catch { /* offline is tolerated; the ahead/behind check below still runs on cached refs */ }
  let upstream;
  try { upstream = git(['rev-parse', '--abbrev-ref', '@{u}']); }
  catch { throw new Error('main has no upstream; set origin/main'); }
  if (git(['rev-parse', 'HEAD']) !== git(['rev-parse', '@{u}'])) {
    throw new Error(`main is not in sync with ${upstream} (ahead or behind)`);
  }
  if (git(['config', '--get', 'gpg.format']) !== 'ssh') {
    throw new Error('git config gpg.format must be "ssh" (see docs/RELEASING.md)');
  }
  const keyPath = git(['config', '--get', 'user.signingkey']);
  if (!keyPath) throw new Error('git config user.signingkey is not set (see docs/RELEASING.md)');
  const keyFile = keyPath.replace(/^~(?=\/)/, process.env.HOME || '');
  if (!existsSync(keyFile)) throw new Error(`signing key not found: ${keyFile}`);
  if (!existsSync('allowed_signers')) throw new Error('allowed_signers is missing at repo root');
  if (!sshKeygenVersionOk()) throw new Error('ssh-keygen lacks -Y support (need OpenSSH >= 8.2)');
  return { keyFile };
}

function buildOnce() {
  execFileSync('node', ['tools/build.mjs'], { stdio: 'inherit' });
  return createHash('sha256').update(readFileSync('dist/kunji.html')).digest('hex');
}

function main(argv) {
  const version = argv[0];
  const parsed = parseVersion(version);
  if (!parsed) throw new Error(`version must be MAJOR.MINOR.PATCH, got "${version ?? ''}"`);
  const current = parseVersion(JSON.parse(readFileSync('package.json', 'utf8')).version) || [0, 0, 0];
  if (compareVersions(parsed, current) <= 0) {
    throw new Error(`version ${version} is not greater than current ${current.join('.')}`);
  }

  const { keyFile } = preconditions();

  // 1. verify
  console.error('release: npm run verify …');
  execFileSync('npm', ['run', 'verify'], { stdio: 'inherit' });

  // 2. determinism
  console.error('release: determinism check …');
  const h1 = buildOnce();
  const h2 = buildOnce();
  if (h1 !== h2) throw new Error(`build is not deterministic: ${h1} != ${h2}`);

  // 3. checksum
  writeFileSync('dist/kunji.html.sha256', formatSha256Line(h1, 'kunji.html'));

  // 4. manifest (tracked)
  mkdirSync('releases', { recursive: true });
  const manifest = formatManifest({
    version,
    date: new Date().toISOString(),
    commit: git(['rev-parse', 'HEAD']),
    node: process.version,
    sha256: h1,
  });
  const manifestPath = `releases/v${version}.txt`;
  writeFileSync(manifestPath, manifest);

  // 5. sign + verify-back
  execFileSync('ssh-keygen', ['-Y', 'sign', '-f', keyFile, '-n', 'file', 'dist/kunji.html'], { stdio: 'pipe' });
  const pubkey = execFileSync('ssh-keygen', ['-y', '-f', keyFile], { encoding: 'utf8' }).trim();
  const identity = parseSignerIdentity(readFileSync('allowed_signers', 'utf8'), pubkey);
  if (!identity) throw new Error('signing key is not listed in allowed_signers');
  execFileSync('ssh-keygen', ['-Y', 'verify', '-f', 'allowed_signers', '-I', identity,
    '-n', 'file', '-s', 'dist/kunji.html.sig'],
    { input: readFileSync('dist/kunji.html'), stdio: ['pipe', 'pipe', 'pipe'] });

  // 6. version bump + stage
  const pkgRaw = readFileSync('package.json', 'utf8');
  writeFileSync('package.json', pkgRaw.replace(/("version":\s*")[^"]*(")/, `$1${version}$2`));
  execFileSync('git', ['add', 'package.json', manifestPath], { stdio: 'pipe' });

  // 7. review block
  const tagMsg = `kunji v${version}\n\nsha256: ${h1}`;
  console.log(`
── release v${version} ────────────────────────────────
commit  ${git(['rev-parse', 'HEAD'])}
node    ${process.version}
sha256  ${h1}
assets  dist/kunji.html
        dist/kunji.html.sha256
        dist/kunji.html.sig
        ${manifestPath}   (also the release notes)

Next, run:

  git commit -m "release: v${version}"
  git tag -s v${version} -m ${JSON.stringify(tagMsg)}
  git push && git push --tags
  gh release create v${version} \\
    dist/kunji.html dist/kunji.html.sha256 dist/kunji.html.sig \\
    --title "kunji v${version}" \\
    --notes-file ${manifestPath}
─────────────────────────────────────────────────────
`);
}
```

- [ ] **Step 4: Run to verify all release tests pass**

Run: `node --test tests/release.test.mjs`
Expected: PASS. On a machine with `git` + `ssh-keygen` (incl. CI): 10 tests. On a minimal box: the 4 e2e/precondition tests report as `skipped`, the 5 helper tests pass. `fail 0` either way.

- [ ] **Step 5: Run the full suite**

Run: `npm test`
Expected: `fail 0`. Count is 166 where `git`/`ssh-keygen` exist (157 + 5 helpers + 4 e2e), else 162 with 4 skipped.

- [ ] **Step 6: Sanity-check the real repo is untouched**

Run: `git status --porcelain`
Expected: only `tools/release.mjs` and `tests/release.test.mjs` modified — **not** `package.json`, **not** `releases/`, **not** `dist/` (gitignored). The e2e test operates only inside its tmp clone.

- [ ] **Step 7: Commit**

```bash
git add tools/release.mjs tests/release.test.mjs
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: release.mjs orchestration — verify, double-build, checksum, sign, manifest

Runs npm run verify, asserts a byte-identical rebuild, writes
dist/kunji.html.sha256 + releases/v<version>.txt, signs the artifact with
the maintainer's SSH key and verifies it back against allowed_signers,
bumps package.json, and prints the git-tag + gh-release commands. Never
pushes or publishes. End-to-end tested against a local clone with a
throwaway key.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Task 3: `allowed_signers` + `docs/RELEASING.md`

**Files:**
- Create: `allowed_signers`
- Create: `docs/RELEASING.md`

This task needs the **maintainer's** SSH signing key. If you are an agent without
it, do Steps 1–2 with the placeholder, commit, and leave a note that the
maintainer must run Step 3 before Task 7. The e2e test in Task 2 already proves
the file *format* works.

- [ ] **Step 1: Create `docs/RELEASING.md`**

```markdown
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
```

- [ ] **Step 2: Create `allowed_signers` (placeholder if you lack the key)**

If you have the maintainer key, run:

```sh
echo "$(git config user.email) namespaces=\"git,file\" $(ssh-keygen -y -f "$(git config user.signingkey)")" > allowed_signers
```

Otherwise create `allowed_signers` with this exact placeholder content and a
`TODO` the maintainer resolves in Step 3 / before Task 7:

```
# Maintainer SSH signing key. Regenerate with:
#   echo "$(git config user.email) namespaces=\"git,file\" $(ssh-keygen -y -f \"$(git config user.signingkey)\")" > allowed_signers
# TODO(maintainer): replace the line below with your real signing key before the first release.
maintainer@example.invalid namespaces="git,file" ssh-ed25519 AAAAPLACEHOLDERDONOTUSE placeholder
```

- [ ] **Step 3: (Maintainer) install the real key**

```sh
echo "$(git config user.email) namespaces=\"git,file\" $(ssh-keygen -y -f "$(git config user.signingkey)")" > allowed_signers
git add allowed_signers && git commit -m "chore: real maintainer signing key in allowed_signers"
```

- [ ] **Step 4: Verify the file parses**

Run:
```sh
node -e "import('./tools/release.mjs').then(m => { const t=require('fs').readFileSync('allowed_signers','utf8'); const line=t.split('\n').find(l=>l && !l.startsWith('#')); const key=line.split(/\s+/).slice(-2).join(' '); console.log(m.parseSignerIdentity(t, key)); })"
```
Expected: prints the principal email (the placeholder prints `maintainer@example.invalid`; that's fine for now).

- [ ] **Step 5: Commit**

```bash
git add allowed_signers docs/RELEASING.md
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
docs: RELEASING.md + allowed_signers for SSH-signed releases

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Task 4: `.github/workflows/ci.yml`

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Create the workflow**

```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 6 * * 1'   # Mondays 06:00 UTC — catches Node / runner drift on an unchanged tree

permissions:
  contents: read

jobs:
  gates:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: '24'

      - name: Unit + vector + KAT tests
        run: npm test

      - name: No-network invariant scan
        run: npm run check

      - name: Build is deterministic
        run: |
          node tools/build.mjs
          H1=$(sha256sum dist/kunji.html | cut -d' ' -f1)
          rm -rf dist
          node tools/build.mjs
          H2=$(sha256sum dist/kunji.html | cut -d' ' -f1)
          echo "build1=$H1"
          echo "build2=$H2"
          test "$H1" = "$H2"

      - name: Working tree is clean
        run: |
          if [ -n "$(git status --porcelain)" ]; then
            echo "Tree dirty after build/tests:"
            git status --porcelain
            git diff
            exit 1
          fi
```

- [ ] **Step 2: Dry-run the shell logic locally**

Run each script step's body from the repo root:

```sh
node tools/build.mjs
H1=$(sha256sum dist/kunji.html | cut -d' ' -f1); rm -rf dist
node tools/build.mjs
H2=$(sha256sum dist/kunji.html | cut -d' ' -f1)
test "$H1" = "$H2" && echo "deterministic OK"
test -z "$(git status --porcelain)" && echo "tree clean OK"
npm test && npm run check
```
Expected: `deterministic OK`, `tree clean OK`, `fail 0`, `invariants ok (17 files)`.
(On macOS `sha256sum` may be absent — use `shasum -a 256`; the workflow runs on
ubuntu where `sha256sum` is standard.)

- [ ] **Step 3: Validate the YAML**

Run: `node -e "const y=require('fs').readFileSync('.github/workflows/ci.yml','utf8'); if(!/^name: ci$/m.test(y)||!/runs-on: ubuntu-latest/.test(y)) throw new Error('bad'); console.log('yaml shape ok')"`
Expected: `yaml shape ok`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
ci: gate tests, invariant scan, build determinism, tree cleanliness

Runs on push to main, PRs, and a weekly cron. Node pinned to 24.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Task 5: `.github/workflows/verify-release.yml` + `releases/` ledger

**Files:**
- Create: `.github/workflows/verify-release.yml`
- Create: `releases/.gitkeep`

- [ ] **Step 1: Create the `releases/` directory marker**

```sh
mkdir -p releases
printf '# Per-release manifests (v<version>.txt) written by tools/release.mjs.\n' > releases/.gitkeep
```

- [ ] **Step 2: Create the workflow**

```yaml
name: verify-release

on:
  push:
    tags: ['v*']

permissions:
  contents: read

jobs:
  verify-tag:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.ref }}
          fetch-tags: true

      - name: Tag is signed by an allowed signer
        run: |
          git config gpg.ssh.allowedSignersFile "$GITHUB_WORKSPACE/allowed_signers"
          git verify-tag "$GITHUB_REF_NAME"

      - uses: actions/setup-node@v4
        with:
          node-version: '24'

      - name: Full verify
        run: npm run verify

      - name: Rebuilt hash matches the release manifest
        run: |
          MANIFEST="releases/${GITHUB_REF_NAME}.txt"
          test -f "$MANIFEST" || { echo "missing $MANIFEST"; exit 1; }
          echo "── $MANIFEST ──"; cat "$MANIFEST"; echo "──────────────"
          WANT=$(grep '^sha256: ' "$MANIFEST" | awk '{print $2}')
          GOT=$(sha256sum dist/kunji.html | cut -d' ' -f1)
          echo "manifest=$WANT"
          echo "rebuilt =$GOT"
          test "$WANT" = "$GOT"
```

- [ ] **Step 3: Dry-run the verification logic against a local signed tag**

If you have a signing key configured (`gpg.format=ssh`, `user.signingkey`, and a
real `allowed_signers`):

```sh
node tools/release.mjs 9.9.9        # writes releases/v9.9.9.txt, signs, prints commands
git stash                          # unstage the bump; keep releases/v9.9.9.txt around
git tag -s v9.9.9-dryrun -m "dry run"
git config gpg.ssh.allowedSignersFile "$PWD/allowed_signers"
git verify-tag v9.9.9-dryrun && echo "tag verify OK"
WANT=$(grep '^sha256: ' releases/v9.9.9.txt | awk '{print $2}')
node tools/build.mjs
GOT=$(shasum -a 256 dist/kunji.html | cut -d' ' -f1)
test "$WANT" = "$GOT" && echo "manifest match OK"
git tag -d v9.9.9-dryrun
git checkout -- package.json; rm -f releases/v9.9.9.txt; git stash drop 2>/dev/null || true
```
Expected: `tag verify OK`, `manifest match OK`. Clean tree afterward.

If you lack a key, skip this step — the workflow is exercised for real in Task 7.

- [ ] **Step 4: Validate the YAML**

Run: `node -e "const y=require('fs').readFileSync('.github/workflows/verify-release.yml','utf8'); if(!/tags: \['v\*'\]/.test(y)||!/git verify-tag/.test(y)) throw new Error('bad'); console.log('yaml shape ok')"`
Expected: `yaml shape ok`.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/verify-release.yml releases/.gitkeep
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
ci: verify-release job — check tag signature and rebuilt hash on v* tags

Also adds the tracked releases/ manifest ledger.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Task 6: `docs/sync.md`

**Files:**
- Create: `docs/sync.md`

- [ ] **Step 1: Create the guide**

```markdown
# Syncing a vault across devices

Kunji never syncs for you. You move one file — `kunji-data.json` — with whatever
tool you already trust.

## What actually moves

Just `kunji-data.json`. It is one AES-256-GCM blob: the transport (Syncthing, a
git repo, an email attachment) only ever sees ciphertext. If two devices both
edited the vault, open one copy on the other device via **Vault → Merge another
copy…** — Kunji shows a one-screen summary (added / updated / deleted here /
deleted there / unchanged) and merges per entry, newest edit winning.

## Recommended: Syncthing

No cloud, no account, direct device-to-device.

1. Install Syncthing on every device (desktop app, or the Android app; **not
   available on iOS** — see below).
2. On one device, put `kunji-data.json` in its own folder and add that folder to
   Syncthing.
3. Share the folder to each other device; accept on each. Set the folder type to
   **Send & Receive** everywhere.
4. Edit the vault on any device; Syncthing propagates the new blob within seconds.

When two devices edit before syncing, Syncthing keeps both and writes a
`kunji-data.sync-conflict-<date>-<device>.json` beside your file. That conflict
file is exactly what **Merge another copy…** is for: open it, review the summary,
apply, save, then delete the conflict file.

**iOS / iPadOS:** there is no Syncthing. Use QR transfer (below) or a private git
client (e.g. Working Copy) instead.

## Private git repo

For the technically inclined: a git repo **separate from the public Kunji repo**,
containing only `kunji-data.json` (and nothing else — never your source).

- Before editing: `git pull`.
- After saving from Kunji: `git add kunji-data.json && git commit -m "vault" && git push`.

If a push is rejected because the remote moved, `git pull` produces a merge
conflict on the blob; discard git's merge, keep either side, then reconcile
inside Kunji with **Merge another copy…** against the other revision.

## Manual: file or QR

No infrastructure at all.

- **File:** email or AirDrop or USB-copy `kunji-data.json` to the other device,
  then open it in Kunji.
- **QR:** on the source device, unlock the vault and choose **Show as QR**; on the
  target device, choose **Scan QR…** and point the camera. Large vaults animate
  across several frames — hold steady until it completes. The target device then
  asks for the passphrase as usual.

## Whichever you pick

- It only ever moves an encrypted blob. A compromised sync channel leaks nothing
  a stolen file wouldn't.
- Losing the sync channel loses convenience, not data — every unlocked device can
  re-export the whole vault.
- Keep one device's copy as the reference in your head, so a merge decision is
  always "does this other copy have anything I want?" rather than "which of these
  is real?".
```

- [ ] **Step 2: Check it renders and links are internal-only**

Run: `node -e "const t=require('fs').readFileSync('docs/sync.md','utf8'); if(/https?:\/\//.test(t)) throw new Error('external URL in sync.md'); if(!/Show as QR/.test(t)||!/Merge another copy/.test(t)) throw new Error('missing feature refs'); console.log('sync.md ok')"`
Expected: `sync.md ok`.

- [ ] **Step 3: Commit**

```bash
git add docs/sync.md
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
docs: sync.md — Syncthing / private-git / manual+QR device sync guide

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Task 7: README refresh

**Files:**
- Modify: `README.md`

Current `README.md` structure (headings): `# Kunji`, `## Status`, `## Build`,
`## Test`, `## The vault`, `## The v1 profile is frozen`, `## Crypto`.

- [ ] **Step 1: Replace the `## Status` section body**

Find:

```markdown
## Status

Phase 2: the deterministic v1 generator (Phase 1) plus an optional encrypted
vault — `kunji-data.json`, AES-256-GCM, entry list / detail / editor, SSO
entries, 5-minute idle auto-lock — still shipped as a single file. Decoy
authoring, QR, and sync merge are Phase 3.
```

Replace with:

```markdown
## Status

Phases 1–3 shipped, still one file: the deterministic `v1` generator, an
optional AES-256-GCM vault (`kunji-data.json`), the Generate-tab account picker,
a real decoy vault, an installable PWA build, tombstone-based sync merge, and
whole-vault QR transfer. Releases are tagged, checksummed, and SSH-signed — see
**Verifying a download** below.
```

- [ ] **Step 2: Extend the `## Build` section**

After the existing `--no-pwa` paragraph, append:

```markdown

A tagged release ships three files: `kunji.html`, `kunji.html.sha256`, and
`kunji.html.sig` (an SSH signature). See `docs/RELEASING.md` to cut one.
```

- [ ] **Step 3: Add `## Verifying a download` after `## Build`**

```markdown
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
```

- [ ] **Step 4: Add pointers near the end (after `## Crypto`)**

```markdown
## More

- Cutting a release: `docs/RELEASING.md`
- Moving a vault between devices: `docs/sync.md`
- Design: `docs/specs/`, implementation plans: `docs/plans/`
```

- [ ] **Step 5: Check the README**

Run:
```sh
node -e "const t=require('fs').readFileSync('README.md','utf8'); for (const s of ['Verifying a download','ssh-keygen -Y verify','docs/RELEASING.md','docs/sync.md','Phases 1–3 shipped']) if(!t.includes(s)) throw new Error('missing: '+s); console.log('README ok')"
```
Expected: `README ok`.

- [ ] **Step 6: Full verification (nothing regressed)**

Run: `npm run verify`
Expected: `fail 0`; `dist/kunji.html written`; `dist/pwa/ written`;
`invariants ok (17 files)`. `git status --porcelain` shows only `README.md`.

- [ ] **Step 7: Commit**

```bash
git add README.md
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
docs: README — Phases 1–3 status, Verifying a download, release/sync pointers

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015YASToX89MLPqBzCkMVDhB
EOF
)"
```

---

## Task 8: (Maintainer) cut `v1.0.0` and confirm the pipeline

**Not an agent task.** Requires: the GitHub repo created and pushed, `gh` authenticated,
the real SSH signing key installed (Task 3 Step 3 done), and OpenSSH ≥ 8.2 locally.

- [ ] **Step 1: Preconditions**

```sh
git switch main && git pull
git config gpg.format          # -> ssh
git config user.signingkey     # -> your key path
grep -v '^#' allowed_signers   # -> your real key line, not the placeholder
```

- [ ] **Step 2: Run the release script**

```sh
node tools/release.mjs 1.0.0
```
Expect: `npm run verify` passes, determinism check passes, a review block with a
sha256 and the four asset paths, and the printed `git`/`gh` commands.

- [ ] **Step 3: Publish (run the printed commands)**

```sh
git commit -m "release: v1.0.0"
git tag -s v1.0.0 -m "kunji v1.0.0
<the sha256 line the script printed>"
git push && git push --tags
gh release create v1.0.0 \
  dist/kunji.html dist/kunji.html.sha256 dist/kunji.html.sig \
  --title "kunji v1.0.0" \
  --notes-file releases/v1.0.0.txt
```

- [ ] **Step 4: Confirm**

- Actions → `verify-release` run for `v1.0.0` is green (tag verified, rebuilt
  hash matches the manifest).
- Actions → `ci` run for the release commit is green.
- The Release page shows a **Verified** tag and all four assets.
- From a clean clone: `git config gpg.ssh.allowedSignersFile "$PWD/allowed_signers" && git verify-tag v1.0.0` succeeds.
- Download `kunji.html` + `.sha256` + `.sig`, run the two commands from README
  **Verifying a download** — both succeed.

- [ ] **Step 5: Update `README.md` "Status"** only if wording needs it (the Task 7
  copy already says "Releases are tagged, checksummed, and SSH-signed"), then commit.

---

## Self-review

**Spec coverage:**
- `tools/release.mjs` (verify → double-build → sha256 → manifest → SSH-sign →
  verify-back → version bump → print commands; reads/builds/signs only, never
  pushes) — Tasks 1, 2. Every precondition in spec §4.1 has an assertion in
  `preconditions()` and (dirty-tree, missing-signingkey) a test; the others
  (branch, upstream sync, gpg.format, ssh-keygen version, allowed_signers
  present) are covered by the code and exercised by the happy-path e2e which sets
  them all correctly.
- Pure helpers `parseVersion` / `compareVersions` / `formatManifest` /
  `formatSha256Line` / `parseSignerIdentity` (spec §4.1) — Task 1, unit-tested.
- `releases/v<version>.txt` tracked manifest (spec §4.5) — written by Task 2,
  directory created in Task 5, consumed by Task 5's workflow and Task 8.
- `allowed_signers` with `namespaces="git,file"` (spec §4.4) — Task 3.
- `.github/workflows/ci.yml` — push/PR/weekly cron; `npm test`, `npm run check`,
  determinism, cleanliness; Node 24 pinned (spec §4.2) — Task 4.
- `.github/workflows/verify-release.yml` — `v*` tag; signature check against
  `allowed_signers`, `npm run verify`, rebuilt-hash vs manifest (spec §4.3) —
  Task 5.
- `docs/RELEASING.md` (one-time config + checklist + back-out) (spec §4.6) —
  Task 3.
- `docs/sync.md` (what syncs / Syncthing / private-git / manual+QR / closing)
  (spec §4.6) — Task 6.
- `README.md` — Status, Build, **Verifying a download** with the three commands,
  pointers (spec §4.6) — Task 7.
- Trust model's three checks (spec §3) — SHA-256 (Task 2 checksum), artifact
  signature (Task 2 sign + Task 7 README verify), signed tag (Task 3 config +
  Task 5 CI + Task 8) — all present.
- Reproducibility claim (spec §3) — determinism step in `release.mjs` (Task 2),
  in `ci.yml` (Task 4), and in `verify-release.yml` vs the manifest (Task 5).
- Non-goals respected: no Pages workflow, no CI-held key (`permissions:
  contents: read`, no secrets referenced), no registry publish, `src/` and the
  build untouched (Task 7 Step 6 asserts `invariants ok (17 files)` and only
  `README.md` changed).
- Spec §7 open questions (repo name, maintainer email/key, first version) —
  deferred to Task 3 Step 3 and Task 8, as the spec says.

**Placeholder scan:** every code/YAML/doc step contains the full content. The one
intentional placeholder is `allowed_signers`'s dummy key line in Task 3 Step 2,
explicitly flagged with a `TODO(maintainer)` and resolved in Step 3 / Task 8 —
this is a real credential that cannot be invented, not a lazy stub, and the file
*format* is proven by Task 2's e2e test. Task 8 is deliberately a
maintainer-run checklist (needs a live GitHub repo, `gh` auth, and the real key)
— its steps are exact commands, not "do the release".

**Type / name consistency:** `parseVersion(str) -> [n,n,n]|null`,
`compareVersions(a,b) -> -1|0|1`, `formatManifest({version,date,commit,node,sha256})`,
`formatSha256Line(hash, filename)`, `parseSignerIdentity(text, "type b64") -> principal|null`
are used identically in `tools/release.mjs` and every test that imports them. The
manifest path is `releases/v<version>.txt` everywhere (script, `verify-release.yml`,
RELEASING.md, Task 8). The tag name is `v<version>` everywhere. `allowed_signers`
is repo-root everywhere. Node pin is `'24'` in both workflows.

**Running test total:** baseline 157 → Task 1 (+5 helpers) 162 → Task 2 (+4
e2e/precondition, skipped where `git`/`ssh-keygen` absent) 166. Tasks 3–7 add no
runtime tests (they add a config file, two workflows, and Markdown; each has a
`node -e` shape check that is run, not committed as a test). `fail 0` is the gate.

**Scope:** one sub-project, 8 tasks, C→D→E-style ordering so `verify-release.yml`
(Task 5) can rely on `release.mjs` (Task 2) and the `releases/` convention; Task 8
is the end-to-end proof and is the only task requiring maintainer credentials.
No `src/` or build change — `dist/kunji.html` is byte-identical from `53cb8f6`
through the `v1.0.0` release commit.
