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

import { execFileSync as _exec } from 'node:child_process';
import { mkdtempSync, realpathSync, rmSync, existsSync as _exists, readFileSync as _read, writeFileSync as _write } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

function have(bin) {
  // A non-zero exit still proves the binary exists (macOS `ssh-keygen --version`
  // is an "illegal option"); only a spawn failure (ENOENT) means it is absent.
  try { _exec(bin, ['--version'], { stdio: 'ignore' }); return true; }
  catch (e) { return e && e.code !== 'ENOENT'; }
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
  // realpath: on macOS os.tmpdir() lives under /var -> /private/var; Node
  // realpaths an ESM entry point, so release.mjs's `import.meta.url` guard would
  // not match process.argv[1] and main() would never run.
  const dir = realpathSync(mkdtempSync(join(tmpdir(), 'kunji-rel-')));
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
