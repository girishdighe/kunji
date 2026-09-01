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

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  try {
    main(process.argv.slice(2));
  } catch (err) {
    console.error(`release: ${err.message}`);
    process.exit(1);
  }
}
