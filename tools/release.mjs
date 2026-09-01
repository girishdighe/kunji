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
