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
