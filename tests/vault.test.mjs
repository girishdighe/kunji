import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  BadEnvelopeError, WrongPassphraseError, CorruptVaultError,
  VAULT_FORMAT, VAULT_V, VAULT_AAD,
  randomBytes, newDecoyBytes,
} from '../src/vault.js';
import { base64ToBytes, fromUtf8 } from '../src/encoding.js';

test('typed errors have distinct names and are Error subclasses', () => {
  for (const E of [BadEnvelopeError, WrongPassphraseError, CorruptVaultError]) {
    const e = new E('x');
    assert.ok(e instanceof Error);
    assert.equal(e.message, 'x');
  }
  assert.equal(new BadEnvelopeError().name, 'BadEnvelopeError');
  assert.equal(new WrongPassphraseError().name, 'WrongPassphraseError');
  assert.equal(new CorruptVaultError().name, 'CorruptVaultError');
});

test('envelope constants are the frozen values', () => {
  assert.equal(VAULT_FORMAT, 'kunji-data');
  assert.equal(VAULT_V, 1);
  assert.equal(fromUtf8(VAULT_AAD), 'kunji-vault-v1');
});

test('randomBytes returns n fresh bytes', () => {
  const a = randomBytes(16);
  const b = randomBytes(16);
  assert.equal(a.length, 16);
  assert.notEqual(
    Buffer.from(a).toString('hex'),
    Buffer.from(b).toString('hex'),
    'two calls should almost never collide',
  );
});

test('newDecoyBytes(ctLen) has 4-byte kcv, 12-byte iv, ctLen-byte ct, all base64', () => {
  const d = newDecoyBytes(320);
  assert.equal(base64ToBytes(d.kcv).length, 4);
  assert.equal(base64ToBytes(d.iv).length, 12);
  assert.equal(base64ToBytes(d.ct).length, 320);
  const d2 = newDecoyBytes(320);
  assert.notEqual(d.ct, d2.ct, 'decoy ct is random per call');
});

import {
  createVault, makeEntry, addEntry, updateEntry, removeEntry,
} from '../src/vault.js';

test('createVault is empty with the default settings', () => {
  const v = createVault();
  assert.deepEqual(v.entries, []);
  assert.equal(v.settings.autoLockMinutes, 5);
  assert.equal(v.settings.clipboardClearSeconds, 25);
  assert.equal(v.settings.revealSeconds, 20);
  assert.equal(v.settings.defaultRules, 'standard');
  assert.equal(v.settings.defaultLength, 20);
});

test('makeEntry: password defaults', () => {
  const e = makeEntry({ name: 'GitHub', site: 'github.com', account: 'me' });
  assert.equal(e.type, 'password');
  assert.equal(e.profile, 'v1');
  assert.equal(e.counter, 1);
  assert.equal(e.length, 20);
  assert.equal(e.rules, 'standard');
  assert.equal(e.totp, null);
  assert.deepEqual(e.recoveryCodes, []);
  assert.match(e.id, /^[0-9a-f-]{36}$/);
  assert.ok(e.updatedAt);
});

test('makeEntry: sso shape, no derivation fields', () => {
  const e = makeEntry({ type: 'sso', name: 'News', site: 'news.example.com', account: 'me', via: { site: 'google.com', account: 'me' } });
  assert.equal(e.type, 'sso');
  assert.deepEqual(e.via, { site: 'google.com', account: 'me' });
  assert.equal(e.counter, undefined);
  assert.equal(e.rules, undefined);
});

test('makeEntry: caller cannot override id via partial', () => {
  const e = makeEntry({ id: 'attacker', name: 'x' });
  assert.notEqual(e.id, 'attacker');
});

test('addEntry appends a new entry without mutating the input', () => {
  const v0 = createVault();
  const v1 = addEntry(v0, { name: 'A', site: 's', account: 'a' });
  assert.equal(v0.entries.length, 0);
  assert.equal(v1.entries.length, 1);
  assert.equal(v1.entries[0].name, 'A');
});

test('updateEntry patches by id, bumps updatedAt, keeps id', async () => {
  let v = addEntry(createVault(), { name: 'A', site: 's', account: 'a' });
  const id = v.entries[0].id;
  const before = v.entries[0].updatedAt;
  await new Promise((r) => setTimeout(r, 2));
  v = updateEntry(v, id, { name: 'A2', id: 'nope' });
  assert.equal(v.entries[0].name, 'A2');
  assert.equal(v.entries[0].id, id);
  assert.notEqual(v.entries[0].updatedAt, before);
});

test('removeEntry drops by id', () => {
  let v = addEntry(createVault(), { name: 'A', site: 's', account: 'a' });
  const id = v.entries[0].id;
  v = removeEntry(v, id);
  assert.equal(v.entries.length, 0);
});
