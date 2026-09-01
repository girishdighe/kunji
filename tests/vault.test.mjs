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
