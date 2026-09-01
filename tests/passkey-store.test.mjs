import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { hasPasskey, loadPasskey, savePasskey, removePasskey } from '../src/passkey-store.js';

// minimal localStorage shim
beforeEach(() => {
  const m = new Map();
  globalThis.localStorage = {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
  };
});

const REC = { v: 1, credentialId: 'Y2lk', prfSalt: 'c2FsdA', iv: 'aXY', ct: 'Y3Q', label: 'this device', createdAt: '2026-09-01T00:00:00Z' };

test('save / has / load / remove, namespaced by kcv', () => {
  assert.equal(hasPasskey('KCV_A'), false);
  savePasskey('KCV_A', REC);
  assert.equal(hasPasskey('KCV_A'), true);
  assert.equal(hasPasskey('KCV_B'), false);
  assert.deepEqual(loadPasskey('KCV_A'), REC);
  removePasskey('KCV_A');
  assert.equal(hasPasskey('KCV_A'), false);
  assert.equal(loadPasskey('KCV_A'), null);
});

test('loadPasskey returns null on corrupt JSON, does not throw', () => {
  localStorage.setItem('kunji.passkey.KCV_C', '{not json');
  assert.equal(loadPasskey('KCV_C'), null);
  assert.equal(hasPasskey('KCV_C'), true); // key exists, value unparseable -> present but unusable
});

test('all functions no-op safely when localStorage throws', () => {
  globalThis.localStorage = {
    getItem() { throw new Error('blocked'); },
    setItem() { throw new Error('blocked'); },
    removeItem() { throw new Error('blocked'); },
  };
  assert.equal(hasPasskey('X'), false);
  assert.equal(loadPasskey('X'), null);
  assert.doesNotThrow(() => savePasskey('X', REC));
  assert.doesNotThrow(() => removePasskey('X'));
});
