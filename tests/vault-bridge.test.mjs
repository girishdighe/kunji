import { test } from 'node:test';
import assert from 'node:assert/strict';
import { vaultBridge } from '../src/vault-bridge.js';

test('bridge is inactive until publish, then active, then inactive after clear', () => {
  vaultBridge.clear();
  assert.equal(vaultBridge.isActive(), false);
  assert.deepEqual(vaultBridge.forSite('x.com'), []);
  vaultBridge.publish([{ site: 'x.com', account: 'a', type: 'password' }]);
  assert.equal(vaultBridge.isActive(), true);
  assert.equal(vaultBridge.forSite('x.com').length, 1);
  vaultBridge.clear();
  assert.equal(vaultBridge.isActive(), false);
  assert.deepEqual(vaultBridge.forSite('x.com'), []);
});

test('publish(null) or publish(non-array) deactivates', () => {
  vaultBridge.publish([{ site: 'x.com', account: 'a', type: 'password' }]);
  vaultBridge.publish(null);
  assert.equal(vaultBridge.isActive(), false);
});

test('bridge stores a copy: mutating the caller array or an entry does not leak', () => {
  const list = [{ site: 'x.com', account: 'a', type: 'password' }];
  vaultBridge.publish(list);
  list.push({ site: 'x.com', account: 'b', type: 'password' });
  list[0].account = 'CHANGED';
  const got = vaultBridge.forSite('x.com');
  assert.equal(got.length, 1);
  assert.equal(got[0].account, 'a');
  vaultBridge.clear();
});

test('forSite normalises like the rest of the app', () => {
  vaultBridge.publish([{ site: 'GitHub.com', account: 'me', type: 'password' }]);
  assert.equal(vaultBridge.forSite('  github.com ').length, 1);
  vaultBridge.clear();
});
