import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isPasskeySupported } from '../src/webauthn.js';

test('isPasskeySupported returns false (not throws) with no WebAuthn present', async () => {
  // Node has no window / navigator.credentials
  assert.equal(await isPasskeySupported(), false);
});
