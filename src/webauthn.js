import { utf8 } from './encoding.js';

function b(arr) { return new Uint8Array(arr); }
function rand(n) { return crypto.getRandomValues(new Uint8Array(n)); }

// Cheap capability check. Never throws.
export async function isPasskeySupported() {
  try {
    if (typeof window === 'undefined') return false;
    if (location && location.protocol === 'file:') return false;   // WebAuthn needs an origin
    return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
  } catch {
    return false;
  }
}

// Creates a discoverable credential with the PRF extension. Returns { credentialId }.
// Rejects if PRF is not available on this authenticator.
export async function registerPasskey({ rpName = 'Kunji', userName = 'vault' } = {}) {
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: rand(32),
      rp: { name: rpName },                       // rp.id omitted -> current origin
      user: { id: utf8(userName), name: userName, displayName: userName },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
      extensions: { prf: {} },
      timeout: 60000,
    },
  });
  const ext = cred.getClientExtensionResults();
  if (!ext || !ext.prf || ext.prf.enabled !== true) {
    throw new Error('this device does not support the WebAuthn PRF extension');
  }
  return { credentialId: new Uint8Array(cred.rawId) };
}

// Returns a stable 32-byte secret for (credential, salt). Rejects on cancel / failure.
export async function getPasskeySecret(credentialId, salt) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: rand(32),
      allowCredentials: [{ type: 'public-key', id: b(credentialId) }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: b(salt) } } },
      timeout: 60000,
    },
  });
  const ext = assertion.getClientExtensionResults();
  const first = ext && ext.prf && ext.prf.results && ext.prf.results.first;
  if (!first) throw new Error('PRF result missing from the assertion');
  return new Uint8Array(first);
}
