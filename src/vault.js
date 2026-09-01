import { utf8, bytesToBase64, base64ToBytes, fromUtf8 } from './encoding.js';
import { aesGcmEncrypt, aesGcmDecrypt } from './webcrypto.js';
import { deriveVaultKey, computeKcv, PBKDF2_ITERATIONS } from './derive.js';

export const VAULT_FORMAT = 'kunji-data';
export const VAULT_V = 1;
export const VAULT_AAD = utf8('kunji-vault-v1');

export class BadEnvelopeError extends Error {
  constructor(msg) { super(msg); this.name = 'BadEnvelopeError'; }
}
export class WrongPassphraseError extends Error {
  constructor(msg) { super(msg); this.name = 'WrongPassphraseError'; }
}
export class CorruptVaultError extends Error {
  constructor(msg) { super(msg); this.name = 'CorruptVaultError'; }
}

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

// Until real decoys ship (Phase 3) the decoy slot is random bytes. `ctLen` is
// passed the real ciphertext length so the decoy blob matches the real vault's
// size and the file leaks nothing about whether a decoy exists.
export function newDecoyBytes(ctLen) {
  return {
    kcv: bytesToBase64(randomBytes(4)),
    iv: bytesToBase64(randomBytes(12)),
    ct: bytesToBase64(randomBytes(ctLen)),
  };
}

export function createVault() {
  return {
    entries: [],
    settings: {
      clipboardClearSeconds: 25,
      revealSeconds: 20,
      defaultRules: 'standard',
      defaultLength: 20,
      autoLockMinutes: 5,
    },
  };
}

export function makeEntry(partial) {
  const now = new Date().toISOString();
  const common = {
    name: '', site: '', account: '', notes: '',
    ...partial,
    id: crypto.randomUUID(),
    updatedAt: now,
  };
  if (partial.type === 'sso') {
    return {
      ...common,
      type: 'sso',
      via: partial.via ? { site: partial.via.site ?? '', account: partial.via.account ?? '' } : { site: '', account: '' },
    };
  }
  return {
    ...common,
    type: 'password',
    profile: 'v1',
    counter: partial.counter ?? 1,
    length: partial.length ?? 20,
    rules: partial.rules ?? 'standard',
    totp: partial.totp ?? null,
    recoveryCodes: partial.recoveryCodes ?? [],
  };
}

export function addEntry(vault, partial) {
  return { ...vault, entries: [...vault.entries, makeEntry(partial)] };
}

export function updateEntry(vault, id, patch) {
  return {
    ...vault,
    entries: vault.entries.map((e) =>
      e.id === id ? { ...e, ...patch, id: e.id, updatedAt: new Date().toISOString() } : e,
    ),
  };
}

export function removeEntry(vault, id) {
  return { ...vault, entries: vault.entries.filter((e) => e.id !== id) };
}

export async function encodeEnvelope(vault, { masterKey, identityHint = null, prevRevision = 0, writerId }) {
  const plainBytes = utf8(JSON.stringify({ entries: vault.entries, settings: vault.settings }));
  const vaultKey = await deriveVaultKey(masterKey);
  const iv = randomBytes(12);
  const ct = await aesGcmEncrypt(vaultKey, iv, plainBytes, VAULT_AAD);
  const envelope = {
    format: VAULT_FORMAT,
    v: VAULT_V,
    kdf: `pbkdf2-sha512-${PBKDF2_ITERATIONS}`,
    identityHint: identityHint || null,
    kcv: await computeKcv(masterKey),
    iv: bytesToBase64(iv),
    ct: bytesToBase64(ct),
    decoy: newDecoyBytes(ct.length),
    revision: prevRevision + 1,
    lastWriter: writerId,
    updatedAt: new Date().toISOString(),
  };
  return JSON.stringify(envelope, null, 2) + '\n';
}

export function parseEnvelope(text) {
  let env;
  try {
    env = JSON.parse(text);
  } catch {
    throw new BadEnvelopeError('not valid JSON');
  }
  if (!env || typeof env !== 'object') throw new BadEnvelopeError('not an object');
  if (env.format !== VAULT_FORMAT) throw new BadEnvelopeError('not a Kunji vault file');
  if (env.v !== VAULT_V) throw new BadEnvelopeError(`unsupported version ${env.v}`);
  for (const k of ['kcv', 'iv', 'ct']) {
    if (typeof env[k] !== 'string') throw new BadEnvelopeError(`missing ${k}`);
  }
  const d = env.decoy;
  if (!d || typeof d.kcv !== 'string' || typeof d.iv !== 'string' || typeof d.ct !== 'string') {
    throw new BadEnvelopeError('missing decoy section');
  }
  return env;
}

export async function unlockVault(envelope, { masterKey }) {
  if (await computeKcv(masterKey) !== envelope.kcv) {
    throw new WrongPassphraseError('that is not the passphrase for this vault');
  }
  const vaultKey = await deriveVaultKey(masterKey);
  let plainBytes;
  try {
    plainBytes = await aesGcmDecrypt(
      vaultKey, base64ToBytes(envelope.iv), base64ToBytes(envelope.ct), VAULT_AAD,
    );
  } catch {
    throw new CorruptVaultError('the file could not be decrypted');
  }
  let plain;
  try {
    plain = JSON.parse(fromUtf8(plainBytes));
  } catch {
    throw new CorruptVaultError('the vault contents could not be read');
  }
  if (!plain || !Array.isArray(plain.entries) || typeof plain.settings !== 'object') {
    throw new CorruptVaultError('the vault contents are not in the expected shape');
  }
  return { entries: plain.entries, settings: plain.settings };
}
