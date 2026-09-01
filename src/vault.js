import { utf8, bytesToBase64 } from './encoding.js';

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
