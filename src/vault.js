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
