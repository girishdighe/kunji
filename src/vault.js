import { utf8, bytesToBase64, base64ToBytes, fromUtf8 } from './encoding.js';
import { aesGcmEncrypt, aesGcmDecrypt } from './webcrypto.js';
import { deriveVaultKey, computeKcv, PBKDF2_ITERATIONS, normaliseInput } from './derive.js';

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
  // Both branches are built from named fields only — never `...partial` — so a
  // partial carrying fields for the other type (a stale `via`, or leftover
  // counter/rules/totp/recoveryCodes) cannot bleed onto the entry.
  const common = {
    id: crypto.randomUUID(),
    updatedAt: new Date().toISOString(),
    name: partial.name ?? '',
    site: partial.site ?? '',
    account: partial.account ?? '',
    notes: partial.notes ?? '',
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
  // Only `entries` and `settings` are persisted; any other top-level keys a
  // future format version adds would be dropped on a v1 save-through.
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
  if (!Number.isInteger(env.revision) || env.revision < 0) {
    throw new BadEnvelopeError('missing or invalid revision');
  }
  return env;
}

// Decrypt one slot's ciphertext and validate the plaintext shape. Drops `_pad`
// (Phase 3b length-matching filler) by returning only { entries, settings }.
async function decryptSlot(vaultKey, ivB64, ctB64) {
  let plainBytes;
  try {
    plainBytes = await aesGcmDecrypt(vaultKey, base64ToBytes(ivB64), base64ToBytes(ctB64), VAULT_AAD);
  } catch {
    throw new CorruptVaultError('the file could not be decrypted');
  }
  let plain;
  try {
    plain = JSON.parse(fromUtf8(plainBytes));
  } catch {
    throw new CorruptVaultError('the vault contents could not be read');
  }
  if (!plain || !Array.isArray(plain.entries)
      || typeof plain.settings !== 'object' || plain.settings === null || Array.isArray(plain.settings)) {
    throw new CorruptVaultError('the vault contents are not in the expected shape');
  }
  return { entries: plain.entries, settings: plain.settings };
}

export async function unlockVault(envelope, { masterKey }) {
  if (await computeKcv(masterKey) !== envelope.kcv) {
    throw new WrongPassphraseError('that is not the passphrase for this vault');
  }
  const vaultKey = await deriveVaultKey(masterKey);
  return decryptSlot(vaultKey, envelope.iv, envelope.ct);
}

// Try the real slot first (KCV match), then the decoy slot. Returns the
// decrypted vault plus which slot it came from. `WrongPassphraseError` when the
// passphrase matches neither.
export async function openVault(envelope, { masterKey }) {
  const k = await computeKcv(masterKey);
  const vaultKey = await deriveVaultKey(masterKey);
  if (k === envelope.kcv) {
    return { slot: 'real', ...(await decryptSlot(vaultKey, envelope.iv, envelope.ct)) };
  }
  if (envelope.decoy && k === envelope.decoy.kcv) {
    return { slot: 'decoy', ...(await decryptSlot(vaultKey, envelope.decoy.iv, envelope.decoy.ct)) };
  }
  throw new WrongPassphraseError('that passphrase does not match this vault');
}

// --- Phase 3a: account-picker lookups (pure) ---

// Every entry whose site matches `rawSite` under the shared input normalisation.
// Empty/whitespace `rawSite` -> []. Input order is preserved. Does not mutate.
export function entriesForSite(entries, rawSite) {
  const s = normaliseInput(rawSite || '');
  if (!s) return [];
  return entries.filter((e) => e && typeof e.site === 'string' && normaliseInput(e.site) === s);
}

// For a pick: a non-sso entry resolves to itself; an `sso` entry resolves to the
// underlying entry it points at (a non-sso entry whose normalised site+account
// equal the sso entry's `via`), or null when that entry is not present.
export function resolveEntryForPick(entries, entry) {
  if (!entry) return null;
  if (entry.type !== 'sso') return entry;
  const viaSite = normaliseInput((entry.via && entry.via.site) || '');
  const viaAccount = normaliseInput((entry.via && entry.via.account) || '');
  if (!viaSite) return null;
  return entries.find((e) => e && e.type !== 'sso'
    && typeof e.site === 'string' && typeof e.account === 'string'
    && normaliseInput(e.site) === viaSite && normaliseInput(e.account) === viaAccount) || null;
}

// --- Phase 3b: length-matching filler (pure) ---

// Returns { ...obj, _pad } where `_pad` is a base64 string sized so that
// utf8(JSON.stringify(result)).length === targetBytes exactly. Throws if `obj`
// (with an empty _pad) already serialises to more than targetBytes. base64
// characters are JSON-safe (no escaping), so one _pad char == one output byte.
export function padPlaintextTo(obj, targetBytes) {
  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const base = utf8(JSON.stringify({ ...obj, _pad: '' })).length;
  const need = targetBytes - base;
  if (need < 0) throw new Error(`padPlaintextTo: object is ${-need} bytes over target`);
  let pad = '';
  const r = randomBytes(need);
  for (let i = 0; i < need; i++) pad += B64[r[i] & 63];
  return { ...obj, _pad: pad };
}
