import { utf8, bytesToBase64, base64ToBytes, fromUtf8 } from './encoding.js';
import { aesGcmEncrypt, aesGcmDecrypt } from './webcrypto.js';
import { deriveVaultKey, computeKcv, PBKDF2_ITERATIONS, normaliseInput } from './derive.js';

export const VAULT_FORMAT = 'kunji-data';
export const VAULT_V = 1;
export const VAULT_AAD = utf8('kunji-vault-v1');

// Both slot plaintexts are padded to a multiple of this before encryption, so
// the real and decoy ciphertexts are the same (quantised) length and a duress
// edit of the decoy has room to grow. ~2 KB fits roughly a dozen entries per
// block, so a sparse real vault still leaves a believable decoy room to change.
export const PAD_BLOCK = 2048;

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

// Phase 3d: a delete is a tombstone kept in `entries[]` forever, so it survives
// a later merge with a device that still has the entry.
export function removeEntry(vault, id) {
  const now = new Date().toISOString();
  return {
    ...vault,
    entries: vault.entries.map((e) => (e.id === id ? { id, deleted: true, updatedAt: now } : e)),
  };
}

export function visibleEntries(vault) {
  return vault.entries.filter((e) => e && !e.deleted);
}

export async function encodeEnvelope(vault, { masterKey, identityHint = null, prevRevision = 0, writerId, decoy = null }) {
  // Only `entries` and `settings` are persisted per slot; other top-level keys
  // (e.g. a future format's) would be dropped on a v1 save-through. When a decoy
  // is present both plaintexts are space-padded (see padPlaintextTo) so the two
  // ciphertexts are the same length.
  const realObj = { entries: vault.entries, settings: vault.settings };
  let realBytes = utf8(JSON.stringify(realObj));

  let decoySection = null;
  if (decoy) {
    const decoyObj = { entries: decoy.vault.entries, settings: decoy.vault.settings };
    let decoyBytes = utf8(JSON.stringify(decoyObj));
    // Round both slots up to the next PAD_BLOCK boundary above the larger, so a
    // later duress edit of the decoy (which can only re-use the real ct's length)
    // has headroom, and the on-disk size is quantised rather than revealing the
    // exact vault size.
    const target = (Math.floor(Math.max(realBytes.length, decoyBytes.length) / PAD_BLOCK) + 1) * PAD_BLOCK;
    realBytes = utf8(padPlaintextTo(realObj, target));
    decoyBytes = utf8(padPlaintextTo(decoyObj, target));
    const dKey = await deriveVaultKey(decoy.masterKey);
    const dIv = randomBytes(12);
    const dCt = await aesGcmEncrypt(dKey, dIv, decoyBytes, VAULT_AAD);
    decoySection = { kcv: await computeKcv(decoy.masterKey), iv: bytesToBase64(dIv), ct: bytesToBase64(dCt) };
  }

  const vaultKey = await deriveVaultKey(masterKey);
  const iv = randomBytes(12);
  const ct = await aesGcmEncrypt(vaultKey, iv, realBytes, VAULT_AAD);
  const envelope = {
    format: VAULT_FORMAT,
    v: VAULT_V,
    kdf: `pbkdf2-sha512-${PBKDF2_ITERATIONS}`,
    identityHint: identityHint || null,
    kcv: await computeKcv(masterKey),
    iv: bytesToBase64(iv),
    ct: bytesToBase64(ct),
    decoy: decoySection || newDecoyBytes(ct.length),
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

// Returns JSON text for `obj` padded with trailing ASCII spaces to exactly
// `targetBytes` UTF-8 bytes. `JSON.parse` ignores trailing whitespace, so the
// loader recovers `obj` unchanged. Throws if `obj` already serialises longer
// than the target. Zero structural overhead — every target >= the raw length is
// reachable (an object key would instead add a fixed ~10 bytes, leaving a
// 1..9-byte dead zone the caller could accidentally land in).
export function padPlaintextTo(obj, targetBytes) {
  const json = JSON.stringify(obj);
  const need = targetBytes - utf8(json).length;
  if (need < 0) throw new Error(`padPlaintextTo: object is ${-need} bytes over target`);
  return json + ' '.repeat(need);
}

// Phase 3d: entry-level last-writer-wins merge. `local`/`incoming` are decrypted
// vaults plus their envelope `revision` and `lastWriter`. Deterministic; the
// resulting `vault` is the same for mergeVaults(a,b) and mergeVaults(b,a) (only
// the summary's *ByRemote/*ByLocal labels swap).
export function mergeVaults(local, incoming) {
  const li = new Map(local.entries.map((e) => [e.id, e]));
  const ri = new Map(incoming.entries.map((e) => [e.id, e]));
  const summary = { added: [], updated: [], deletedByRemote: [], deletedByLocal: [], unchanged: 0 };

  const pick = (a, b) => {
    // both defined; choose the winner
    const ta = a.updatedAt || '';
    const tb = b.updatedAt || '';
    if (ta > tb) return a;
    if (tb > ta) return b;
    // tie: lastWriter order, then local (a)
    const wa = local.lastWriter || '';
    const wb = incoming.lastWriter || '';
    return wb > wa ? b : a;
  };

  const out = [];
  for (const e of local.entries) {
    const other = ri.get(e.id);
    if (!other) { out.push(e); summary.unchanged += 1; continue; }
    if (JSON.stringify(e) === JSON.stringify(other)) { out.push(e); summary.unchanged += 1; continue; }
    const winner = pick(e, other);
    out.push(winner);
    const localDel = !!e.deleted;
    const remoteDel = !!other.deleted;
    if (winner === other && remoteDel && !localDel) summary.deletedByRemote.push(e.id);
    else if (winner === e && localDel && !remoteDel) summary.deletedByLocal.push(e.id);
    else summary.updated.push(e.id);
  }
  for (const e of incoming.entries) {
    if (!li.has(e.id)) { out.push(e); summary.added.push(e.id); }
  }

  const settings = (incoming.revision || 0) > (local.revision || 0) ? incoming.settings : local.settings;
  return { vault: { entries: out, settings }, summary };
}
