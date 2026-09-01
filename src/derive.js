import { utf8, uint32be, concatBytes, bytesToBase64 } from './encoding.js';
import { pbkdf2Sha512, hkdfSha256, hmacSha256 } from './webcrypto.js';

export const PROFILE = 'v1';

// OPEN DECISION (spec s13): confirm on the slowest target device before freezing v1.
export const PBKDF2_ITERATIONS = 600000;

// --- Profile registry -----------------------------------------------------
// Every master-key derivation routes through a profile so a future KDF (v2)
// is a one-object drop-in. See docs/specs/2026-09-01-kunji-v2-profile-requirements.md.

export const PROFILES = {
  v1: {
    id: 'v1',
    label: 'PBKDF2-HMAC-SHA512',
    // passphrase: raw string; normalisedIdentity: already NFKC+trim+lowercase
    deriveMasterKey: (passphrase, normalisedIdentity) =>
      pbkdf2Sha512(utf8(passphrase), utf8(normalisedIdentity), PBKDF2_ITERATIONS, MASTER_KEY_BYTES),
    kdfTag: `pbkdf2-sha512-${PBKDF2_ITERATIONS}`,
  },
};

export const DEFAULT_PROFILE = 'v1';

export function profileOf(id) {
  const p = PROFILES[id];
  if (!p) throw new Error(`unknown profile: ${id}`);
  return p;
}

export const MASTER_KEY_BYTES = 32;
export const DEFAULT_LENGTH = 20;
export const MIN_LENGTH = 8;
export const MAX_LENGTH = 64;
export const DEFAULT_RULES = 'standard';

export const CHARSETS = {
  'standard':
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*+-=?@_',
  'letters-digits':
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
  'max-symbols':
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*()-_=+[]{};:,.?@',
};

const _LOWER = 'abcdefghijklmnopqrstuvwxyz';
const _UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const _DIGIT = '0123456789';

export function normaliseInput(str) {
  return str.normalize('NFKC').trim().toLowerCase();
}

export function requiredClasses(rules) {
  if (rules === 'letters-digits') return ['lower', 'upper', 'digit'];
  return ['lower', 'upper', 'digit', 'symbol'];
}

export function classChars(cls, charset) {
  if (cls === 'lower') return _LOWER;
  if (cls === 'upper') return _UPPER;
  if (cls === 'digit') return _DIGIT;
  let out = '';
  for (const ch of charset) {
    if (!/[A-Za-z0-9]/.test(ch)) out += ch;
  }
  return out;
}

export function makeKeystream(entrySeed, label) {
  const labelBytes = utf8(label);
  let block = new Uint8Array(0);
  let blockIndex = 0;
  let pos = 0;
  return {
    async next() {
      if (pos >= block.length) {
        block = await hmacSha256(entrySeed, concatBytes(labelBytes, uint32be(blockIndex)));
        blockIndex += 1;
        pos = 0;
      }
      const value = block[pos];
      pos += 1;
      return value;
    },
  };
}

export async function sampleIndex(keystream, n) {
  if (!Number.isInteger(n) || n < 1) {
    throw new Error('sampleIndex: n must be a positive integer');
  }
  const limit = 256 - (256 % n);
  for (;;) {
    const b = await keystream.next();
    if (b < limit) return b % n;
  }
}

export async function deriveEntrySeed(masterKey, { site, account, counter, rules, length }) {
  const info = utf8(`gen|${site}|${account}|${counter}|${rules}|${length}`);
  return hkdfSha256(masterKey, utf8('kunji/v1'), info, 64);
}

export async function deriveVaultKey(masterKey) {
  return hkdfSha256(masterKey, utf8('kunji/v1'), utf8('vault-key'), 32);
}

export async function generateChars(entrySeed, charset, length) {
  const keystream = makeKeystream(entrySeed, 'gen');
  const n = charset.length;
  const out = new Array(length);
  for (let i = 0; i < length; i++) {
    out[i] = charset[await sampleIndex(keystream, n)];
  }
  return out;
}

function _classOf(ch) {
  if (/[a-z]/.test(ch)) return 'lower';
  if (/[A-Z]/.test(ch)) return 'upper';
  if (/[0-9]/.test(ch)) return 'digit';
  return 'symbol';
}

export async function enforceClasses(chars, entrySeed, rules, charset) {
  const result = chars.slice();
  const length = result.length;
  const need = requiredClasses(rules);

  const present = new Set();
  for (const ch of result) present.add(_classOf(ch));
  const missing = need.filter((c) => !present.has(c));
  if (missing.length === 0) return result;

  const keystream = makeKeystream(entrySeed, 'fix');
  const used = new Set();
  for (const cls of missing) {
    // Protect the sole carrier of any already-present required class.
    const counts = {};
    for (const c of need) counts[c] = 0;
    for (const ch of result) {
      if (_classOf(ch) in counts) counts[_classOf(ch)] += 1;
    }
    const protectedPos = new Set();
    for (let i = 0; i < length; i++) {
      if (counts[_classOf(result[i])] === 1) protectedPos.add(i);
    }

    let pos = await sampleIndex(keystream, length);
    while (used.has(pos) || protectedPos.has(pos)) pos = (pos + 1) % length;
    used.add(pos);
    const pool = classChars(cls, charset);
    result[pos] = pool[await sampleIndex(keystream, pool.length)];
  }
  return result;
}

export async function deriveMasterKey(passphrase, identity, profile = DEFAULT_PROFILE) {
  return profileOf(profile).deriveMasterKey(passphrase, normaliseInput(identity));
}

export async function computeKcv(masterKey) {
  const mac = await hmacSha256(masterKey, utf8('kunji/kcv/v1'));
  return bytesToBase64(mac.slice(0, 4));
}

export async function derivePassword(params) {
  const site = normaliseInput(params.site ?? '');
  const account = normaliseInput(params.account ?? '');
  const counter = params.counter ?? 1;
  const rules = params.rules ?? DEFAULT_RULES;
  const length = params.length ?? DEFAULT_LENGTH;

  if (!Number.isInteger(counter) || counter < 1) {
    throw new Error('counter must be an integer >= 1');
  }
  if (!Number.isInteger(length) || length < MIN_LENGTH || length > MAX_LENGTH) {
    throw new Error(`length must be an integer in ${MIN_LENGTH}..${MAX_LENGTH}`);
  }
  const charset = CHARSETS[rules];
  if (!charset) throw new Error(`unknown rules: ${rules}`);

  const masterKey = params.masterKey
    ? params.masterKey
    : await deriveMasterKey(params.passphrase, params.identity ?? '');

  const entrySeed = await deriveEntrySeed(masterKey, { site, account, counter, rules, length });
  const raw = await generateChars(entrySeed, charset, length);
  const fixed = await enforceClasses(raw, entrySeed, rules, charset);
  return fixed.join('');
}
