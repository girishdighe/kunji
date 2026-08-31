import { utf8, uint32be, concatBytes, bytesToBase64 } from './encoding.js';
import { pbkdf2Sha512, hkdfSha256, hmacSha256 } from './webcrypto.js';

export const PROFILE = 'v1';

// OPEN DECISION (spec s13): confirm on the slowest target device before freezing v1.
export const PBKDF2_ITERATIONS = 600000;

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
