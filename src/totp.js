import { uint64be } from './encoding.js';
import { hmac } from './webcrypto.js';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// RFC 4648 base32, case-insensitive; strips spaces and '=' padding.
// Throws on any non-alphabet character.
export function base32Decode(str) {
  const clean = String(str).replace(/[\s=]/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error(`base32Decode: invalid character ${JSON.stringify(ch)}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

// RFC 4226. counter: integer >= 0. algorithm: 'SHA-1'|'SHA-256'|'SHA-512'.
export async function hotp(keyBytes, counter, { algorithm = 'SHA-1', digits = 6 } = {}) {
  const mac = await hmac(algorithm, keyBytes, uint64be(counter));
  const offset = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[offset] & 0x7f) << 24)
    | (mac[offset + 1] << 16)
    | (mac[offset + 2] << 8)
    | mac[offset + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

// totpObj: { secret (base32 string), algorithm, digits, period }
export async function totp(totpObj, { now = Date.now() } = {}) {
  const key = base32Decode(totpObj.secret);
  const seconds = Math.floor(now / 1000);
  const counter = Math.floor(seconds / totpObj.period);
  const code = await hotp(key, counter, totpObj);
  const secondsRemaining = totpObj.period - (seconds % totpObj.period);
  return { code, secondsRemaining, period: totpObj.period };
}

const ALGO_MAP = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512',
  'SHA-1': 'SHA-1', 'SHA-256': 'SHA-256', 'SHA-512': 'SHA-512' };

// otpauth://totp/LABEL?secret=...&algorithm=...&digits=...&period=...&issuer=...
// Returns null (never throws) for anything that is not a totp otpauth URI.
export function parseOtpauth(uri) {
  let u;
  try { u = new URL(String(uri)); } catch { return null; }
  if (u.protocol !== 'otpauth:') return null;
  if (u.host.toLowerCase() !== 'totp') return null;
  const q = u.searchParams;
  const secret = (q.get('secret') || '').replace(/\s+/g, '');
  if (!secret) return null;
  const algorithm = ALGO_MAP[(q.get('algorithm') || 'SHA1').toUpperCase()] || 'SHA-1';
  const digits = Number(q.get('digits')) || 6;
  const period = Number(q.get('period')) || 30;
  const label = decodeURIComponent(u.pathname.replace(/^\//, ''));
  const issuer = q.get('issuer') || (label.includes(':') ? label.split(':')[0] : '');
  const account = label.includes(':') ? label.split(':').slice(1).join(':') : label;
  return { secret, algorithm, digits, period, issuer, account };
}
