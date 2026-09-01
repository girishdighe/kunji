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
