const _enc = new TextEncoder();
const _dec = new TextDecoder();

export function utf8(str) {
  return _enc.encode(str);
}

export function fromUtf8(bytes) {
  return _dec.decode(bytes);
}

export function uint32be(n) {
  const b = new Uint8Array(4);
  b[0] = (n >>> 24) & 0xff;
  b[1] = (n >>> 16) & 0xff;
  b[2] = (n >>> 8) & 0xff;
  b[3] = n & 0xff;
  return b;
}

export function uint64be(n) {
  const b = new Uint8Array(8);
  // n is a JS number; safe for TOTP counters (< 2^53). High 32 bits via division.
  let hi = Math.floor(n / 0x100000000);
  let lo = n >>> 0;
  for (let i = 3; i >= 0; i--) { b[i] = hi & 0xff; hi >>>= 8; }
  for (let i = 7; i >= 4; i--) { b[i] = lo & 0xff; lo >>>= 8; }
  return b;
}

export function concatBytes(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

export function bytesToHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error('hex length must be even');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToBase64(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
