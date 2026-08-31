export async function pbkdf2Sha512(passphraseBytes, saltBytes, iterations, dkLenBytes) {
  const key = await crypto.subtle.importKey(
    'raw', passphraseBytes, 'PBKDF2', false, ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-512', salt: saltBytes, iterations },
    key, dkLenBytes * 8,
  );
  return new Uint8Array(bits);
}

export async function hkdfSha256(ikmBytes, saltBytes, infoBytes, lenBytes) {
  const key = await crypto.subtle.importKey(
    'raw', ikmBytes, 'HKDF', false, ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info: infoBytes },
    key, lenBytes * 8,
  );
  return new Uint8Array(bits);
}

export async function hmacSha256(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, msgBytes);
  return new Uint8Array(sig);
}
