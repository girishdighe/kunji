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

// algorithm: 'SHA-1' | 'SHA-256' | 'SHA-512'
export async function hmac(algorithm, keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: algorithm }, false, ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, msgBytes);
  return new Uint8Array(sig);
}

export const hmacSha256 = (keyBytes, msgBytes) => hmac('SHA-256', keyBytes, msgBytes);

export async function aesGcmEncrypt(keyBytes, ivBytes, plaintextBytes, aadBytes) {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt'],
  );
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: ivBytes, additionalData: aadBytes, tagLength: 128 },
    key, plaintextBytes,
  );
  return new Uint8Array(ct);
}

export async function aesGcmDecrypt(keyBytes, ivBytes, ciphertextBytes, aadBytes) {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt'],
  );
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBytes, additionalData: aadBytes, tagLength: 128 },
    key, ciphertextBytes,
  );
  return new Uint8Array(pt);
}
