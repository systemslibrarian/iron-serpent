/**
 * HMAC-SHA256 Encrypt-then-MAC using Web Crypto API.
 *
 * The MAC key is derived from the Argon2id encryption key via
 * HKDF-SHA256 with info label "iron-serpent-mac".
 */

const MAC_INFO = new TextEncoder().encode('iron-serpent-mac');
const HKDF_SALT = new Uint8Array(32); // zero-filled per RFC 5869 when no salt

export async function deriveMACKey(encryptionKey: Uint8Array): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    encryptionKey.slice().buffer as ArrayBuffer,
    'HKDF',
    false,
    ['deriveBits']
  );
  const macKeyBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: MAC_INFO },
    baseKey,
    256
  );
  return crypto.subtle.importKey(
    'raw',
    macKeyBits,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

export async function computeMAC(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign('HMAC', key, data.slice().buffer as ArrayBuffer);
  return new Uint8Array(sig);
}

export async function verifyMAC(key: CryptoKey, data: Uint8Array, mac: Uint8Array): Promise<boolean> {
  return crypto.subtle.verify('HMAC', key, mac.slice().buffer as ArrayBuffer, data.slice().buffer as ArrayBuffer);
}
