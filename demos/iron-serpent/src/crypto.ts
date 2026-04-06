/**
 * Serpent-256-CTR encrypt/decrypt pipeline with Argon2id KDF and HMAC-SHA256 authentication.
 *
 * Flow:
 * Encrypt: passphrase → Argon2id → encKey → Serpent-256-CTR encrypt → HMAC-SHA256 tag
 * Decrypt: verify HMAC first → Serpent-256-CTR decrypt
 */
import { SerpentCTR } from './serpent-ctr';
import { deriveKey, generateSalt } from './kdf';
import { deriveMACKey, computeMAC, verifyMAC } from './mac';

export interface EncryptedPayload {
  salt: string;       // base64
  nonce: string;      // base64
  ciphertext: string; // base64
  mac: string;        // base64
  version: string;    // 'iron-serpent-v1'
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

export async function encrypt(plaintext: string, passphrase: string): Promise<EncryptedPayload> {
  const salt = generateSalt();
  const nonce = new Uint8Array(16);
  crypto.getRandomValues(nonce);

  const encKey = await deriveKey(passphrase, salt);
  const macKey = await deriveMACKey(encKey);

  const plaintextBytes = new TextEncoder().encode(plaintext);
  const ctr = new SerpentCTR();
  const ciphertextBytes = ctr.encrypt(encKey, nonce, plaintextBytes);
  ctr.dispose();

  const macData = concat(salt, nonce, ciphertextBytes);
  const mac = await computeMAC(macKey, macData);

  return {
    salt: toBase64(salt),
    nonce: toBase64(nonce),
    ciphertext: toBase64(ciphertextBytes),
    mac: toBase64(mac),
    version: 'iron-serpent-v1',
  };
}

export async function decrypt(payload: EncryptedPayload, passphrase: string): Promise<string> {
  if (payload.version !== 'iron-serpent-v1') {
    throw new Error('Unsupported payload version');
  }

  const salt = fromBase64(payload.salt);
  const nonce = fromBase64(payload.nonce);
  const ciphertextBytes = fromBase64(payload.ciphertext);
  const mac = fromBase64(payload.mac);

  const encKey = await deriveKey(passphrase, salt);
  const macKey = await deriveMACKey(encKey);

  // Verify MAC BEFORE decryption — Encrypt-then-MAC
  const macData = concat(salt, nonce, ciphertextBytes);
  const valid = await verifyMAC(macKey, macData, mac);
  if (!valid) {
    throw new Error('Authentication failed — ciphertext has been tampered with');
  }

  const ctr = new SerpentCTR();
  const plaintextBytes = ctr.decrypt(encKey, nonce, ciphertextBytes);
  ctr.dispose();

  return new TextDecoder().decode(plaintextBytes);
}
