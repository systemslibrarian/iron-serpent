/**
 * Serpent-256 in CTR (Counter) mode.
 *
 * Uses leviathan-crypto's SerpentCtr which implements:
 * - 128-bit nonce/counter block
 * - Counter increment per block
 * - XOR keystream against plaintext/ciphertext
 *
 * Reference: https://www.cl.cam.ac.uk/~rja14/serpent.html
 */
import { SerpentCtr as SerpentCtrCore } from 'leviathan-crypto/serpent';

export class SerpentCTR {
  private core: SerpentCtrCore;

  constructor() {
    this.core = new SerpentCtrCore({ dangerUnauthenticated: true });
  }

  encrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array): Uint8Array {
    if (key.length !== 32) throw new Error('Serpent-256-CTR requires a 32-byte key');
    if (nonce.length !== 16) throw new Error('Serpent-256-CTR requires a 16-byte nonce');
    this.core.beginEncrypt(key, nonce);
    return this.core.encryptChunk(plaintext);
  }

  decrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    if (key.length !== 32) throw new Error('Serpent-256-CTR requires a 32-byte key');
    if (nonce.length !== 16) throw new Error('Serpent-256-CTR requires a 16-byte nonce');
    this.core.beginDecrypt(key, nonce);
    return this.core.decryptChunk(ciphertext);
  }

  dispose(): void {
    this.core.dispose();
  }
}
