/**
 * Serpent-256 block cipher wrapper.
 *
 * Implementation source: leviathan-crypto (npm) v1.4.0
 * - WASM-based Serpent-256 with bitslice S-boxes
 * - Verified against official AES submission test vectors
 * - Reference specification: https://www.cl.cam.ac.uk/~rja14/serpent.html
 */
import { serpentInit, Serpent as SerpentCore } from 'leviathan-crypto/serpent';

let initialized = false;

export async function initSerpent(): Promise<void> {
  if (initialized) return;
  await serpentInit();
  initialized = true;
}

export class Serpent256 {
  private core: SerpentCore;

  constructor() {
    this.core = new SerpentCore();
  }

  loadKey(key: Uint8Array): void {
    if (key.length !== 32) throw new Error('Serpent-256 requires a 32-byte (256-bit) key');
    this.core.loadKey(key);
  }

  encryptBlock(plaintext: Uint8Array): Uint8Array {
    if (plaintext.length !== 16) throw new Error('Serpent block size is 16 bytes (128 bits)');
    return this.core.encryptBlock(plaintext);
  }

  decryptBlock(ciphertext: Uint8Array): Uint8Array {
    if (ciphertext.length !== 16) throw new Error('Serpent block size is 16 bytes (128 bits)');
    return this.core.decryptBlock(ciphertext);
  }

  dispose(): void {
    this.core.dispose();
  }
}
