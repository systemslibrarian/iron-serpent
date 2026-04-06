/**
 * Serpent-256 test suite.
 *
 * Test vector source: Official AES submission package
 * https://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf
 * https://www.cl.cam.ac.uk/~rja14/Papers/serpent.tar.gz (floppy4/ecb_vk.txt, ecb_vt.txt)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initSerpent, Serpent256 } from '../serpent';
import { SerpentCTR } from '../serpent-ctr';

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

describe('Serpent-256 Block Cipher', () => {
  beforeAll(async () => {
    await initSerpent();
  });

  it('encrypts official variable-text vector #1 (256-bit key)', () => {
    // From ecb_vt.txt KEYSIZE=256:
    // KEY=0000...0000 (32 bytes), PT=80000000000000000000000000000000
    // CT=da5a7992b1b4ae6f8c004bc8a7de5520
    const key = hexToBytes('0000000000000000000000000000000000000000000000000000000000000000');
    const pt = hexToBytes('80000000000000000000000000000000');
    const expectedCt = 'da5a7992b1b4ae6f8c004bc8a7de5520';

    const cipher = new Serpent256();
    cipher.loadKey(key);
    const ct = cipher.encryptBlock(pt);
    expect(bytesToHex(ct)).toBe(expectedCt);
    cipher.dispose();
  });

  it('encrypts official variable-key vector #1 (256-bit key)', () => {
    // From ecb_vk.txt KEYSIZE=256:
    // KEY=8000...0000, PT=0000...0000
    // CT=abed96e766bf28cbc0ebd21a82ef0819
    const key = hexToBytes('8000000000000000000000000000000000000000000000000000000000000000');
    const pt = hexToBytes('00000000000000000000000000000000');
    const expectedCt = 'abed96e766bf28cbc0ebd21a82ef0819';

    const cipher = new Serpent256();
    cipher.loadKey(key);
    const ct = cipher.encryptBlock(pt);
    expect(bytesToHex(ct)).toBe(expectedCt);
    cipher.dispose();
  });

  it('decrypts official variable-key vector #1 (256-bit key)', () => {
    const key = hexToBytes('8000000000000000000000000000000000000000000000000000000000000000');
    const ct = hexToBytes('abed96e766bf28cbc0ebd21a82ef0819');
    const expectedPt = '00000000000000000000000000000000';

    const cipher = new Serpent256();
    cipher.loadKey(key);
    const pt = cipher.decryptBlock(ct);
    expect(bytesToHex(pt)).toBe(expectedPt);
    cipher.dispose();
  });

  it('encrypts additional variable-text vectors (256-bit key)', () => {
    const key = hexToBytes('0000000000000000000000000000000000000000000000000000000000000000');
    const vectors = [
      { pt: '40000000000000000000000000000000', ct: 'f351351b823e3d7a4f3bf390c4f198cb' },
      { pt: '20000000000000000000000000000000', ct: 'a477a65d9db75c8ed7218c52b64c65bb' },
      { pt: '10000000000000000000000000000000', ct: 'f8019452cba4fe618d80a6756183b2e0' },
    ];

    const cipher = new Serpent256();
    cipher.loadKey(key);
    for (const v of vectors) {
      const ct = cipher.encryptBlock(hexToBytes(v.pt));
      expect(bytesToHex(ct)).toBe(v.ct);
    }
    cipher.dispose();
  });
});

describe('Serpent-256-CTR', () => {
  beforeAll(async () => {
    await initSerpent();
  });

  it('encrypts and decrypts a known string (round-trip)', () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    const nonce = new Uint8Array(16);
    crypto.getRandomValues(nonce);
    const plaintext = new TextEncoder().encode('Hello, Serpent-256-CTR! This is a round-trip test.');

    const encCTR = new SerpentCTR();
    const ciphertext = encCTR.encrypt(key, nonce, plaintext);
    encCTR.dispose();

    // Ciphertext must differ from plaintext
    expect(bytesToHex(ciphertext)).not.toBe(bytesToHex(plaintext));

    const decCTR = new SerpentCTR();
    const decrypted = decCTR.decrypt(key, nonce, ciphertext);
    decCTR.dispose();

    expect(new TextDecoder().decode(decrypted)).toBe('Hello, Serpent-256-CTR! This is a round-trip test.');
  });

  it('produces different ciphertext with different nonces', () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    const nonce1 = new Uint8Array(16);
    crypto.getRandomValues(nonce1);
    const nonce2 = new Uint8Array(16);
    crypto.getRandomValues(nonce2);
    const plaintext = new TextEncoder().encode('Same plaintext, different nonces');

    const ctr1 = new SerpentCTR();
    const ct1 = ctr1.encrypt(key, nonce1, plaintext);
    ctr1.dispose();

    const ctr2 = new SerpentCTR();
    const ct2 = ctr2.encrypt(key, nonce2, plaintext);
    ctr2.dispose();

    expect(bytesToHex(ct1)).not.toBe(bytesToHex(ct2));
  });
});
