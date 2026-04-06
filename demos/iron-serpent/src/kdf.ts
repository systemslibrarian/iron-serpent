/**
 * Argon2id key derivation for Serpent-256.
 *
 * Parameters per specification:
 * - Time cost: 3 iterations
 * - Memory cost: 65536 KiB (64 MiB)
 * - Parallelism: 1
 * - Output: 32 bytes (256-bit key)
 * - Salt: 16 bytes, randomly generated per operation
 *
 * argon2-browser is loaded via script tag (bundled WASM version).
 */

declare const argon2: {
  ArgonType: { Argon2d: 0; Argon2i: 1; Argon2id: 2 };
  hash(opts: {
    pass: string | Uint8Array;
    salt: string | Uint8Array;
    type?: number;
    time?: number;
    mem?: number;
    parallelism?: number;
    hashLen?: number;
  }): Promise<{ hash: Uint8Array; hashHex: string; encoded: string }>;
};

export const KDF_PARAMS = {
  timeCost: 3,
  memoryCost: 65536,
  parallelism: 1,
  hashLength: 32,
  saltLength: 16,
} as const;

export function generateSalt(): Uint8Array {
  const salt = new Uint8Array(KDF_PARAMS.saltLength);
  crypto.getRandomValues(salt);
  return salt;
}

export async function deriveKey(passphrase: string, salt: Uint8Array): Promise<Uint8Array> {
  if (salt.length !== KDF_PARAMS.saltLength) {
    throw new Error(`Salt must be ${KDF_PARAMS.saltLength} bytes`);
  }
  const result = await argon2.hash({
    pass: passphrase,
    salt,
    type: argon2.ArgonType.Argon2id,
    time: KDF_PARAMS.timeCost,
    mem: KDF_PARAMS.memoryCost,
    parallelism: KDF_PARAMS.parallelism,
    hashLen: KDF_PARAMS.hashLength,
  });
  return result.hash;
}
