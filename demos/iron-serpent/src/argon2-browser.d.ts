declare module 'argon2-browser' {
  export interface Argon2Result {
    hash: Uint8Array;
    hashHex: string;
    encoded: string;
  }

  export interface Argon2HashOptions {
    pass: string | Uint8Array;
    salt: string | Uint8Array;
    type?: number;
    time?: number;
    mem?: number;
    parallelism?: number;
    hashLen?: number;
  }

  export interface Argon2Runtime {
    ArgonType: {
      Argon2d: number;
      Argon2i: number;
      Argon2id: number;
    };
    hash(options: Argon2HashOptions): Promise<Argon2Result>;
  }

  const argon2: Argon2Runtime;
  export default argon2;
}