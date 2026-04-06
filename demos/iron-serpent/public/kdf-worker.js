/**
 * Argon2id KDF worker.
 * Runs as a classic worker so importScripts is available to load the
 * argon2-bundled UMD bundle (which inlines WASM as base64).
 */
/* global importScripts, argon2 */
importScripts(new URL('argon2-bundled.min.js', self.location.href).href);

self.onmessage = async function (e) {
  var passphrase = e.data.passphrase;
  var salt = new Uint8Array(e.data.salt);
  try {
    var result = await argon2.hash({
      pass: passphrase,
      salt: salt,
      type: argon2.ArgonType.Argon2id,
      time: 3,
      mem: 65536,
      parallelism: 1,
      hashLen: 32,
    });
    self.postMessage({ hash: Array.from(result.hash) });
  } catch (err) {
    self.postMessage({ error: err.message || String(err) });
  }
};
