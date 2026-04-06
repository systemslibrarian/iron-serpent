/**
 * Benchmark: Serpent-256-CTR vs AES-256-GCM.
 *
 * Serpent runs in WASM (leviathan-crypto). AES-256-GCM uses the Web Crypto API
 * which benefits from hardware AES-NI acceleration.
 */
import { SerpentCTR } from './serpent-ctr';

interface BenchmarkResult {
  serpentMBps: number;
  aesMBps: number;
  ratio: number;
}

function generateRandomData(size: number): Uint8Array {
  const data = new Uint8Array(size);
  const chunkSize = 65536;
  for (let offset = 0; offset < size; offset += chunkSize) {
    const len = Math.min(chunkSize, size - offset);
    const chunk = new Uint8Array(len);
    crypto.getRandomValues(chunk);
    data.set(chunk, offset);
  }
  return data;
}

export async function runBenchmark(
  onProgress?: (msg: string) => void
): Promise<BenchmarkResult> {
  const iterations = 10;
  const dataSize = 1024 * 1024; // 1 MB
  const data = generateRandomData(dataSize);

  const key32 = new Uint8Array(32);
  crypto.getRandomValues(key32);
  const nonce16 = new Uint8Array(16);
  crypto.getRandomValues(nonce16);

  // --- Serpent-256-CTR benchmark ---
  onProgress?.('Benchmarking Serpent-256-CTR...');
  const serpentTimes: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const ctr = new SerpentCTR();
    const start = performance.now();
    ctr.encrypt(key32, nonce16, data);
    const elapsed = performance.now() - start;
    serpentTimes.push(elapsed);
    ctr.dispose();
    onProgress?.(`Serpent iteration ${i + 1}/${iterations}: ${elapsed.toFixed(1)}ms`);
  }
  const serpentAvgMs = serpentTimes.reduce((a, b) => a + b, 0) / iterations;
  const serpentMBps = (dataSize / (1024 * 1024)) / (serpentAvgMs / 1000);

  // --- AES-256-GCM benchmark ---
  onProgress?.('Benchmarking AES-256-GCM (Web Crypto)...');
  const aesKey = await crypto.subtle.importKey('raw', key32.slice().buffer as ArrayBuffer, 'AES-GCM', false, ['encrypt']);
  const aesTimes: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);
    const start = performance.now();
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv.buffer as ArrayBuffer }, aesKey, data.slice().buffer as ArrayBuffer);
    const elapsed = performance.now() - start;
    aesTimes.push(elapsed);
    onProgress?.(`AES iteration ${i + 1}/${iterations}: ${elapsed.toFixed(1)}ms`);
  }
  const aesAvgMs = aesTimes.reduce((a, b) => a + b, 0) / iterations;
  const aesMBps = (dataSize / (1024 * 1024)) / (aesAvgMs / 1000);

  const ratio = aesMBps / serpentMBps;

  return { serpentMBps, aesMBps, ratio };
}
