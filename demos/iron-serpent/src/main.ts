import './style.css';
import { initSerpent } from './serpent';
import { encrypt, decrypt } from './crypto';
import type { EncryptedPayload } from './crypto';
import { renderVisualization } from './visualization';
import { runBenchmark } from './benchmark';

let lastPayload: EncryptedPayload | null = null;
let outputFormat: 'base64' | 'hex' = 'base64';

function $(id: string): HTMLElement {
  return document.getElementById(id)!;
}

function toHexString(b64: string): string {
  const binary = atob(b64);
  return Array.from(binary, (c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}

function formatPayload(p: EncryptedPayload, fmt: 'base64' | 'hex'): string {
  if (fmt === 'hex') {
    return JSON.stringify({
      salt: toHexString(p.salt),
      nonce: toHexString(p.nonce),
      ciphertext: toHexString(p.ciphertext),
      mac: toHexString(p.mac),
      version: p.version,
    }, null, 2);
  }
  return JSON.stringify(p, null, 2);
}

async function init() {
  const status = $('init-status');
  try {
    await initSerpent();
    status.textContent = 'Serpent-256 engine ready.';
    status.classList.add('ready');
    ($('enc-btn') as HTMLButtonElement).disabled = false;
    ($('dec-btn') as HTMLButtonElement).disabled = false;
  } catch (e) {
    status.textContent = `Initialization failed: ${e instanceof Error ? e.message : e}`;
    status.classList.add('error');
    return;
  }

  // --- Password toggle ---
  for (const prefix of ['enc', 'dec']) {
    const input = $(`${prefix}-pass`) as HTMLInputElement;
    $(`${prefix}-pass-toggle`).addEventListener('click', () => {
      input.type = input.type === 'password' ? 'text' : 'password';
    });
  }

  // --- Encrypt ---
  $('enc-btn').addEventListener('click', async () => {
    const pass = ($('enc-pass') as HTMLInputElement).value;
    const text = ($('enc-input') as HTMLTextAreaElement).value;
    if (!pass || !text) return;

    const btn = $('enc-btn') as HTMLButtonElement;
    btn.disabled = true;
    btn.textContent = 'Encrypting…';
    try {
      lastPayload = await encrypt(text, pass);
      ($('enc-output') as HTMLTextAreaElement).value = formatPayload(lastPayload, outputFormat);
    } catch (e) {
      ($('enc-output') as HTMLTextAreaElement).value = `Error: ${e instanceof Error ? e.message : e}`;
    } finally {
      btn.disabled = false;
      btn.textContent = 'Encrypt';
    }
  });

  // --- Format toggle ---
  $('enc-fmt-b64').addEventListener('click', () => {
    outputFormat = 'base64';
    $('enc-fmt-b64').classList.add('active');
    $('enc-fmt-hex').classList.remove('active');
    if (lastPayload) ($('enc-output') as HTMLTextAreaElement).value = formatPayload(lastPayload, outputFormat);
  });
  $('enc-fmt-hex').addEventListener('click', () => {
    outputFormat = 'hex';
    $('enc-fmt-hex').classList.add('active');
    $('enc-fmt-b64').classList.remove('active');
    if (lastPayload) ($('enc-output') as HTMLTextAreaElement).value = formatPayload(lastPayload, outputFormat);
  });

  // --- Copy ---
  $('enc-copy').addEventListener('click', () => {
    const output = ($('enc-output') as HTMLTextAreaElement).value;
    if (output) navigator.clipboard.writeText(output);
  });

  // --- Decrypt ---
  $('dec-btn').addEventListener('click', async () => {
    const pass = ($('dec-pass') as HTMLInputElement).value;
    const input = ($('dec-input') as HTMLTextAreaElement).value;
    if (!pass || !input) return;

    const btn = $('dec-btn') as HTMLButtonElement;
    btn.disabled = true;
    btn.textContent = 'Decrypting…';
    const badge = $('auth-badge');

    try {
      const payload: EncryptedPayload = JSON.parse(input);
      const result = await decrypt(payload, pass);
      ($('dec-output') as HTMLTextAreaElement).value = result;
      badge.textContent = '✓ Authenticated';
      badge.className = 'badge verified';
    } catch (e) {
      ($('dec-output') as HTMLTextAreaElement).value = '';
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes('tampered')) {
        badge.textContent = '✗ Authentication Failed';
        badge.className = 'badge failed';
      } else {
        badge.textContent = `Error: ${msg}`;
        badge.className = 'badge failed';
      }
    } finally {
      btn.disabled = false;
      btn.textContent = 'Decrypt';
    }
  });

  // --- Visualization ---
  renderVisualization($('vis-container'));

  // --- Benchmark ---
  $('bench-btn').addEventListener('click', async () => {
    const btn = $('bench-btn') as HTMLButtonElement;
    btn.disabled = true;
    const progress = $('bench-progress');
    const results = $('bench-results');
    progress.classList.remove('hidden');
    results.classList.add('hidden');

    try {
      const r = await runBenchmark((msg) => {
        progress.textContent = msg;
      });
      $('bench-serpent').textContent = `${r.serpentMBps.toFixed(1)} MB/s`;
      $('bench-aes').textContent = `${r.aesMBps.toFixed(1)} MB/s`;
      $('bench-ratio').textContent = `AES is ${r.ratio.toFixed(1)}× faster`;
      results.classList.remove('hidden');
    } catch (e) {
      progress.textContent = `Benchmark error: ${e instanceof Error ? e.message : e}`;
    } finally {
      btn.disabled = false;
      progress.classList.add('hidden');
    }
  });
}

init();

