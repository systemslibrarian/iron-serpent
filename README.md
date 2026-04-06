# iron-serpent

A browser-based cryptographic demo for the [crypto-compare](https://github.com/systemslibrarian/crypto-compare) portfolio showcasing **Serpent-256**, the AES finalist designed by Eli Biham (Technion, Israel), Ross Anderson (Cambridge), and Lars Knudsen (DTU Denmark).

## Symmetric Block Ciphers (Non-AES)

| Field | Value |
|---|---|
| Cipher | Serpent-256 |
| Key size | 256-bit |
| Block size | 128-bit |
| Rounds | 32 |
| Security margin | 20 rounds (63%) |
| Designers | Biham, Anderson, Knudsen |
| Year | 1998 |
| Status | AES finalist (2nd place) |

## Quick Start

```bash
cd demos/iron-serpent
npm install && npm run dev
```

## Demo Features

- **Encrypt/Decrypt UI** — Serpent-256-CTR with Argon2id KDF and HMAC-SHA256 Encrypt-then-MAC
- **Security Margin Visualization** — Animated SVG comparing Serpent (32 rounds) vs AES (10/12/14 rounds) with attack frontier markers
- **Performance Benchmark** — Live Serpent-256-CTR vs AES-256-GCM throughput comparison
- **Attribution Panel** — Designers, Israeli cryptographic lineage, AES competition history

See [demos/iron-serpent/README.md](demos/iron-serpent/README.md) for detailed documentation.