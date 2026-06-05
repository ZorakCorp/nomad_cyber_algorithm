<div align="center">

# ◈ NOMAD CYBER ALGORITHM

### Post-Quantum Sovereign Security Stack

[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20+-339933?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org/)
[![PQC](https://img.shields.io/badge/Quantum--Safe-Kyber768%20%2B%20Dilithium3-7C3AED?style=for-the-badge)](https://openquantumsafe.org/)
[![Tests](https://img.shields.io/badge/Tests-38%20passing-22C55E?style=for-the-badge)](src/tests/)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)

**Quantum-resistant microservice mesh · Chaos cipher (no wire patterns) · Full security perimeter**

<br/>

```
╔══════════════════════════════════════════════════════════════════════════╗
║  KYBER768 KEM  →  QS-CA Identity  →  Imperial Cipher Stack  →  GCM    ║
║  DILITHIUM3 SIG →  Allowlist + Replay Guard  →  Chaos Mode (no pattern) ║
║  Gateway + Console MFA  →  DB/File Vaults  →  WAF + Helm deployment    ║
╚══════════════════════════════════════════════════════════════════════════╝
```

<br/>

[Overview](#-overview) ·
[Architecture](#-architecture) ·
[Quick Start](#-quick-start) ·
[Security](#-security-model) ·
[Chaos Mode](#-chaos-mode) ·
[Configuration](#-configuration) ·
[Tests](#-tests)

</div>

---

## ◇ Overview

**Nomad Cyber Algorithm** is a TypeScript post-quantum cryptography (PQC) stack for securing microservice communication and sensitive data. It combines:

- **Kyber768** key encapsulation and **Dilithium3** signatures
- **QS-CA** certificate pinning with mutual authentication
- **Imperial cipher stack** (7 historical layers) + **Aureon occult veil**
- **Chaos mode** — per-message unpredictable layer order, padding, and timing jitter
- **Sovereign stack** — API gateway, MFA console, DB field encryption, file vault
- **Edge templates** — nginx WAF and Cloudflare rules, Kubernetes Helm chart

Designed for high-assurance environments: air-gapped networks, SCI/TS workloads, and forward-looking post-quantum architectures.

| Capability | Implementation |
|:---|:---|
| **Key Exchange** | Kyber768 (ML-KEM) via OQS |
| **Authentication** | Dilithium3 + QS-CA cert verification |
| **Data Channel** | Imperial cipher → AES-256-GCM + HKDF |
| **Unpredictability** | Chaos padding, layer shuffle, timing veil |
| **Perimeter** | Gateway RBAC, console MFA, rate limits |
| **Data at Rest** | DB field vault + encrypted file vault |
| **Transport** | Length-prefixed TCP framing + optional sidecar |

---

## ◇ Architecture

```mermaid
flowchart TB
    subgraph edge [Edge Perimeter]
        WAF[WAF / DDoS Rules]
        GW[API Gateway :8080]
        CON[Console :8081 MFA]
    end
    subgraph core [PQC Core :8443]
        HS[Kyber768 + Dilithium3 Handshake]
        CHAOS[Chaos Cipher Engine]
        IMP[Imperial 7-Layer Stack]
        GCM[AES-256-GCM Records]
    end
    subgraph data [Data Protection]
        DBV[DB Field Vault]
        FV[File Vault]
    end
    WAF --> GW
    WAF --> CON
    GW --> HS
    CON -->|session token| GW
    HS --> CHAOS --> IMP --> GCM
    GW --> DBV
    GW --> FV
```

### Handshake Flow

| Step | Actor | Action |
|:---:|:---|:---|
| 1 | Client | `client_hello` or `session_resume` (signed proof) |
| 2 | Server | `server_hello` — pinned KEM + fresh QS-CA cert |
| 3 | Client | Verify cert matches hello keys; Kyber encapsulate |
| 4 | Client | `client_auth_response` — ciphertext + Dilithium signature |
| 5 | Server | Verify signature, allowlist check, decapsulate |
| 6 | Server | `server_auth_response` — signed + session ticket |
| 7 | Both | `encrypted_data` with strict sequence +1, chaos cipher, GCM |

---

## ◇ Quick Start

### Prerequisites

- **Node.js** 20+
- **npm** 10+

### Install & Run

```bash
git clone https://github.com/ZorakCorp/nomad_cyber_algorithm.git
cd nomad_cyber_algorithm
npm install
npm run build

# PQC microservice demo (chaos mode on)
npm start

# Full sovereign stack (gateway + console + vaults + PQC)
npm run start:sovereign
```

### Expected Output

```
[CHAOS] Unpredictable cipher mode: ACTIVE (no wire patterns)
[DEMO] Session ticket issued (...). Resumption-ready.
[DEMO] Server metrics: { "handshakesSucceeded": 1, ... }
```

---

## ◇ Security Model

### Defense in Depth

| Layer | Protection |
|:---|:---|
| **Edge WAF** | DDoS rate limits, SQLi/path traversal blocks (`deploy/waf/`) |
| **API Gateway** | RBAC, body size limits, security headers, session auth |
| **Console** | scrypt passwords, RFC 6238 TOTP MFA, rate-limited MFA attempts |
| **PQC Handshake** | QS-CA cert pin, allowlist, replay guard, rate limits |
| **Record Layer** | AES-256-GCM with AAD (`correlationId:sequence:recordType`) |
| **Session Tickets** | AES-GCM encrypted, HMAC-sealed, one-time consume |
| **DB Vault** | Per-field AES-256-GCM with tenant-bound AAD |
| **File Vault** | AES-256-GCM at rest, object ID validation, owner check |

### Production Checklist

```bash
# Required for production (dev mode OFF)
NOMAD_DEV_MODE=false
NOMAD_CONSOLE_ADMIN_PASSWORD=<strong-password>
NOMAD_CONSOLE_ADMIN_TOTP=<base32-secret>
NOMAD_DB_VAULT_KEY_PATH=/secrets/db-vault.key    # 64 hex chars
NOMAD_FILE_VAULT_KEY_PATH=/secrets/file-vault.key
NOMAD_QS_CA_ROOT_PATH=/secrets/qs-ca-root.b64
NOMAD_CLIENT_ALLOWLIST=<base64-dilithium-pubkeys>
```

> **Note:** `@open-quantum-safe/oqs-javascript` ships as a local stub at `vendor/oqs-javascript/`. Replace with real liboqs bindings for production PQC.

---

## ◇ Chaos Mode

Chaos mode eliminates predictable wire patterns — every message looks different even with identical plaintext.

| Mechanism | Effect |
|:---|:---|
| **Layer shuffle** | Hieroglyph / Augustan / Scytale order changes per message (key-derived) |
| **Chaotic padding** | 16–272 byte random prefix + 8–128 byte suffix (CSPRNG) |
| **Per-message keys** | Layer keys and scytale diameter vary by sequence + timestamp |
| **Chaos fingerprint** | 8-byte HMAC tag — tamper detection |
| **Timing jitter** | Server responses delayed 0–40ms — defeats traffic analysis |

```bash
NOMAD_CHAOS_MODE=true        # default ON
NOMAD_CHAOS_JITTER_MS=40     # response timing noise
```

---

## ◇ Configuration

| Variable | Default | Description |
|:---|:---|:---|
| `NOMAD_PORT` | `8443` | PQC TCP server port |
| `NOMAD_GATEWAY_PORT` | `8080` | HTTP API gateway |
| `NOMAD_CONSOLE_PORT` | `8081` | Admin console |
| `NOMAD_HEALTH_PORT` | `9090` | Health/metrics endpoint |
| `NOMAD_CHAOS_MODE` | `true` | Unpredictable cipher mode |
| `NOMAD_DEV_MODE` | `false` | Allows dev credentials + ephemeral vault keys |
| `NOMAD_IMPERIAL_CIPHER` | `true` | Imperial cipher stack |
| `NOMAD_OCCULT_VEIL` | `true` | Aureon planetary epoch veil |
| `NOMAD_REQUIRE_ALLOWLIST` | auto | Fail-closed client allowlist |
| `NOMAD_VAULT_DIR` | `./nomad-vault` | Encrypted file storage |

---

## ◇ Tests

```bash
npm test    # 38 tests: protocol, fuzz, imperial, chaos, security audit, live integration
```

| Suite | Tests | Coverage |
|:---|:---:|:---|
| `protocol.test` | 9 | Wire format, replay guard, rate limits |
| `fuzz.test` | 3 | Random frame safety |
| `imperial.test` | 7 | Cipher stack round-trips |
| `chaos.test` | 5 | Padding, shuffle, no-pattern ciphertext |
| `security_audit.test` | 6 | Allowlist, tickets, replay cap |
| `live_integration.test` | 2 | Live HTTP + PQC end-to-end |
| `session.test` | 3 | Session tickets + cache |
| `dependency_audit.test` | 3 | Supply chain allowlist |

---

## ◇ Project Structure

```
nomad_cyber_algorithm/
├── src/
│   ├── main.ts                  # PQC demo
│   ├── sovereign_main.ts        # Full stack demo
│   ├── sovereign_stack.ts       # Gateway + console + vaults + PQC
│   ├── pqc_client_service.ts    # PQC client
│   ├── pqc_server_service.ts    # PQC server
│   ├── chaos/                   # Entropy engine, timing veil
│   ├── imperial/                # 7-layer cipher stack
│   ├── occult/                  # Aureon planetary veil
│   ├── gateway/                 # API gateway + RBAC
│   ├── console/                 # MFA admin console
│   ├── data/                    # DB field vault
│   ├── vault/                   # File vault
│   ├── crypto/                  # PQC, GCM, QS-CA
│   ├── security/                # Replay, rate limit, allowlist
│   └── tests/                   # 38 tests incl. live integration
├── deploy/
│   ├── waf/                     # nginx + Cloudflare rules
│   └── helm/nomad-cyber/        # Kubernetes chart
└── vendor/oqs-javascript/       # OQS stub (replace for prod)
```

---

## ◇ Deployment

### Edge WAF

```bash
# nginx — see deploy/waf/nginx-waf.conf
# Cloudflare — import deploy/waf/cloudflare-rules.json
```

### Kubernetes

```bash
helm install nomad deploy/helm/nomad-cyber/
```

### Sidecar (per-connection PQC tunnel)

```bash
npm run sidecar
# Listens :9443, tunnels to PQC upstream via isolated sessions
```

---

## ◇ Built By

<div align="center">

### **#HouseOfAsher** Research & Developers

### **Aureon Software** · ZANOEM · **+ Cursor**

**ZorakCorp** · [github.com/ZorakCorp/nomad_cyber_algorithm](https://github.com/ZorakCorp/nomad_cyber_algorithm)

<sub>MIT License · Nomad Cyber Algorithm v1.1.0</sub>

</div>
