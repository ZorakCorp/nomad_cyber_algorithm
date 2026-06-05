# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes         |

## Reporting a Vulnerability

Nomad Cyber Algorithm follows responsible disclosure per NIST and MITRE CVE guidelines.

**Contact:** security@zorakcorp.com  
**PGP Key:** [Download public key](https://github.com/ZorakCorp/nomad_cyber_algorithm/releases/download/security/nomad-security.asc)  
**Fingerprint:** `A1B2 C3D4 E5F6 7890 ABCD EF12 3456 7890 ABCD EF12`

### SLA

| Severity | Acknowledgement | Fix Window |
|----------|-----------------|------------|
| Critical | 24 hours        | 7 days     |
| High     | 72 hours        | 30 days    |
| Medium   | 7 days          | 90 days    |
| Low      | 14 days         | Best effort |

### Safe Harbour

Good-faith security research conducted in accordance with this policy will not be subject to legal action. Do not access data beyond what is necessary to demonstrate the vulnerability. Do not perform denial-of-service attacks against production systems.

## Scope

In scope: PQC handshake, QS-CA, console authentication, vault encryption, gateway RBAC, audit log integrity.

Out of scope: Third-party HSM firmware, cloud provider infrastructure, social engineering.
