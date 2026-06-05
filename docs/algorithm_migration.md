# Cryptographic Algorithm Agility — Migration Plan

## Supported Suites

| Suite ID | KEM | SIG | Production |
|----------|-----|-----|------------|
| `kyber1024_dilithium5` | Kyber-1024 | Dilithium-5 | **Default (prod)** |
| `kyber768_dilithium3` | Kyber-768 | Dilithium-3 | Dev/compatibility only |

## Migration Triggers

- NIST deprecation announcement for Kyber or Dilithium parameter set
- Cryptanalytic breakthrough affecting current suite
- Organizational policy upgrade to next NIST PQC standard

## Zero-Downtime Migration Procedure

### Stage 1 — Dual-stack (Week 1)

1. Deploy nodes with `NOMAD_ALGORITHM_SUITE=kyber1024_dilithium5` alongside existing fleet
2. Gateway accepts sessions from both suites during transition
3. QS-CA issues dual certificates (old + new suite public keys)

### Stage 2 — Session rotation (Week 2)

1. Set `NOMAD_SESSION_TTL_MS=300000` (5 min) to accelerate natural expiry
2. Force client reconnect with new suite handshake
3. Monitor `handshake_failed` audit events

### Stage 3 — Vault re-encryption (Week 3)

```bash
export NOMAD_MIGRATE_FROM=kyber768_dilithium3
export NOMAD_MIGRATE_TO=kyber1024_dilithium5
export NOMAD_VAULT_DIR=./nomad-vault
node dist/scripts/migrate_vault_suite.js
```

1. Run migration script in maintenance window
2. Verify sample decrypt on `migrated-*.enc` files
3. Atomically swap vault index

### Stage 4 — Certificate re-issue (Week 4)

1. Revoke old-suite certificates via OCSP
2. Issue new-suite certificates only
3. Update CT log; verify chain integrity

### Stage 5 — Decommission old suite

1. Set production guard: reject `kyber768_dilithium3` (already enforced in `config.ts`)
2. Remove dual-stack gateway routes
3. Archive old QS-CA root in air-gap storage

## Rollback

If migration fails:

1. Restore vault from pre-migration snapshot
2. Revert `NOMAD_ALGORITHM_SUITE` on all nodes
3. Re-issue certificates under previous root
4. Document failure in post-incident review

## Testing

Before production migration:

```bash
NOMAD_DEV_MODE=true npm test
node dist/scripts/migrate_vault_suite.js  # dry-run on staging vault copy
```

## Code References

- Suite selection: `src/config.ts`
- Migration executor: `src/scripts/migrate_vault_suite.ts`
- Algorithm definitions: `src/crypto/algorithm_suite.ts`
