# QS-CA Root Key Revocation Runbook

## When to Execute

- Confirmed compromise of QS-CA root private key or HSM slot
- Shamir threshold custodians report share exposure
- Third-party audit finds critical flaw in signing path

## Prerequisites

- M-of-N custodian shares for new root ceremony (`scripts/key_ceremony.ts`)
- Air-gap workstation for new root generation
- Updated TPM baseline for all nodes

## Procedure

### Phase 1 — Revoke (0–30 min)

1. Set `NOMAD_QS_CA_REVOKED=true` on all nodes (emergency config)
2. OCSP responder: `ocsp.revoke()` for every active certificate
3. Block new handshakes at gateway (maintenance mode)
4. Record incident in audit log with correlation ID

### Phase 2 — New Root (30 min – 4 hr)

1. Run key ceremony: `npx ts-node scripts/key_ceremony.ts --threshold 3 --shares 5 --custodians ./custodians.json`
2. Destroy old HSM keys per vendor procedure
3. Load new root public key: `NOMAD_QS_CA_ROOT_PATH`
4. Verify CT log genesis entry

### Phase 3 — Re-issue (4–24 hr)

1. For each registered client: issue new Dilithium certificate
2. Append each issuance to CT log
3. Distribute air-gap bundles to operators
4. Update client pinned roots

### Phase 4 — Vault Migration

1. Run `node dist/scripts/migrate_vault_suite.js` per `docs/algorithm_migration.md`
2. Verify decrypt round-trip on sample records
3. Delete old vault key files after confirmation

### Phase 5 — Resume

1. Clear `NOMAD_QS_CA_REVOKED`
2. Re-enable gateway traffic
3. Monitor handshake success rate for 24 hours

## Verification Checklist

- [ ] All old certificates return OCSP `revoked`
- [ ] CT log `verifyChain()` passes
- [ ] Audit log `verifyChain()` passes
- [ ] Client handshake succeeds with new root pin
- [ ] No nodes running old root public key
