# Incident Response Plan

NIST SP 800-61 aligned runbook for Nomad Cyber Algorithm.

## Severity Classification

| Level | Criteria | Response Time |
|-------|----------|---------------|
| P0 | Active key compromise, data exfiltration | Immediate |
| P1 | Fuzz crash, chain break in audit log | 1 hour |
| P2 | High SAST finding, rate limit bypass | 4 hours |
| P3 | Medium vulnerability report | 72 hours |

## Detection Triggers

- `AuditLog.verifyChain()` failure on startup
- TPM attestation PCR mismatch
- HSM connection loss in production
- Fuzz pipeline failure (`.github/workflows/fuzz.yml`)
- SAST High/Critical finding blocked in CI
- Distributed rate limit spike > 10x baseline

## Containment

1. **Isolate node:** Remove from load balancer; revoke client allowlist entry
2. **Revoke sessions:** Flush Redis session store; rotate `NOMAD_SESSION_MASTER_KEY`
3. **HSM lock:** Disable PKCS#11 slot via vendor console
4. **Preserve evidence:** Copy audit JSONL + CT log before any restart

## Evidence Collection

```bash
# Audit chain verification
node -e "const {AuditLog}=require('./dist/ops/audit_log'); const a=new AuditLog('./evidence'); console.log(a.verifyChain());"

# CT log chain
node -e "const {CertificateTransparencyLog}=require('./dist/crypto/ct_log'); const c=new CertificateTransparencyLog('./evidence'); console.log(c.verifyChain());"
```

## Communication Chain

1. On-call engineer → Security lead (15 min)
2. Security lead → Engineering director (30 min)
3. Director → Legal/compliance for regulatory notification (P0 only, within 72h GDPR / state breach laws)

## Recovery

1. Rotate server KEM/SIG keys via console `/console/rotate`
2. Re-issue all QS-CA certificates (see `docs/key_revocation_runbook.md`)
3. Re-establish TPM baseline after firmware verification
4. Post-incident review within 5 business days

## Tabletop Exercise

Conduct annually. Scenario: compromised QS-CA root + audit chain tamper attempt.
