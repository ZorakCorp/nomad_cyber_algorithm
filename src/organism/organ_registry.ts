/**
 * Sovereign Organism — organ registry and dependency graph.
 * Every security subsystem is an organ; no organ operates in isolation.
 * An attacker must compromise ALL organs simultaneously to breach the stack.
 */

export type OrganId =
    | 'crypto_core'      // liboqs integrity — the heart
    | 'supply_spleen'    // SBOM / dependency integrity
    | 'audit_immune'     // chained HMAC audit log
    | 'tpm_skeletal'     // TPM boot attestation — structural integrity
    | 'hsm_heart'        // PKCS#11 HSM — key material never leaves hardware
    | 'ca_liver'         // QS-CA + certificate transparency log
    | 'console_brain'    // Argon2id + WebAuthn + ZK sovereign auth
    | 'rate_limit_nerves'// distributed rate limiting (Redis)
    | 'pqc_lungs'        // PQC handshake mesh
    | 'gateway_skin'     // API gateway perimeter
    | 'vault_marrow';    // DB + file vault encryption

export type OrganState = 'vital' | 'dormant' | 'critical' | 'pending';

export interface OrganStatus {
    id: OrganId;
    name: string;
    role: string;
    state: OrganState;
    dependsOn: OrganId[];
    lastPulse: string;
    detail?: string;
}

/** Directed acyclic graph — organs activate only after dependencies are vital/dormant. */
export const ORGAN_DEPENDENCIES: Record<OrganId, OrganId[]> = {
    crypto_core: [],
    supply_spleen: ['crypto_core'],
    audit_immune: ['crypto_core'],
    tpm_skeletal: ['crypto_core'],
    hsm_heart: ['crypto_core', 'tpm_skeletal', 'audit_immune'],
    ca_liver: ['crypto_core', 'audit_immune', 'hsm_heart'],
    console_brain: ['audit_immune', 'ca_liver'],
    rate_limit_nerves: ['audit_immune'],
    pqc_lungs: ['hsm_heart', 'ca_liver', 'audit_immune', 'crypto_core'],
    gateway_skin: ['console_brain', 'pqc_lungs', 'audit_immune', 'rate_limit_nerves'],
    vault_marrow: ['tpm_skeletal', 'hsm_heart', 'audit_immune', 'crypto_core'],
};

export const ORGAN_META: Record<OrganId, { name: string; role: string }> = {
    crypto_core: { name: 'Crypto Core', role: 'PQC algorithm integrity (liboqs self-test)' },
    supply_spleen: { name: 'Supply Spleen', role: 'SBOM hash verification' },
    audit_immune: { name: 'Audit Immune', role: 'Tamper-evident chained audit log' },
    tpm_skeletal: { name: 'TPM Skeletal', role: 'Boot attestation PCR baseline' },
    hsm_heart: { name: 'HSM Heart', role: 'Non-extractable hardware key storage' },
    ca_liver: { name: 'CA Liver', role: 'QS-CA certificate transparency chain' },
    console_brain: { name: 'Console Brain', role: 'Argon2id + WebAuthn + ZK sovereign proof' },
    rate_limit_nerves: { name: 'Rate Nerves', role: 'Distributed connection/handshake limits' },
    pqc_lungs: { name: 'PQC Lungs', role: 'Kyber/Dilithium secure channel respiration' },
    gateway_skin: { name: 'Gateway Skin', role: 'RBAC perimeter and session auth' },
    vault_marrow: { name: 'Vault Marrow', role: 'Encrypted data-at-rest stem cells' },
};

/** Topological activation order — parents before children. */
export function organActivationOrder(): OrganId[] {
    const visited = new Set<OrganId>();
    const order: OrganId[] = [];
    const visit = (id: OrganId): void => {
        if (visited.has(id)) return;
        for (const dep of ORGAN_DEPENDENCIES[id]) visit(dep);
        visited.add(id);
        order.push(id);
    };
    const all = Object.keys(ORGAN_DEPENDENCIES) as OrganId[];
    for (const id of all) visit(id);
    return order;
}

export function dependenciesSatisfied(
    organId: OrganId,
    statuses: Map<OrganId, OrganStatus>
): boolean {
    return ORGAN_DEPENDENCIES[organId].every((dep) => {
        const s = statuses.get(dep);
        return s?.state === 'vital' || s?.state === 'dormant';
    });
}
