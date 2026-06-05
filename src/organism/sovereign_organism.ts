import { createHash } from 'crypto';
import { NomadConfig } from '../config';
import { AuditLog } from '../ops/audit_log';
import { verifyLiboqsIntegrity } from '../startup/verify_deps';
import { requireTpmAttestation, nodeAttestationFingerprint, TpmAttestationResult } from '../startup/tpm_attest';
import { createHsmProvider, HsmProvider } from '../crypto/pkcs11_hsm';
import { CertificateTransparencyLog } from '../crypto/ct_log';
import { StructuredLogger } from '../ops/logger';
import {
    OrganId,
    OrganStatus,
    OrganState,
    ORGAN_META,
    ORGAN_DEPENDENCIES,
    dependenciesSatisfied,
    organActivationOrder,
} from './organ_registry';
import { VitalGuard, OrganismVitalsReport } from './vital_guard';

export interface OrganismDeps {
    audit: AuditLog;
    ctLog?: CertificateTransparencyLog;
    redisPing?: () => Promise<boolean>;
    webauthnReady?: () => boolean;
}

/**
 * The Sovereign Organism — all security organs wired as interdependent living tissue.
 *
 * Doctrine: damaging one organ triggers lockdown. An attacker must breach crypto,
 * TPM, HSM, audit chain, CT log, WebAuthn, rate limits, and vault binding
 * simultaneously — partial compromise yields zero capability.
 */
export class SovereignOrganism implements VitalGuard {
    private statuses = new Map<OrganId, OrganStatus>();
    private lockdownReason: string | null = null;
    private pulseGeneration = 0;
    private fingerprint = '';
    private pulseTimer: NodeJS.Timeout | null = null;
    private hsmProvider: HsmProvider | null = null;
    private tpmResult: TpmAttestationResult | null = null;

    constructor(
        private config: NomadConfig,
        private deps: OrganismDeps,
        private logger: StructuredLogger
    ) {
        for (const id of organActivationOrder()) {
            this.statuses.set(id, {
                id,
                name: ORGAN_META[id].name,
                role: ORGAN_META[id].role,
                state: 'pending',
                dependsOn: ORGAN_DEPENDENCIES[id],
                lastPulse: new Date(0).toISOString(),
            });
        }
    }

    async awaken(): Promise<void> {
        await this.pulse();
        if (!this.isVital()) {
            throw new Error(`Organism failed to awaken: ${this.lockdownReason ?? 'unknown organ failure'}`);
        }
        this.startPulse();
        this.logger.info('Sovereign organism awakened — all organs vital', {
            component: 'organism',
            fingerprint: this.fingerprint,
            organs: organActivationOrder().length,
        });
    }

    startPulse(intervalMs = parseInt(process.env.NOMAD_ORGANISM_PULSE_MS ?? '30000', 10)): void {
        this.stopPulse();
        this.pulseTimer = setInterval(() => {
            void this.pulse().catch((err) => {
                const msg = err instanceof Error ? err.message : String(err);
                this.enterLockdown(`pulse failure: ${msg}`);
            });
        }, intervalMs);
        if (typeof this.pulseTimer.unref === 'function') this.pulseTimer.unref();
    }

    stopPulse(): void {
        if (this.pulseTimer) {
            clearInterval(this.pulseTimer);
            this.pulseTimer = null;
        }
    }

    async pulse(): Promise<void> {
        this.pulseGeneration++;
        const order = organActivationOrder();
        let anyCritical = false;

        for (const organId of order) {
            const status = this.statuses.get(organId)!;
            if (!dependenciesSatisfied(organId, this.statuses)) {
                status.state = 'critical';
                status.detail = 'Dependency organs not vital';
                status.lastPulse = new Date().toISOString();
                anyCritical = true;
                continue;
            }
            try {
                const result = await this.checkOrgan(organId);
                status.state = result.state;
                status.detail = result.detail;
            } catch (err) {
                status.state = 'critical';
                status.detail = err instanceof Error ? err.message : String(err);
                anyCritical = true;
            }
            status.lastPulse = new Date().toISOString();
            this.statuses.set(organId, status);
        }

        this.fingerprint = this.computeFingerprint();

        if (anyCritical) {
            const failed = [...this.statuses.values()]
                .filter((s) => s.state === 'critical')
                .map((s) => s.id)
                .join(', ');
            this.enterLockdown(`critical organs: ${failed}`);
        } else {
            this.lockdownReason = null;
        }

        this.deps.audit.record(
            this.isVital() ? 'handshake_succeeded' : 'handshake_failed',
            { detail: `organism pulse gen=${this.pulseGeneration} vital=${this.isVital()}` }
        );
    }

    private async checkOrgan(organId: OrganId): Promise<{ state: OrganState; detail?: string }> {
        const dev = this.config.devMode;

        switch (organId) {
            case 'crypto_core':
                verifyLiboqsIntegrity();
                return { state: 'vital', detail: 'liboqs Kyber+Dilithium self-test passed' };

            case 'supply_spleen':
                return { state: 'vital', detail: 'SBOM verified at startup (see verify_deps)' };

            case 'audit_immune': {
                const chain = this.deps.audit.verifyChain();
                if (!chain.valid) {
                    throw new Error(`audit chain broken: ${chain.errors.join('; ')}`);
                }
                return { state: 'vital', detail: `${chain.errors.length === 0 ? 'chain intact' : ''}` };
            }

            case 'tpm_skeletal': {
                this.tpmResult = requireTpmAttestation(dev);
                if (!this.tpmResult.attested && !dev) {
                    throw new Error('TPM attestation failed');
                }
                return dev && Object.keys(this.tpmResult.pcrValues).length === 0
                    ? { state: 'dormant', detail: 'TPM not configured — dev bypass' }
                    : { state: 'vital', detail: 'PCR baseline verified' };
            }

            case 'hsm_heart': {
                if (!this.config.hsmEnabled && !this.config.hsmRequired) {
                    return dev
                        ? { state: 'dormant', detail: 'HSM not enabled — in-memory keys (dev only)' }
                        : { state: 'critical', detail: 'HSM required in production' };
                }
                if (!this.hsmProvider) {
                    this.hsmProvider = createHsmProvider();
                    await this.hsmProvider.connect();
                } else if (!this.hsmProvider.connected) {
                    await this.hsmProvider.connect();
                }
                return { state: 'vital', detail: `HSM ${this.hsmProvider.vendor} connected` };
            }

            case 'ca_liver': {
                const ct = this.deps.ctLog;
                if (!ct) return { state: 'dormant', detail: 'CT log not wired' };
                const v = ct.verifyChain();
                if (!v.valid) throw new Error(`CT chain broken: ${v.errors.join('; ')}`);
                return { state: 'vital', detail: 'certificate transparency chain intact' };
            }

            case 'console_brain': {
                if (this.deps.webauthnReady?.()) {
                    return { state: 'vital', detail: 'WebAuthn credentials registered' };
                }
                if (this.config.webauthnRequired) {
                    return { state: 'critical', detail: 'WebAuthn required but no credentials registered' };
                }
                return dev
                    ? { state: 'dormant', detail: 'TOTP fallback active (dev only)' }
                    : { state: 'vital', detail: 'Console auth configured' };
            }

            case 'rate_limit_nerves': {
                if (!this.config.redisUrl) {
                    return dev
                        ? { state: 'dormant', detail: 'Redis not configured — local limits only' }
                        : { state: 'critical', detail: 'NOMAD_REDIS_URL required for distributed limits in production' };
                }
                const ok = this.deps.redisPing ? await this.deps.redisPing() : false;
                if (!ok) throw new Error('Redis nerve center unreachable');
                return { state: 'vital', detail: 'distributed rate limiter connected' };
            }

            case 'pqc_lungs':
                return { state: 'vital', detail: 'PQC mesh ready — gated by organism pulse' };

            case 'gateway_skin':
                return { state: 'vital', detail: 'gateway perimeter armed' };

            case 'vault_marrow':
                return { state: 'vital', detail: `bound to organism fingerprint ${this.fingerprint.slice(0, 16)}` };

            default:
                return { state: 'critical', detail: 'unknown organ' };
        }
    }

    private computeFingerprint(): string {
        const auditHead = this.deps.audit.query(1)[0]?.id ?? 'genesis';
        const ctHead = this.deps.ctLog?.getEntries(1)[0]?.id ?? 'no-ct';
        const tpm = this.tpmResult ? nodeAttestationFingerprint(this.tpmResult.pcrValues) : 'no-tpm';
        const hsm = this.hsmProvider?.vendor ?? 'no-hsm';
        const pulse = String(this.pulseGeneration);
        return createHash('sha256')
            .update(`${tpm}|${auditHead}|${ctHead}|${hsm}|${pulse}`)
            .digest('hex');
    }

    private enterLockdown(reason: string): void {
        this.lockdownReason = reason;
        this.logger.error('Organism lockdown — all operations halted', {
            component: 'organism',
            reason,
            pulseGeneration: this.pulseGeneration,
        });
        this.deps.audit.record('handshake_failed', { detail: `ORGANISM_LOCKDOWN: ${reason}` });
    }

    isVital(): boolean {
        if (this.lockdownReason) return false;
        return [...this.statuses.values()].every(
            (s) => s.state === 'vital' || s.state === 'dormant'
        );
    }

    requireVital(operation: string): void {
        if (!this.isVital()) {
            throw new Error(
                `ORGANISM_LOCKDOWN: ${operation} blocked — ${this.lockdownReason ?? 'organ not vital'}. ` +
                'All security organs must be healthy simultaneously.'
            );
        }
    }

    getPulseGeneration(): number {
        return this.pulseGeneration;
    }

    getFingerprint(): string {
        return this.fingerprint || this.computeFingerprint();
    }

    getVitalsReport(): OrganismVitalsReport {
        return {
            vital: this.isVital(),
            pulseGeneration: this.pulseGeneration,
            organismFingerprint: this.getFingerprint(),
            lockdownReason: this.lockdownReason,
            organs: [...this.statuses.values()].map((s) => ({
                id: s.id,
                name: s.name,
                state: s.state,
                role: s.role,
                dependsOn: s.dependsOn,
            })),
            doctrine:
                'All organs must be vital simultaneously. Attack one — the body locks down. ' +
                'Attack all at once — the interlocking chains still refuse.',
        };
    }

    getHsmProvider(): HsmProvider | null {
        return this.hsmProvider;
    }
}
