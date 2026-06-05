/**
 * VitalGuard — every protected operation consults the organism before executing.
 * If any organ is critical, the entire body refuses to function.
 */

export interface OrganismVitalsReport {
    vital: boolean;
    pulseGeneration: number;
    organismFingerprint: string;
    lockdownReason: string | null;
    organs: Array<{
        id: string;
        name: string;
        state: string;
        role: string;
        dependsOn: string[];
    }>;
    doctrine: string;
}

export interface VitalGuard {
    isVital(): boolean;
    requireVital(operation: string): void;
    getPulseGeneration(): number;
    getFingerprint(): string;
    getVitalsReport(): OrganismVitalsReport;
}

export class LockdownGuard implements VitalGuard {
    constructor(private reason: string) {}

    isVital(): boolean {
        return false;
    }

    requireVital(operation: string): void {
        throw new Error(`ORGANISM_LOCKDOWN: ${operation} blocked — ${this.reason}`);
    }

    getPulseGeneration(): number {
        return 0;
    }

    getFingerprint(): string {
        return 'lockdown';
    }

    getVitalsReport(): OrganismVitalsReport {
        return {
            vital: false,
            pulseGeneration: 0,
            organismFingerprint: 'lockdown',
            lockdownReason: this.reason,
            organs: [],
            doctrine: 'All organs must be vital simultaneously. Partial compromise is total failure.',
        };
    }
}

/** Dev/test pass-through when organism integration is not wired. */
export class PermissiveGuard implements VitalGuard {
    private generation = 1;
    private fingerprint = 'dev-permissive';

    isVital(): boolean {
        return true;
    }

    requireVital(_operation: string): void {}

    getPulseGeneration(): number {
        return this.generation;
    }

    getFingerprint(): string {
        return this.fingerprint;
    }

    getVitalsReport(): OrganismVitalsReport {
        return {
            vital: true,
            pulseGeneration: this.generation,
            organismFingerprint: this.fingerprint,
            lockdownReason: null,
            organs: [],
            doctrine: 'Dev mode — organism guards dormant.',
        };
    }
}
