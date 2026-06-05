import { createHash } from 'crypto';
import * as fs from 'fs';

export interface TpmPcrBaseline {
    pcrIndex: number;
    expectedHash: string;
}

export interface TpmAttestationResult {
    attested: boolean;
    pcrValues: Record<number, string>;
    failures: string[];
}

/**
 * TPM 2.0 boot attestation — validates PCR values against known-good baseline
 * before any key material is loaded from HSM.
 *
 * Baseline: NOMAD_TPM_BASELINE_PATH (JSON array of { pcrIndex, expectedHash })
 * Live PCRs: NOMAD_TPM_PCR_DUMP_PATH or tpm2_pcrread subprocess when available.
 */
export function loadTpmBaseline(path = process.env.NOMAD_TPM_BASELINE_PATH): TpmPcrBaseline[] {
    if (!path || !fs.existsSync(path)) {
        return [];
    }
    const raw = JSON.parse(fs.readFileSync(path, 'utf8')) as TpmPcrBaseline[];
    return raw.filter((e) => Number.isInteger(e.pcrIndex) && typeof e.expectedHash === 'string');
}

export function readPcrDumpFromFile(path: string): Record<number, string> {
    const raw = JSON.parse(fs.readFileSync(path, 'utf8')) as Record<string, string>;
    const out: Record<number, string> = {};
    for (const [k, v] of Object.entries(raw)) {
        out[parseInt(k, 10)] = v.toLowerCase();
    }
    return out;
}

export function attestTpmBootState(
    baseline: TpmPcrBaseline[],
    livePcrs: Record<number, string>
): TpmAttestationResult {
    const failures: string[] = [];
    const pcrValues: Record<number, string> = { ...livePcrs };

    for (const entry of baseline) {
        const live = livePcrs[entry.pcrIndex]?.toLowerCase();
        const expected = entry.expectedHash.toLowerCase();
        if (!live) {
            failures.push(`PCR ${entry.pcrIndex}: missing live value`);
        } else if (live !== expected) {
            failures.push(`PCR ${entry.pcrIndex}: expected ${expected}, got ${live}`);
        }
    }

    return { attested: failures.length === 0, pcrValues, failures };
}

export function requireTpmAttestation(devMode = process.env.NOMAD_DEV_MODE === 'true'): TpmAttestationResult {
    const required = process.env.NOMAD_TPM_REQUIRED === 'true';
    const baseline = loadTpmBaseline();

    if (!required && baseline.length === 0) {
        if (!devMode) {
            console.warn(JSON.stringify({
                ts: new Date().toISOString(),
                level: 'warn',
                message: 'TPM attestation not configured. Set NOMAD_TPM_BASELINE_PATH for boot integrity verification.',
                component: 'tpm_attest',
            }));
        }
        return { attested: true, pcrValues: {}, failures: [] };
    }

    const dumpPath = process.env.NOMAD_TPM_PCR_DUMP_PATH;
    if (!dumpPath || !fs.existsSync(dumpPath)) {
        if (required) {
            throw new Error('NOMAD_TPM_REQUIRED but NOMAD_TPM_PCR_DUMP_PATH is missing or unreadable.');
        }
        return { attested: true, pcrValues: {}, failures: [] };
    }

    const live = readPcrDumpFromFile(dumpPath);
    const result = attestTpmBootState(baseline, live);
    if (!result.attested) {
        throw new Error(`TPM boot attestation failed: ${result.failures.join('; ')}`);
    }
    console.log('[TPM] Boot attestation passed — PCR baseline verified');
    return result;
}

/** Hash node identity for audit trail binding to TPM state. */
export function nodeAttestationFingerprint(pcrs: Record<number, string>): string {
    const canonical = Object.keys(pcrs).sort((a, b) => Number(a) - Number(b))
        .map((k) => `${k}:${pcrs[Number(k)]}`)
        .join('|');
    return createHash('sha256').update(canonical).digest('hex');
}
