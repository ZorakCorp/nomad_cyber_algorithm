import { createHash, createHmac, randomBytes } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { PQCertificate } from './qs_ca';
import { encodeBinary } from '../protocol';

export interface CtLogEntry {
    id: string;
    ts: string;
    certSubject: string;
    certFingerprint: string;
    dilithiumSignature: string;
    prevEntryId: string;
    entryMac: string;
}

export class CertificateTransparencyLog {
    private entries: CtLogEntry[] = [];
    private chainKey: Buffer;
    private filePath: string | null;

    constructor(logDir: string | null = process.env.NOMAD_CT_LOG_DIR ?? null) {
        this.chainKey = process.env.NOMAD_CT_LOG_CHAIN_KEY
            ? Buffer.from(process.env.NOMAD_CT_LOG_CHAIN_KEY, 'hex')
            : randomBytes(32);
        this.filePath = logDir ? path.join(logDir, 'nomad-ct-log.jsonl') : null;
        if (this.filePath) {
            fs.mkdirSync(logDir!, { recursive: true });
        }
    }

    private fingerprint(cert: PQCertificate): string {
        return createHash('sha256')
            .update(JSON.stringify({ subject: cert.subject, sig: cert.sigPublicKey, kem: cert.kemPublicKey }))
            .digest('hex');
    }

    private signEntry(entry: Omit<CtLogEntry, 'entryMac'>): string {
        const prevId = entry.prevEntryId || 'GENESIS';
        const payload = `${entry.id}|${entry.ts}|${entry.certFingerprint}|${prevId}`;
        return createHmac('sha256', this.chainKey).update(payload).digest('hex');
    }

    append(cert: PQCertificate, dilithiumSignature: Uint8Array): CtLogEntry {
        const prev = this.entries[this.entries.length - 1];
        const base: Omit<CtLogEntry, 'entryMac'> = {
            id: `${Date.now()}-${randomBytes(8).toString('hex')}`,
            ts: new Date().toISOString(),
            certSubject: cert.subject,
            certFingerprint: this.fingerprint(cert),
            dilithiumSignature: encodeBinary(dilithiumSignature),
            prevEntryId: prev?.id ?? '',
        };
        const entry: CtLogEntry = { ...base, entryMac: this.signEntry(base) };
        this.entries.push(entry);
        if (this.filePath) {
            fs.appendFileSync(this.filePath, JSON.stringify(entry) + '\n', 'utf8');
        }
        return entry;
    }

    verifyChain(): { valid: boolean; errors: string[] } {
        const errors: string[] = [];
        let prevId = '';
        for (const entry of this.entries) {
            const { entryMac: _mac, ...base } = entry;
            const expectedMac = this.signEntry(base);
            if (entry.entryMac !== expectedMac) {
                errors.push(`CT entry ${entry.id}: MAC mismatch`);
            }
            if (entry.prevEntryId !== prevId) {
                errors.push(`CT entry ${entry.id}: broken chain (expected prev ${prevId})`);
            }
            prevId = entry.id;
        }
        return { valid: errors.length === 0, errors };
    }

    getEntries(limit = 100): CtLogEntry[] {
        return this.entries.slice(-limit);
    }
}
