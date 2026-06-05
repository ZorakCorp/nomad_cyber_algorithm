import { createHmac, randomBytes } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

export type AuditEventType =
    | 'handshake_started'
    | 'handshake_succeeded'
    | 'handshake_failed'
    | 'session_resumed'
    | 'client_rejected_allowlist'
    | 'rate_limit_exceeded'
    | 'replay_detected'
    | 'message_encrypted'
    | 'message_decrypted'
    | 'connection_closed'
    | 'key_rotated';

export interface AuditEvent {
    id: string;
    ts: string;
    type: AuditEventType;
    correlationId?: string;
    peer?: string;
    detail?: string;
    prevEntryId: string;
    entryMac: string;
}

export class AuditLog {
    private entries: AuditEvent[] = [];
    private filePath: string | null;
    private chainKey: Buffer;

    constructor(logDir: string | null = process.env.NOMAD_AUDIT_LOG_DIR ?? null) {
        this.chainKey = process.env.NOMAD_AUDIT_CHAIN_KEY
            ? Buffer.from(process.env.NOMAD_AUDIT_CHAIN_KEY, 'hex')
            : randomBytes(32);
        this.filePath = logDir ? path.join(logDir, 'nomad-audit.jsonl') : null;
        if (this.filePath) {
            fs.mkdirSync(logDir!, { recursive: true });
            this.loadFromDisk();
        }
    }

    private loadFromDisk(): void {
        if (!this.filePath || !fs.existsSync(this.filePath)) return;
        const lines = fs.readFileSync(this.filePath, 'utf8').split('\n').filter(Boolean);
        for (const line of lines) {
            try {
                const event = JSON.parse(line) as AuditEvent;
                this.entries.push(event);
            } catch {
                // skip corrupt lines — verifyChain will detect gaps
            }
        }
    }

    private signEntry(event: Omit<AuditEvent, 'entryMac'>): string {
        const prevId = event.prevEntryId || 'GENESIS';
        const payload = `${event.id}|${event.ts}|${event.type}|${prevId}|${event.detail ?? ''}`;
        return createHmac('sha256', this.chainKey).update(payload).digest('hex');
    }

    record(type: AuditEventType, fields: Omit<AuditEvent, 'id' | 'ts' | 'type' | 'prevEntryId' | 'entryMac'> = {}): void {
        const prev = this.entries[this.entries.length - 1];
        const base: Omit<AuditEvent, 'entryMac'> = {
            id: `${Date.now()}-${randomBytes(8).toString('hex')}`,
            ts: new Date().toISOString(),
            type,
            prevEntryId: prev?.id ?? '',
            ...fields,
        };
        const event: AuditEvent = { ...base, entryMac: this.signEntry(base) };
        this.entries.push(event);
        if (this.filePath) {
            fs.appendFileSync(this.filePath, JSON.stringify(event) + '\n', 'utf8');
        }
    }

    verifyChain(): { valid: boolean; errors: string[] } {
        const errors: string[] = [];
        let prevId = '';
        for (const entry of this.entries) {
            const { entryMac: _mac, ...base } = entry;
            const expectedMac = this.signEntry(base);
            if (entry.entryMac !== expectedMac) {
                errors.push(`Entry ${entry.id}: HMAC mismatch (tamper detected)`);
            }
            if (entry.prevEntryId !== prevId) {
                errors.push(`Entry ${entry.id}: chain broken (expected prev ${prevId}, got ${entry.prevEntryId})`);
            }
            prevId = entry.id;
        }
        return { valid: errors.length === 0, errors };
    }

    query(limit = 100): AuditEvent[] {
        return this.entries.slice(-limit);
    }
}
