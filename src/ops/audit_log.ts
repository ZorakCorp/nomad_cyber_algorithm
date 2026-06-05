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
}

export class AuditLog {
    private entries: AuditEvent[] = [];
    private filePath: string | null;

    constructor(logDir: string | null = process.env.NOMAD_AUDIT_LOG_DIR ?? null) {
        this.filePath = logDir ? path.join(logDir, 'nomad-audit.jsonl') : null;
        if (this.filePath) {
            fs.mkdirSync(logDir!, { recursive: true });
        }
    }

    record(type: AuditEventType, fields: Omit<AuditEvent, 'id' | 'ts' | 'type'> = {}): void {
        const event: AuditEvent = {
            id: `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
            ts: new Date().toISOString(),
            type,
            ...fields,
        };
        this.entries.push(event);
        if (this.entries.length > 10_000) {
            this.entries.shift();
        }
        if (this.filePath) {
            fs.appendFileSync(this.filePath, JSON.stringify(event) + '\n', 'utf8');
        }
    }

    query(limit = 100): AuditEvent[] {
        return this.entries.slice(-limit);
    }
}
