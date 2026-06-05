import { CryptoService, EncryptedRecord } from './crypto_service';
import { ImperialCipherStack, ImperialCipherConfig } from '../imperial/imperial_cipher_stack';

export type RecordType = 'application' | 'heartbeat_ping' | 'heartbeat_pong' | 'close_notify';

export interface RecordPayload {
    recordType: RecordType;
    serviceId?: string;
    body: Buffer;
    imperialTimestamp?: number;
}

export class RecordLayer {
    private imperial: ImperialCipherStack | null = null;
    private correlationId: string | null = null;

    constructor(private crypto: CryptoService) {}

    setImperialChannel(masterKey: Buffer, correlationId: string, config: ImperialCipherConfig): void {
        this.correlationId = correlationId;
        if (config.enabled) {
            this.imperial = new ImperialCipherStack(masterKey, correlationId, config);
        }
    }

    serialize(payload: RecordPayload): Buffer {
        return Buffer.from(JSON.stringify({
            recordType: payload.recordType,
            serviceId: payload.serviceId ?? 'default',
            body: payload.body.toString('base64'),
            imperialTimestamp: payload.imperialTimestamp ?? Date.now(),
        }));
    }

    deserialize(raw: Buffer): RecordPayload {
        const parsed = JSON.parse(raw.toString('utf8')) as {
            recordType: RecordType;
            serviceId?: string;
            body: string;
            imperialTimestamp?: number;
        };
        return {
            recordType: parsed.recordType,
            serviceId: parsed.serviceId,
            body: Buffer.from(parsed.body, 'base64'),
            imperialTimestamp: parsed.imperialTimestamp,
        };
    }

    seal(aesKey: Buffer, payload: RecordPayload, sequence: number): EncryptedRecord {
        if (!this.correlationId) {
            throw new Error('RecordLayer missing correlationId');
        }
        const ts = payload.imperialTimestamp ?? Date.now();
        let serialized = this.serialize(payload);
        if (this.imperial) {
            serialized = this.imperial.encipher(serialized, ts, sequence);
        }
        return this.crypto.encrypt(aesKey, serialized, {
            correlationId: this.correlationId,
            sequence,
            recordType: payload.recordType,
        });
    }

    open(aesKey: Buffer, record: EncryptedRecord, imperialTimestamp?: number, recordType: RecordType = 'application'): RecordPayload {
        if (!this.correlationId) {
            throw new Error('RecordLayer missing correlationId');
        }
        let plaintext = this.crypto.decrypt(aesKey, record, {
            correlationId: this.correlationId,
            sequence: record.sequence,
            recordType,
        });
        if (this.imperial) {
            plaintext = this.imperial.decipher(plaintext, imperialTimestamp ?? Date.now(), record.sequence);
        }
        return this.deserialize(plaintext);
    }
}
