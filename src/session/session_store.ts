import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { CRYPTO_CONSTANTS } from '../crypto/crypto_service';
import { StructuredLogger } from '../ops/logger';

export interface SessionTicketPayload {
    correlationId: string;
    aesKeyHex: string;
    clientSigPublicKey: string;
    serverSigPublicKey: string;
    expiresAt: number;
}

function parseMasterKeyHex(raw: string): Buffer {
    const trimmed = raw.trim();
    if (!/^[0-9a-fA-F]{64}$/.test(trimmed)) {
        throw new Error('NOMAD_SESSION_MASTER_KEY must be exactly 64 hexadecimal characters (32 bytes).');
    }
    return Buffer.from(trimmed, 'hex');
}

function isDevRuntime(explicitDevMode?: boolean): boolean {
    if (explicitDevMode !== undefined) return explicitDevMode;
    return process.env.NOMAD_DEV_MODE === 'true';
}

export class SessionStore {
    private masterKey: Buffer;
    private consumedTickets = new Set<string>();

    constructor(masterSecret: Buffer) {
        if (masterSecret.length !== 32) {
            throw new Error('SessionStore master key must be 32 bytes.');
        }
        this.masterKey = masterSecret;
    }

    static generateKey(): string {
        const key = randomBytes(32).toString('hex');
        console.log(`[SESSION] Generated session master key. Set NOMAD_SESSION_MASTER_KEY=${key}`);
        return key;
    }

    static fromEnv(logger?: StructuredLogger, devMode?: boolean): SessionStore {
        const raw = process.env.NOMAD_SESSION_MASTER_KEY?.trim();
        if (raw) {
            return new SessionStore(parseMasterKeyHex(raw));
        }

        if (!isDevRuntime(devMode)) {
            throw new Error(
                'NOMAD_SESSION_MASTER_KEY is required in production. ' +
                'Run SessionStore.generateKey() to create a 64-char hex key and persist it.'
            );
        }

        const warning =
            'SessionStore using ephemeral master key — all session tickets invalidate on restart. Set NOMAD_SESSION_MASTER_KEY for persistence.';
        if (logger) {
            logger.warn(warning, { component: 'session_store' });
        } else {
            console.warn(JSON.stringify({ ts: new Date().toISOString(), level: 'warn', message: warning }));
        }
        return new SessionStore(randomBytes(32));
    }

    issue(
        correlationId: string,
        aesKey: Buffer,
        clientSigPublicKey: string,
        serverSigPublicKey: string,
        ttlMs: number
    ): string {
        const payload: SessionTicketPayload = {
            correlationId,
            aesKeyHex: aesKey.toString('hex'),
            clientSigPublicKey,
            serverSigPublicKey,
            expiresAt: Date.now() + ttlMs,
        };
        const plaintext = Buffer.from(JSON.stringify(payload));
        const iv = randomBytes(CRYPTO_CONSTANTS.GCM_IV_BYTES);
        const cipher = createCipheriv('aes-256-gcm', this.masterKey, iv);
        const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
        const authTag = cipher.getAuthTag();
        const bundle = Buffer.concat([iv, authTag, ciphertext]);
        const mac = createHmac('sha256', this.masterKey).update(bundle).digest();
        return Buffer.concat([mac, bundle]).toString('base64');
    }

    redeem(ticket: string, consume = true): SessionTicketPayload | null {
        try {
            if (this.consumedTickets.has(ticket)) {
                return null;
            }
            const raw = Buffer.from(ticket, 'base64');
            if (raw.length < 32) return null;
            const mac = raw.subarray(0, 32);
            const bundle = raw.subarray(32);
            const expectedMac = createHmac('sha256', this.masterKey).update(bundle).digest();
            if (mac.length !== expectedMac.length || !timingSafeEqual(mac, expectedMac)) {
                return null;
            }
            const iv = bundle.subarray(0, CRYPTO_CONSTANTS.GCM_IV_BYTES);
            const authTag = bundle.subarray(CRYPTO_CONSTANTS.GCM_IV_BYTES, CRYPTO_CONSTANTS.GCM_IV_BYTES + 16);
            const ciphertext = bundle.subarray(CRYPTO_CONSTANTS.GCM_IV_BYTES + 16);
            const decipher = createDecipheriv('aes-256-gcm', this.masterKey, iv);
            decipher.setAuthTag(authTag);
            const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
            const payload = JSON.parse(plaintext.toString('utf8')) as SessionTicketPayload;
            if (Date.now() > payload.expiresAt) {
                return null;
            }
            if (consume) {
                if (this.consumedTickets.size >= 50_000) {
                    const oldest = this.consumedTickets.values().next().value;
                    if (oldest) this.consumedTickets.delete(oldest);
                }
                this.consumedTickets.add(ticket);
            }
            return payload;
        } catch {
            return null;
        }
    }
}
