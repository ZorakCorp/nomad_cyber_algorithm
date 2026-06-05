import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'crypto';
import { CRYPTO_CONSTANTS } from '../crypto/crypto_service';

export interface SessionTicketPayload {
    correlationId: string;
    aesKeyHex: string;
    clientSigPublicKey: string;
    expiresAt: number;
}

export class SessionStore {
    private masterKey: Buffer;

    constructor(masterSecret?: Buffer) {
        this.masterKey = masterSecret ?? randomBytes(32);
    }

    issue(
        correlationId: string,
        aesKey: Buffer,
        clientSigPublicKey: string,
        ttlMs: number
    ): string {
        const payload: SessionTicketPayload = {
            correlationId,
            aesKeyHex: aesKey.toString('hex'),
            clientSigPublicKey,
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

    redeem(ticket: string): SessionTicketPayload | null {
        try {
            const raw = Buffer.from(ticket, 'base64');
            const mac = raw.subarray(0, 32);
            const bundle = raw.subarray(32);
            const expectedMac = createHmac('sha256', this.masterKey).update(bundle).digest();
            if (mac.compare(expectedMac) !== 0) {
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
            return payload;
        } catch {
            return null;
        }
    }
}
