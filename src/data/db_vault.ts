import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'crypto';
import * as fs from 'fs';
import { CRYPTO_CONSTANTS } from '../crypto/crypto_service';
import { AuditLog } from '../ops/audit_log';

export interface DbVaultOptions {
    keyPath?: string | null;
    audit: AuditLog;
}

/**
 * Field-level DB encryption — sensitive columns never stored in plaintext.
 */
export class DbVault {
    private masterKey: Buffer;

    constructor(private options: DbVaultOptions) {
        if (options.keyPath && fs.existsSync(options.keyPath)) {
            this.masterKey = Buffer.from(fs.readFileSync(options.keyPath, 'utf8').trim(), 'hex');
        } else {
            this.masterKey = randomBytes(32);
        }
        if (this.masterKey.length !== 32) {
            throw new Error('DB vault key must be 32 bytes (64 hex chars).');
        }
    }

    encryptField(table: string, column: string, value: string, tenantId: string): string {
        const iv = randomBytes(CRYPTO_CONSTANTS.GCM_IV_BYTES);
        const aad = createHmac('sha256', this.masterKey)
            .update(`${table}:${column}:${tenantId}`)
            .digest();
        const cipher = createCipheriv('aes-256-gcm', this.masterKey, iv);
        cipher.setAAD(aad);
        const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();
        const bundle = Buffer.concat([iv, tag, ciphertext]);
        this.options.audit.record('message_encrypted', { detail: `db:${table}.${column}` });
        return bundle.toString('base64');
    }

    decryptField(table: string, column: string, sealed: string, tenantId: string): string {
        const raw = Buffer.from(sealed, 'base64');
        const iv = raw.subarray(0, CRYPTO_CONSTANTS.GCM_IV_BYTES);
        const tag = raw.subarray(CRYPTO_CONSTANTS.GCM_IV_BYTES, CRYPTO_CONSTANTS.GCM_IV_BYTES + 16);
        const ciphertext = raw.subarray(CRYPTO_CONSTANTS.GCM_IV_BYTES + 16);
        const aad = createHmac('sha256', this.masterKey)
            .update(`${table}:${column}:${tenantId}`)
            .digest();
        const decipher = createDecipheriv('aes-256-gcm', this.masterKey, iv);
        decipher.setAAD(aad);
        decipher.setAuthTag(tag);
        const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        this.options.audit.record('message_decrypted', { detail: `db:${table}.${column}` });
        return plaintext.toString('utf8');
    }

    auditQuery(actor: string, sql: string, tenantId: string): void {
        const fingerprint = createHmac('sha256', this.masterKey)
            .update(sql)
            .digest('hex')
            .slice(0, 16);
        this.options.audit.record('message_decrypted', {
            detail: `db-query:${actor}:${tenantId}:${fingerprint}`,
        });
    }

    exportKeyHint(): string {
        return createHmac('sha256', this.masterKey).update('hint').digest('hex').slice(0, 12);
    }
}
