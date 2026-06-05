import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'crypto';
import * as fs from 'fs';
import { CRYPTO_CONSTANTS } from '../crypto/crypto_service';
import { AuditLog } from '../ops/audit_log';
import { StructuredLogger } from '../ops/logger';
import { VitalGuard } from '../organism/vital_guard';

export interface DbVaultOptions {
    keyPath?: string | null;
    audit: AuditLog;
    devMode?: boolean;
    logger?: StructuredLogger;
    vitalGuard?: VitalGuard;
}

function isProductionMode(): boolean {
    return process.env.NODE_ENV === 'production' || process.env.NOMAD_DEV_MODE !== 'true';
}

function parseKeyHex(raw: string, source: string): Buffer {
    const trimmed = raw.trim();
    if (!/^[0-9a-fA-F]{64}$/.test(trimmed)) {
        throw new Error(
            `${source} must contain exactly 64 hexadecimal characters (32 bytes). Got ${trimmed.length} chars.`
        );
    }
    return Buffer.from(trimmed, 'hex');
}

function resolveMasterKey(
    keyPath: string | null,
    devMode: boolean,
    logger?: StructuredLogger
): Buffer {
    if (keyPath && fs.existsSync(keyPath)) {
        const raw = fs.readFileSync(keyPath, 'utf8');
        return parseKeyHex(raw, `DB vault key file at ${keyPath}`);
    }

    if (isProductionMode() && !devMode) {
        throw new Error(
            'DB vault key path is required in production. Set NOMAD_DB_VAULT_KEY_PATH to a persistent 32-byte hex key file.'
        );
    }

    if (keyPath && !fs.existsSync(keyPath)) {
        throw new Error(`NOMAD_DB_VAULT_KEY_PATH points to missing file: ${keyPath}`);
    }

    const warning =
        'DB vault using ephemeral key — all encrypted data will be unrecoverable after restart. Set NOMAD_DB_VAULT_KEY_PATH for persistence.';
    if (logger) {
        logger.warn(warning, { component: 'db_vault', level: 'warn' });
    } else {
        console.warn(JSON.stringify({ ts: new Date().toISOString(), level: 'warn', message: warning, component: 'db_vault' }));
    }
    return randomBytes(32);
}

/**
 * Field-level DB encryption — sensitive columns never stored in plaintext.
 */
export class DbVault {
    private masterKey: Buffer;

    constructor(private options: DbVaultOptions) {
        const devMode = options.devMode ?? process.env.NOMAD_DEV_MODE === 'true';
        this.masterKey = resolveMasterKey(options.keyPath ?? null, devMode, options.logger);
    }

    static generateKeyFile(filePath: string, logger?: StructuredLogger): void {
        const keyHex = randomBytes(32).toString('hex');
        fs.writeFileSync(filePath, `${keyHex}\n`, { encoding: 'utf8', mode: 0o600 });
        const msg = `DB vault key written to ${filePath} (mode 0o600). Set NOMAD_DB_VAULT_KEY_PATH=${filePath}`;
        if (logger) {
            logger.info(msg, { component: 'db_vault' });
        } else {
            console.log(`[DB VAULT] ${msg}`);
        }
    }

    static fromEnv(audit: AuditLog, logger?: StructuredLogger, devMode = process.env.NOMAD_DEV_MODE === 'true'): DbVault {
        return new DbVault({
            keyPath: process.env.NOMAD_DB_VAULT_KEY_PATH?.trim() ?? null,
            audit,
            devMode,
            logger,
        });
    }

    encryptField(table: string, column: string, value: string, tenantId: string): string {
        this.options.vitalGuard?.requireVital(`db_vault.encrypt:${table}.${column}`);
        const iv = randomBytes(CRYPTO_CONSTANTS.GCM_IV_BYTES);
        const binding = this.options.vitalGuard?.getFingerprint() ?? 'unbound';
        const aad = createHmac('sha256', this.masterKey)
            .update(`${table}:${column}:${tenantId}:${binding}`)
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
        this.options.vitalGuard?.requireVital(`db_vault.decrypt:${table}.${column}`);
        const raw = Buffer.from(sealed, 'base64');
        const iv = raw.subarray(0, CRYPTO_CONSTANTS.GCM_IV_BYTES);
        const tag = raw.subarray(CRYPTO_CONSTANTS.GCM_IV_BYTES, CRYPTO_CONSTANTS.GCM_IV_BYTES + 16);
        const ciphertext = raw.subarray(CRYPTO_CONSTANTS.GCM_IV_BYTES + 16);
        const binding = this.options.vitalGuard?.getFingerprint() ?? 'unbound';
        const aad = createHmac('sha256', this.masterKey)
            .update(`${table}:${column}:${tenantId}:${binding}`)
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
}
