import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { CRYPTO_CONSTANTS } from '../crypto/crypto_service';
import { AuditLog } from '../ops/audit_log';
import { VitalGuard } from '../organism/vital_guard';

export type VirusScanFn = (data: Buffer, filename: string) => Promise<boolean>;

const defaultScan: VirusScanFn = async () => true;

export class FileVault {
    private masterKey: Buffer;

    constructor(
        private vaultDir: string,
        private audit: AuditLog,
        masterKey?: Buffer,
        private scanFn: VirusScanFn = defaultScan,
        private vitalGuard?: VitalGuard
    ) {
        fs.mkdirSync(vaultDir, { recursive: true });
        this.masterKey = masterKey ?? randomBytes(32);
    }

    async store(filename: string, data: Buffer, owner: string): Promise<string> {
        this.vitalGuard?.requireVital(`file_vault.store:${filename}`);
        const safeName = path.basename(filename).replace(/[^a-zA-Z0-9._-]/g, '_');
        if (!(await this.scanFn(data, safeName))) {
            this.audit.record('handshake_failed', { detail: `vault scan rejected: ${safeName}` });
            throw new Error('File rejected by virus scan hook.');
        }
        const objectId = randomBytes(12).toString('hex');
        const iv = randomBytes(CRYPTO_CONSTANTS.GCM_IV_BYTES);
        const binding = this.vitalGuard?.getFingerprint() ?? 'unbound';
        const aad = createHmac('sha256', this.masterKey).update(`${objectId}:${owner}:${binding}`).digest();
        const cipher = createCipheriv('aes-256-gcm', this.masterKey, iv);
        cipher.setAAD(aad);
        const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
        const tag = cipher.getAuthTag();
        const record = {
            objectId,
            owner,
            filename: safeName,
            iv: iv.toString('hex'),
            tag: tag.toString('hex'),
            ciphertext: ciphertext.toString('hex'),
            storedAt: new Date().toISOString(),
        };
        const outPath = path.join(this.vaultDir, `${objectId}.json`);
        fs.writeFileSync(outPath, JSON.stringify(record), 'utf8');
        this.audit.record('message_encrypted', { detail: `vault:${objectId}` });
        return objectId;
    }

    retrieve(objectId: string, owner: string): Buffer {
        this.vitalGuard?.requireVital(`file_vault.retrieve:${objectId}`);
        if (!/^[a-f0-9]{24}$/.test(objectId)) {
            throw new Error('Invalid vault object ID.');
        }
        const filePath = path.join(this.vaultDir, `${objectId}.json`);
        if (!fs.existsSync(filePath)) {
            throw new Error('Vault object not found.');
        }
        const record = JSON.parse(fs.readFileSync(filePath, 'utf8')) as {
            owner: string;
            iv: string;
            tag: string;
            ciphertext: string;
        };
        if (record.owner !== owner) {
            this.audit.record('client_rejected_allowlist', { detail: `vault owner mismatch: ${objectId}` });
            throw new Error('Vault access denied — owner mismatch.');
        }
        const iv = Buffer.from(record.iv, 'hex');
        const tag = Buffer.from(record.tag, 'hex');
        const ciphertext = Buffer.from(record.ciphertext, 'hex');
        const binding = this.vitalGuard?.getFingerprint() ?? 'unbound';
        const aad = createHmac('sha256', this.masterKey).update(`${objectId}:${owner}:${binding}`).digest();
        const decipher = createDecipheriv('aes-256-gcm', this.masterKey, iv);
        decipher.setAAD(aad);
        decipher.setAuthTag(tag);
        const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        this.audit.record('message_decrypted', { detail: `vault:${objectId}` });
        return plaintext;
    }
}
