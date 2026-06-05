import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'crypto';
import { KeyEncapsulation, Signature } from '@open-quantum-safe/oqs-javascript';
import { AlgorithmSuite, resolveAlgorithmSuite } from './algorithm_suite';
import { secureZero, secureZeroMany } from '../security/memory_scrub';

export const CRYPTO_CONSTANTS = {
    AES_KEY_BYTES: 32,
    GCM_IV_BYTES: 12,
    GCM_AUTH_TAG_BYTES: 16,
    HKDF_INFO: 'nomad-pqc-channel-v1',
    HKDF_SALT: 'nomad-pqc-channel-salt-v1',
} as const;

export interface AadContext {
    correlationId: string;
    sequence: number;
    recordType?: string;
}

export interface KemKeyPair {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}

export interface SigKeyPair {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}

export interface EncryptedRecord {
    ciphertext: Buffer;
    iv: Buffer;
    authTag: Buffer;
    sequence: number;
}

export class CryptoService {
    readonly suite: AlgorithmSuite;

    constructor(suiteId: AlgorithmSuite['id'] = 'kyber768_dilithium3') {
        this.suite = resolveAlgorithmSuite(suiteId);
    }

    createKem(): KeyEncapsulation {
        return new KeyEncapsulation(this.suite.kem);
    }

    createSig(): Signature {
        return new Signature(this.suite.sig);
    }

    generateKemKeyPair(kem: KeyEncapsulation): KemKeyPair {
        const pair = kem.generateKeyPair();
        return { publicKey: pair.publicKey, privateKey: pair.privateKey };
    }

    generateSigKeyPair(sig: Signature): SigKeyPair {
        const pair = sig.generateKeyPair();
        return { publicKey: pair.publicKey, privateKey: pair.privateKey };
    }

    encapsulate(kem: KeyEncapsulation, serverPublicKey: Uint8Array): { ciphertext: Uint8Array; sharedSecret: Uint8Array } {
        return kem.encapsulate(serverPublicKey);
    }

    decapsulate(kem: KeyEncapsulation, privateKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
        return kem.decapsulate(privateKey, ciphertext);
    }

    sign(sig: Signature, privateKey: Uint8Array, message: Buffer | Uint8Array): Uint8Array {
        return sig.sign(privateKey, message);
    }

    verify(sig: Signature, publicKey: Uint8Array, message: Buffer | Uint8Array, signature: Uint8Array): boolean {
        return sig.verify(publicKey, message, signature);
    }

    deriveChannelKey(sharedSecret: Uint8Array, correlationId: string): Buffer {
        const info = `${CRYPTO_CONSTANTS.HKDF_INFO}:${correlationId}`;
        const salt = Buffer.from(CRYPTO_CONSTANTS.HKDF_SALT);
        const key = Buffer.from(hkdfSync('sha256', Buffer.from(sharedSecret), salt, info, CRYPTO_CONSTANTS.AES_KEY_BYTES));
        secureZero(sharedSecret);
        return key;
    }

    private buildAad(ctx: AadContext): Buffer {
        const type = ctx.recordType ?? 'application';
        return Buffer.from(`${ctx.correlationId}:${ctx.sequence}:${type}`);
    }

    encrypt(aesKey: Buffer, plaintext: Buffer, aadContext: AadContext): EncryptedRecord {
        const iv = randomBytes(CRYPTO_CONSTANTS.GCM_IV_BYTES);
        const cipher = createCipheriv('aes-256-gcm', aesKey, iv, { authTagLength: CRYPTO_CONSTANTS.GCM_AUTH_TAG_BYTES });
        cipher.setAAD(this.buildAad(aadContext));
        const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
        return { ciphertext, iv, authTag: cipher.getAuthTag(), sequence: aadContext.sequence };
    }

    decrypt(aesKey: Buffer, record: EncryptedRecord, aadContext: AadContext): Buffer {
        const decipher = createDecipheriv('aes-256-gcm', aesKey, record.iv, { authTagLength: CRYPTO_CONSTANTS.GCM_AUTH_TAG_BYTES });
        decipher.setAAD(this.buildAad(aadContext));
        decipher.setAuthTag(record.authTag);
        return Buffer.concat([decipher.update(record.ciphertext), decipher.final()]);
    }

    destroyKey(key: Buffer | null | undefined): void {
        secureZero(key);
    }

    destroyKeyMaterial(...material: Array<Uint8Array | Buffer | null | undefined>): void {
        secureZeroMany(...material);
    }
}
