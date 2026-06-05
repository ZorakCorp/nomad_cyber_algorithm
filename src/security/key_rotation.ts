import { KemKeyPair, CryptoService } from '../crypto/crypto_service';
import { KeyEncapsulation } from '@open-quantum-safe/oqs-javascript';

export interface RotatingKemKeys {
    keyId: string;
    pair: KemKeyPair;
    rotatedAt: number;
    rotateAfterMs: number;
}

export class KeyRotationManager {
    private kemInstance: KeyEncapsulation;
    private current: RotatingKemKeys;
    private previous: RotatingKemKeys | null = null;
    private readonly graceMs: number;

    constructor(
        private crypto: CryptoService,
        private keyId: string,
        rotateAfterMs: number = 3_600_000,
        graceMs: number = 300_000
    ) {
        this.graceMs = graceMs;
        this.kemInstance = crypto.createKem();
        const pair = crypto.generateKemKeyPair(this.kemInstance);
        this.current = { keyId, pair, rotatedAt: Date.now(), rotateAfterMs };
    }

    getActiveKeys(): RotatingKemKeys {
        if (Date.now() - this.current.rotatedAt >= this.current.rotateAfterMs) {
            this.rotate();
        }
        return this.current;
    }

    /** Resolve KEM keypair by public key — supports in-flight handshakes after rotation. */
    resolveByPublicKey(publicKey: Uint8Array): RotatingKemKeys | null {
        if (Buffer.from(this.current.pair.publicKey).compare(Buffer.from(publicKey)) === 0) {
            return this.current;
        }
        if (this.previous &&
            Buffer.from(this.previous.pair.publicKey).compare(Buffer.from(publicKey)) === 0) {
            const age = Date.now() - (this.current.rotatedAt);
            if (age <= this.graceMs) {
                return this.previous;
            }
        }
        return null;
    }

    rotate(): RotatingKemKeys {
        this.previous = this.current;
        const pair = this.crypto.generateKemKeyPair(this.kemInstance);
        this.current = { keyId: this.keyId, pair, rotatedAt: Date.now(), rotateAfterMs: this.current.rotateAfterMs };
        return this.current;
    }

    getKem(): KeyEncapsulation {
        return this.kemInstance;
    }

    refreshCertificateKeys(): KemKeyPair {
        return this.getActiveKeys().pair;
    }
}
