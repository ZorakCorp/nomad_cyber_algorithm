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

    constructor(
        private crypto: CryptoService,
        private keyId: string,
        rotateAfterMs: number = 3_600_000
    ) {
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

    rotate(): RotatingKemKeys {
        this.crypto.destroyKeyMaterial(this.current.pair.privateKey);
        const pair = this.crypto.generateKemKeyPair(this.kemInstance);
        this.current = { keyId: this.keyId, pair, rotatedAt: Date.now(), rotateAfterMs: this.current.rotateAfterMs };
        return this.current;
    }

    getKem(): KeyEncapsulation {
        return this.kemInstance;
    }
}
