import { KemKeyPair, SigKeyPair, CryptoService } from './crypto_service';

export interface KeyStore {
    getSigningKeyPair(keyId: string): Promise<SigKeyPair>;
    getKemKeyPair(keyId: string): Promise<KemKeyPair>;
}

/** In-process key storage for development and demos. */
export class InMemoryKeyStore implements KeyStore {
    private sigKeys = new Map<string, SigKeyPair>();
    private kemKeys = new Map<string, KemKeyPair>();

    constructor(private crypto: CryptoService) {}

    async ensureSigningKey(keyId: string): Promise<SigKeyPair> {
        let pair = this.sigKeys.get(keyId);
        if (!pair) {
            const sig = this.crypto.createSig();
            pair = this.crypto.generateSigKeyPair(sig);
            this.sigKeys.set(keyId, pair);
        }
        return pair;
    }

    async ensureKemKey(keyId: string): Promise<KemKeyPair> {
        let pair = this.kemKeys.get(keyId);
        if (!pair) {
            const kem = this.crypto.createKem();
            pair = this.crypto.generateKemKeyPair(kem);
            this.kemKeys.set(keyId, pair);
        }
        return pair;
    }

    async getSigningKeyPair(keyId: string): Promise<SigKeyPair> {
        return this.ensureSigningKey(keyId);
    }

    async getKemKeyPair(keyId: string): Promise<KemKeyPair> {
        return this.ensureKemKey(keyId);
    }
}

/**
 * HSM/KMS adapter stub — wire to PKCS#11, AWS CloudHSM, or Vault in production.
 * Falls back to in-memory keys when HSM endpoints are unavailable.
 */
export class HsmKeyStore implements KeyStore {
    private fallback: InMemoryKeyStore;

    constructor(
        private crypto: CryptoService,
        private endpoint: string | null = process.env.NOMAD_HSM_ENDPOINT ?? null
    ) {
        this.fallback = new InMemoryKeyStore(crypto);
    }

    async getSigningKeyPair(keyId: string): Promise<SigKeyPair> {
        if (!this.endpoint) {
            return this.fallback.getSigningKeyPair(keyId);
        }
        // Production: call HSM API here. Stub delegates to fallback for runnable demo.
        return this.fallback.getSigningKeyPair(`hsm:${keyId}`);
    }

    async getKemKeyPair(keyId: string): Promise<KemKeyPair> {
        if (!this.endpoint) {
            return this.fallback.getKemKeyPair(keyId);
        }
        return this.fallback.getKemKeyPair(`hsm:${keyId}`);
    }
}

export function createKeyStore(crypto: CryptoService, hsmEnabled: boolean): KeyStore {
    return hsmEnabled ? new HsmKeyStore(crypto) : new InMemoryKeyStore(crypto);
}
