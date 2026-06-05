import { KemKeyPair, SigKeyPair, CryptoService } from './crypto_service';
import { createHsmProvider, HsmProvider } from './pkcs11_hsm';

export interface KeyStore {
    getSigningKeyPair(keyId: string): Promise<SigKeyPair>;
    getKemKeyPair(keyId: string): Promise<KemKeyPair>;
    sign(keyId: string, message: Buffer | Uint8Array): Promise<Uint8Array>;
    kemDecapsulate(keyId: string, ciphertext: Uint8Array): Promise<Uint8Array>;
    isHsmBacked(): boolean;
}

/** Dev-only in-process keys — NEVER used when HSM is required in production. */
export class InMemoryKeyStore implements KeyStore {
    private sigKeys = new Map<string, SigKeyPair>();
    private kemKeys = new Map<string, KemKeyPair>();

    constructor(private crypto: CryptoService) {}

    isHsmBacked(): boolean {
        return false;
    }

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

    async sign(keyId: string, message: Buffer | Uint8Array): Promise<Uint8Array> {
        const pair = await this.getSigningKeyPair(keyId);
        const sig = this.crypto.createSig();
        return this.crypto.sign(sig, pair.privateKey, message);
    }

    async kemDecapsulate(keyId: string, ciphertext: Uint8Array): Promise<Uint8Array> {
        const pair = await this.getKemKeyPair(keyId);
        const kem = this.crypto.createKem();
        return this.crypto.decapsulate(kem, pair.privateKey, ciphertext);
    }
}

/**
 * FIPS 140-3 Level 3 HSM key store.
 * Private keys generated inside HSM — never exported to process memory.
 */
export class HsmKeyStore implements KeyStore {
    private provider: HsmProvider;
    private kemHandles = new Map<string, string>();
    private sigHandles = new Map<string, string>();

    constructor(
        private crypto: CryptoService,
        provider?: HsmProvider
    ) {
        this.provider = provider ?? createHsmProvider();
    }

    isHsmBacked(): boolean {
        return true;
    }

    async initialize(): Promise<void> {
        await this.provider.connect();
        const kemAlg = this.crypto.suite.kem.includes('1024') ? 'Kyber1024' as const : 'Kyber768' as const;
        const sigAlg = this.crypto.suite.sig.includes('5') ? 'Dilithium5' as const : 'Dilithium3' as const;
        const kem = await this.provider.generateKemKeyPair('server-kem', kemAlg);
        const sig = await this.provider.generateSigKeyPair('server-sig', sigAlg);
        this.kemHandles.set('server-kem', kem.keyId);
        this.sigHandles.set('server-sig', sig.keyId);
    }

    async getSigningKeyPair(keyId: string): Promise<SigKeyPair> {
        const handleId = this.sigHandles.get(keyId) ?? keyId;
        const publicKey = await this.provider.getPublicKey(handleId);
        return { publicKey, privateKey: new Uint8Array(0) };
    }

    async getKemKeyPair(keyId: string): Promise<KemKeyPair> {
        const handleId = this.kemHandles.get(keyId) ?? keyId;
        const publicKey = await this.provider.getPublicKey(handleId);
        return { publicKey, privateKey: new Uint8Array(0) };
    }

    async sign(keyId: string, message: Buffer | Uint8Array): Promise<Uint8Array> {
        const handleId = this.sigHandles.get(keyId) ?? keyId;
        const sigAlg = this.crypto.suite.sig.includes('5') ? 'Dilithium5' as const : 'Dilithium3' as const;
        return this.provider.sign({ keyId: handleId, algorithm: sigAlg, message });
    }

    async kemDecapsulate(keyId: string, ciphertext: Uint8Array): Promise<Uint8Array> {
        const handleId = this.kemHandles.get(keyId) ?? keyId;
        const kemAlg = this.crypto.suite.kem.includes('1024') ? 'Kyber1024' as const : 'Kyber768' as const;
        return this.provider.kemDecapsulate({ keyId: handleId, algorithm: kemAlg, ciphertext });
    }
}

export function createKeyStore(crypto: CryptoService, hsmEnabled: boolean, devMode = process.env.NOMAD_DEV_MODE === 'true'): KeyStore {
    if (hsmEnabled) {
        return new HsmKeyStore(crypto);
    }
    if (!devMode && process.env.NOMAD_HSM_REQUIRED === 'true') {
        throw new Error('NOMAD_HSM_REQUIRED is set but HSM is not enabled. Set NOMAD_HSM_ENABLED=true and configure PKCS#11.');
    }
    return new InMemoryKeyStore(crypto);
}
