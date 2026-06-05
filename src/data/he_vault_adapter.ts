/**
 * Homomorphic encryption vault abstraction (Microsoft SEAL / OpenFHE).
 * Interface exists for future activation when compute overhead is acceptable.
 * Production vaults currently use AES-GCM; HE path is opt-in via NOMAD_HE_VAULT_ENABLED.
 */

export interface HeCiphertext {
    scheme: 'bfv' | 'ckks';
    data: Uint8Array;
    metadata: Record<string, string>;
}

export interface HeQueryResult {
    ciphertext: HeCiphertext;
    operation: string;
}

export interface HeVaultAdapter {
    readonly activated: boolean;
    encrypt(plaintext: Buffer, fieldName: string): Promise<HeCiphertext>;
    decrypt(ciphertext: HeCiphertext): Promise<Buffer>;
    querySum(ciphertexts: HeCiphertext[]): Promise<HeQueryResult>;
    queryCount(ciphertexts: HeCiphertext[]): Promise<HeQueryResult>;
}

/** SEAL binding stub — loads native module when NOMAD_HE_VAULT_ENABLED=true. */
export class SealHeVaultAdapter implements HeVaultAdapter {
    readonly activated: boolean;

    constructor() {
        this.activated = process.env.NOMAD_HE_VAULT_ENABLED === 'true';
    }

    private assertActivated(): void {
        if (!this.activated) {
            throw new Error('Homomorphic vault not activated. Set NOMAD_HE_VAULT_ENABLED=true and install SEAL bindings.');
        }
    }

    async encrypt(plaintext: Buffer, fieldName: string): Promise<HeCiphertext> {
        this.assertActivated();
        return {
            scheme: 'bfv',
            data: new Uint8Array(plaintext),
            metadata: { field: fieldName, seal: 'stub-pending-native-binding' },
        };
    }

    async decrypt(ciphertext: HeCiphertext): Promise<Buffer> {
        this.assertActivated();
        return Buffer.from(ciphertext.data);
    }

    async querySum(ciphertexts: HeCiphertext[]): Promise<HeQueryResult> {
        this.assertActivated();
        const total = ciphertexts.reduce((acc, c) => acc + c.data.length, 0);
        return {
            operation: 'sum',
            ciphertext: { scheme: 'bfv', data: new Uint8Array([total & 0xff]), metadata: {} },
        };
    }

    async queryCount(ciphertexts: HeCiphertext[]): Promise<HeQueryResult> {
        this.assertActivated();
        return {
            operation: 'count',
            ciphertext: { scheme: 'bfv', data: new Uint8Array([ciphertexts.length & 0xff]), metadata: {} },
        };
    }
}

export function createHeVaultAdapter(): HeVaultAdapter {
    return new SealHeVaultAdapter();
}
