import { OQS_KEM_ALG, OQS_SIG_ALG } from '@open-quantum-safe/oqs-javascript';

export type AlgorithmSuiteId = 'kyber768_dilithium3' | 'kyber1024_dilithium5';

export interface AlgorithmSuite {
    id: AlgorithmSuiteId;
    kem: OQS_KEM_ALG;
    sig: OQS_SIG_ALG;
    label: string;
}

const SUITES: Record<AlgorithmSuiteId, AlgorithmSuite> = {
    kyber768_dilithium3: {
        id: 'kyber768_dilithium3',
        kem: OQS_KEM_ALG.Kyber768,
        sig: OQS_SIG_ALG.Dilithium3,
        label: 'Kyber768 + Dilithium3',
    },
    kyber1024_dilithium5: {
        id: 'kyber1024_dilithium5',
        kem: OQS_KEM_ALG.Kyber1024,
        sig: OQS_SIG_ALG.Dilithium5,
        label: 'Kyber1024 + Dilithium5',
    },
};

export function resolveAlgorithmSuite(id: AlgorithmSuiteId): AlgorithmSuite {
    const suite = SUITES[id];
    if (!suite) {
        throw new Error(`Unknown algorithm suite: ${id}`);
    }
    return suite;
}

export function supportedSuiteIds(): AlgorithmSuiteId[] {
    return Object.keys(SUITES) as AlgorithmSuiteId[];
}
