export enum OQS_KEM_ALG {
    Kyber768 = 'Kyber768',
    Kyber1024 = 'Kyber1024',
}

export enum OQS_SIG_ALG {
    Dilithium3 = 'Dilithium3',
    Dilithium5 = 'Dilithium5',
}

export interface KeyPair {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}

export interface EncapsulateResult {
    ciphertext: Uint8Array;
    sharedSecret: Uint8Array;
}

export class KeyEncapsulation {
    constructor(algorithm: OQS_KEM_ALG);
    generateKeyPair(): KeyPair;
    encapsulate(publicKey: Uint8Array): EncapsulateResult;
    decapsulate(privateKey: Uint8Array, ciphertext: Uint8Array): Uint8Array;
}

export class Signature {
    constructor(algorithm: OQS_SIG_ALG);
    generateKeyPair(): KeyPair;
    sign(privateKey: Uint8Array, message: Buffer | Uint8Array): Uint8Array;
    verify(publicKey: Uint8Array, message: Buffer | Uint8Array, signature: Uint8Array): boolean;
}
