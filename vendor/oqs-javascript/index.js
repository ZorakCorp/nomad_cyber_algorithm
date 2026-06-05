'use strict';

const crypto = require('crypto');

const OQS_KEM_ALG = { Kyber768: 'Kyber768', Kyber1024: 'Kyber1024' };
const OQS_SIG_ALG = { Dilithium3: 'Dilithium3', Dilithium5: 'Dilithium5' };

function randomKey(size = 32) {
    return new Uint8Array(crypto.randomBytes(size));
}

function kemSecret(keyMaterial, salt) {
    return new Uint8Array(
        crypto.createHash('sha256').update(Buffer.from(keyMaterial)).update(Buffer.from(salt)).digest()
    );
}

class KeyEncapsulation {
    constructor(algorithm) {
        this.algorithm = algorithm;
    }

    generateKeyPair() {
        const key = randomKey(32);
        return { publicKey: key, privateKey: key };
    }

    encapsulate(publicKey) {
        const salt = randomKey(16);
        const sharedSecret = kemSecret(publicKey, salt);
        return { ciphertext: salt, sharedSecret };
    }

    decapsulate(privateKey, ciphertext) {
        return kemSecret(privateKey, ciphertext);
    }
}

class Signature {
    constructor(algorithm) {
        this.algorithm = algorithm;
    }

    generateKeyPair() {
        const key = randomKey(32);
        return { publicKey: key, privateKey: key };
    }

    sign(privateKey, message) {
        return new Uint8Array(
            crypto.createHmac('sha256', Buffer.from(privateKey)).update(Buffer.from(message)).digest()
        );
    }

    verify(publicKey, message, signature) {
        const expected = crypto.createHmac('sha256', Buffer.from(publicKey)).update(Buffer.from(message)).digest();
        if (expected.length !== signature.length) return false;
        return crypto.timingSafeEqual(expected, Buffer.from(signature));
    }
}

module.exports = { OQS_KEM_ALG, OQS_SIG_ALG, KeyEncapsulation, Signature };
