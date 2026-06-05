import { deriveLayerKey, deriveRodDiameter } from './key_derivation';
import { scytaleEncipher, scytaleDecipher } from './scytale';
import { augustanEncipher, augustanDecipher } from './augustan';
import {
    buildHieroglyphSbox,
    hieroglyphEncipher,
    hieroglyphDecipher,
    wrapCartouche,
    unwrapCartouche,
} from './egyptian';
import { applyPersianSeal, verifyPersianSeal } from './persian_seal';
import { torchSlotKey, torchMask } from './aeneas_torch';
import { deriveOccultVeilKey, occultVeilTransform } from '../occult/aureon_veil';

export interface ImperialCipherConfig {
    enabled: boolean;
    occultVeilEnabled: boolean;
    subject: string;
}

export const DEFAULT_IMPERIAL_CONFIG: ImperialCipherConfig = {
    enabled: true,
    occultVeilEnabled: true,
    subject: 'Nomad Sovereign Channel',
};

/**
 * Full imperial encipherment stack (applied BEFORE AES-256-GCM):
 *
 * 1. Egyptian cartouche — identity-bound envelope
 * 2. Egyptian hieroglyph — keyed S-box substitution
 * 3. Roman Augustan — position Caesar rotation
 * 4. Greek scytale — columnar transposition
 * 5. Persian seal — tamper-evident HMAC frame
 * 6. Aeneas torch — hourly epoch XOR mask
 * 7. Aureon occult veil — planetary epoch whitening (optional)
 */
export class ImperialCipherStack {
    constructor(
        private masterKey: Buffer,
        private correlationId: string,
        private config: ImperialCipherConfig = DEFAULT_IMPERIAL_CONFIG
    ) {}

    encipher(plaintext: Buffer, timestampMs: number = Date.now()): Buffer {
        if (!this.config.enabled) return plaintext;

        const cartoucheKey = deriveLayerKey(this.masterKey, this.correlationId, 'cartouche');
        const hieroglyphKey = deriveLayerKey(this.masterKey, this.correlationId, 'hieroglyph');
        const augustanKey = deriveLayerKey(this.masterKey, this.correlationId, 'augustan');
        const sealKey = deriveLayerKey(this.masterKey, this.correlationId, 'persian-seal');
        const columns = deriveRodDiameter(this.masterKey, this.correlationId);

        let body: Buffer = Buffer.from(wrapCartouche(plaintext, this.config.subject, this.correlationId, cartoucheKey));
        const sbox = buildHieroglyphSbox(hieroglyphKey);
        body = Buffer.from(hieroglyphEncipher(body, sbox));
        body = Buffer.from(augustanEncipher(body, augustanKey));
        body = Buffer.from(scytaleEncipher(body, columns));
        body = Buffer.from(applyPersianSeal(body, sealKey));

        const torchKey = torchSlotKey(this.masterKey, this.correlationId, timestampMs);
        body = Buffer.from(torchMask(body, torchKey));

        if (this.config.occultVeilEnabled) {
            const veilKey = deriveOccultVeilKey(this.masterKey, this.correlationId, timestampMs);
            body = Buffer.from(occultVeilTransform(body, veilKey));
        }

        return body;
    }

    decipher(ciphertext: Buffer, timestampMs: number = Date.now()): Buffer {
        if (!this.config.enabled) return ciphertext;

        const cartoucheKey = deriveLayerKey(this.masterKey, this.correlationId, 'cartouche');
        const hieroglyphKey = deriveLayerKey(this.masterKey, this.correlationId, 'hieroglyph');
        const augustanKey = deriveLayerKey(this.masterKey, this.correlationId, 'augustan');
        const sealKey = deriveLayerKey(this.masterKey, this.correlationId, 'persian-seal');
        const columns = deriveRodDiameter(this.masterKey, this.correlationId);

        let body: Buffer = Buffer.from(ciphertext);

        if (this.config.occultVeilEnabled) {
            const veilKey = deriveOccultVeilKey(this.masterKey, this.correlationId, timestampMs);
            body = Buffer.from(occultVeilTransform(body, veilKey));
        }

        body = Buffer.from(torchMask(body, torchSlotKey(this.masterKey, this.correlationId, timestampMs)));
        body = Buffer.from(verifyPersianSeal(body, sealKey));
        body = Buffer.from(scytaleDecipher(body, columns));
        body = Buffer.from(augustanDecipher(body, augustanKey));
        const sbox = buildHieroglyphSbox(hieroglyphKey);
        body = Buffer.from(hieroglyphDecipher(body, sbox));
        body = Buffer.from(unwrapCartouche(body, cartoucheKey));

        return body;
    }
}
