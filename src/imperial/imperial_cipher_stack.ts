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
import {
    applyChaoticPadding,
    stripChaoticPadding,
    deriveShuffledOrder,
    deriveChaosFingerprint,
} from '../chaos/entropy_engine';

export interface ImperialCipherConfig {
    enabled: boolean;
    occultVeilEnabled: boolean;
    chaosModeEnabled: boolean;
    subject: string;
}

export const DEFAULT_IMPERIAL_CONFIG: ImperialCipherConfig = {
    enabled: true,
    occultVeilEnabled: true,
    chaosModeEnabled: true,
    subject: 'Nomad Sovereign Channel',
};

type MutableLayer = 'hieroglyph' | 'augustan' | 'scytale';
type TailLayer = 'torch' | 'veil';

const MUTABLE_LAYERS: MutableLayer[] = ['hieroglyph', 'augustan', 'scytale'];

/**
 * Imperial encipherment stack (BEFORE AES-256-GCM).
 * Chaos mode shuffles layer order and adds random padding per message — no wire pattern.
 */
export class ImperialCipherStack {
    constructor(
        private masterKey: Buffer,
        private correlationId: string,
        private config: ImperialCipherConfig = DEFAULT_IMPERIAL_CONFIG
    ) {}

    encipher(plaintext: Buffer, timestampMs: number = Date.now(), sequence = 0): Buffer {
        if (!this.config.enabled) return plaintext;

        const cartoucheKey = deriveLayerKey(this.masterKey, this.correlationId, 'cartouche', sequence, timestampMs);
        const hieroglyphKey = deriveLayerKey(this.masterKey, this.correlationId, 'hieroglyph', sequence, timestampMs);
        const augustanKey = deriveLayerKey(this.masterKey, this.correlationId, 'augustan', sequence, timestampMs);
        const sealKey = deriveLayerKey(this.masterKey, this.correlationId, 'persian-seal', sequence, timestampMs);
        const columns = deriveRodDiameter(this.masterKey, this.correlationId, sequence, timestampMs);

        let body: Buffer = Buffer.from(wrapCartouche(plaintext, this.config.subject, this.correlationId, cartoucheKey));
        const sbox = buildHieroglyphSbox(hieroglyphKey);

        const layerFns: Record<MutableLayer, () => Buffer> = {
            hieroglyph: () => Buffer.from(hieroglyphEncipher(body, sbox)),
            augustan: () => Buffer.from(augustanEncipher(body, augustanKey)),
            scytale: () => Buffer.from(scytaleEncipher(body, columns)),
        };

        const order = this.config.chaosModeEnabled
            ? deriveShuffledOrder(MUTABLE_LAYERS, this.masterKey, this.correlationId, sequence, timestampMs, 'mutable')
            : MUTABLE_LAYERS;

        for (const layer of order) {
            body = layerFns[layer]();
        }

        body = Buffer.from(applyPersianSeal(body, sealKey));

        const tailLayers: TailLayer[] = ['torch'];
        if (this.config.occultVeilEnabled) tailLayers.push('veil');
        const tailOrder = this.config.chaosModeEnabled
            ? deriveShuffledOrder(tailLayers, this.masterKey, this.correlationId, sequence, timestampMs, 'tail')
            : tailLayers;

        for (const layer of tailOrder) {
            if (layer === 'torch') {
                body = Buffer.from(torchMask(body, torchSlotKey(this.masterKey, this.correlationId, timestampMs)));
            } else {
                const veilKey = deriveOccultVeilKey(this.masterKey, this.correlationId, timestampMs);
                body = Buffer.from(occultVeilTransform(body, veilKey));
            }
        }

        if (this.config.chaosModeEnabled) {
            const fingerprint = deriveChaosFingerprint(this.masterKey, this.correlationId, sequence, timestampMs);
            body = Buffer.concat([fingerprint, body]);
            body = applyChaoticPadding(body, this.masterKey, this.correlationId, sequence, timestampMs);
        }

        return body;
    }

    decipher(ciphertext: Buffer, timestampMs: number = Date.now(), sequence = 0): Buffer {
        if (!this.config.enabled) return ciphertext;

        const cartoucheKey = deriveLayerKey(this.masterKey, this.correlationId, 'cartouche', sequence, timestampMs);
        const hieroglyphKey = deriveLayerKey(this.masterKey, this.correlationId, 'hieroglyph', sequence, timestampMs);
        const augustanKey = deriveLayerKey(this.masterKey, this.correlationId, 'augustan', sequence, timestampMs);
        const sealKey = deriveLayerKey(this.masterKey, this.correlationId, 'persian-seal', sequence, timestampMs);
        const columns = deriveRodDiameter(this.masterKey, this.correlationId, sequence, timestampMs);

        let body: Buffer = Buffer.from(ciphertext);

        if (this.config.chaosModeEnabled) {
            body = stripChaoticPadding(body, this.masterKey, this.correlationId, sequence, timestampMs);
            const expected = deriveChaosFingerprint(this.masterKey, this.correlationId, sequence, timestampMs);
            const actual = body.subarray(0, 8);
            if (actual.length !== 8 || !actual.equals(expected)) {
                throw new Error('Chaos fingerprint mismatch — message pattern rejected.');
            }
            body = body.subarray(8);
        }

        const tailLayers: TailLayer[] = ['torch'];
        if (this.config.occultVeilEnabled) tailLayers.push('veil');
        const tailOrder = this.config.chaosModeEnabled
            ? deriveShuffledOrder(tailLayers, this.masterKey, this.correlationId, sequence, timestampMs, 'tail')
            : tailLayers;

        for (const layer of [...tailOrder].reverse()) {
            if (layer === 'veil') {
                const veilKey = deriveOccultVeilKey(this.masterKey, this.correlationId, timestampMs);
                body = Buffer.from(occultVeilTransform(body, veilKey));
            } else {
                body = Buffer.from(torchMask(body, torchSlotKey(this.masterKey, this.correlationId, timestampMs)));
            }
        }

        body = Buffer.from(verifyPersianSeal(body, sealKey));

        const reverseFns: Record<MutableLayer, () => Buffer> = {
            scytale: () => Buffer.from(scytaleDecipher(body, columns)),
            augustan: () => Buffer.from(augustanDecipher(body, augustanKey)),
            hieroglyph: () => {
                const sbox = buildHieroglyphSbox(hieroglyphKey);
                return Buffer.from(hieroglyphDecipher(body, sbox));
            },
        };

        const order = this.config.chaosModeEnabled
            ? deriveShuffledOrder(MUTABLE_LAYERS, this.masterKey, this.correlationId, sequence, timestampMs, 'mutable')
            : MUTABLE_LAYERS;

        for (const layer of [...order].reverse()) {
            body = reverseFns[layer]();
        }

        body = Buffer.from(unwrapCartouche(body, cartoucheKey));
        return body;
    }
}
