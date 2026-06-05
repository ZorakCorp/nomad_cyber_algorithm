import { createHmac, hkdfSync } from 'crypto';

/**
 * AUREON OCCULT VEIL
 * Planetary epoch anchoring + TCAP temporal entropy + symmetric whitening XOR.
 */

export const PLANETARY_ORBITAL_PERIODS_DAYS = {
    saturn: 10759.22,
    jupiter: 4332.59,
    mars: 686.98,
    venus: 224.70,
    mercury: 87.97,
} as const;

const PHI = 1.618033988749895;
const TCAP_ANCHOR = Math.floor(PHI * 1_000_000) % 9973;

export function planetaryEpochSlot(timestampMs: number): number {
    const day = timestampMs / 86_400_000;
    return Math.floor(day / PLANETARY_ORBITAL_PERIODS_DAYS.saturn);
}

export function tcapTemporalHash(timestampMs: number, correlationId: string): Buffer {
    const slot = Math.floor(timestampMs / 60_000);
    const entropy = (slot * TCAP_ANCHOR) ^ correlationId.charCodeAt(0);
    return createHmac('sha256', Buffer.from('aureon-tcap'))
        .update(correlationId)
        .update(slot.toString())
        .update(entropy.toString())
        .digest();
}

export function deriveOccultVeilKey(
    masterKey: Buffer,
    correlationId: string,
    timestampMs: number
): Buffer {
    const epoch = planetaryEpochSlot(timestampMs);
    const tcap = tcapTemporalHash(timestampMs, correlationId);
    const salt = Buffer.concat([Buffer.from(epoch.toString()), tcap]);
    const info = `aureon-veil:${correlationId}`;
    return Buffer.from(hkdfSync('sha256', masterKey, salt, info, 32));
}

/** Symmetric XOR veil — self-inverse for encipher/decipher. */
export function occultVeilTransform(data: Buffer, veilKey: Buffer): Buffer {
    const out = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) {
        const occultByte = veilKey[i % veilKey.length] ^ ((i * TCAP_ANCHOR + veilKey[0]) & 0xff);
        out[i] = data[i] ^ occultByte;
    }
    return out;
}
