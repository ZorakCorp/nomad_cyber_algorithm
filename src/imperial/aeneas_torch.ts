import { createHmac } from 'crypto';

/**
 * Aeneas Tacticus torch code — time-slot keyed mask.
 * Messages only decode in the agreed temporal window (hour epoch).
 */

export function torchSlotKey(masterKey: Buffer, correlationId: string, timestampMs: number): Buffer {
    const hourSlot = Math.floor(timestampMs / 3_600_000);
    return createHmac('sha256', masterKey)
        .update('aeneas-torch')
        .update(correlationId)
        .update(hourSlot.toString())
        .digest();
}

export function torchMask(data: Buffer, maskKey: Buffer): Buffer {
    const out = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) {
        out[i] = data[i] ^ maskKey[i % maskKey.length];
    }
    return out;
}
