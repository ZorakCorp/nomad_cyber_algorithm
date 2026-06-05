import { createHmac, hkdfSync } from 'crypto';

export function deriveLayerKey(
    masterKey: Buffer,
    correlationId: string,
    layer: string,
    sequence = 0,
    timestampMs = 0
): Buffer {
    const info = `nomad-imperial:${layer}:${correlationId}:${sequence}:${timestampMs}`;
    const salt = createHmac('sha256', masterKey)
        .update('aureon-imperial-salt')
        .update(correlationId)
        .update(sequence.toString())
        .digest();
    return Buffer.from(hkdfSync('sha256', masterKey, salt, info, 32));
}

export function deriveRodDiameter(
    masterKey: Buffer,
    correlationId: string,
    sequence = 0,
    timestampMs = 0
): number {
    const h = createHmac('sha256', masterKey)
        .update(`scytale:${correlationId}:${sequence}:${timestampMs}`)
        .digest();
    return 8 + (h[0] % 9);
}
