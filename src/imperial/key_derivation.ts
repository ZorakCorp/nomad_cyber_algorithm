import { createHmac, hkdfSync } from 'crypto';

export function deriveLayerKey(masterKey: Buffer, correlationId: string, layer: string): Buffer {
    const info = `nomad-imperial:${layer}:${correlationId}`;
    return Buffer.from(hkdfSync('sha256', masterKey, Buffer.from('aureon-imperial-salt'), info, 32));
}

export function deriveRodDiameter(masterKey: Buffer, correlationId: string): number {
    const h = createHmac('sha256', masterKey).update(`scytale:${correlationId}`).digest();
    return 8 + (h[0] % 9);
}
