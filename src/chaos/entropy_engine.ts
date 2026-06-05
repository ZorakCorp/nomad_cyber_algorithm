import { createHmac, hkdfSync, randomBytes } from 'crypto';

/**
 * Chaotic entropy — per-message salts and padding with no repeating wire patterns.
 * All lengths and permutations are key-derived; padding uses OS CSPRNG.
 */

export function deriveMessageSalt(
    masterKey: Buffer,
    correlationId: string,
    sequence: number,
    timestampMs: number
): Buffer {
    const info = `nomad-chaos-salt:${correlationId}:${sequence}`;
    const saltInput = Buffer.concat([
        Buffer.from(timestampMs.toString()),
        Buffer.from(sequence.toString()),
    ]);
    return Buffer.from(hkdfSync('sha256', masterKey, saltInput, info, 32));
}

export function derivePadLength(
    masterKey: Buffer,
    correlationId: string,
    sequence: number,
    timestampMs: number,
    min = 16,
    max = 272
): number {
    const salt = deriveMessageSalt(masterKey, correlationId, sequence, timestampMs);
    const span = max - min + 1;
    return min + (salt[0] ^ salt[1] ^ salt[2]) % span;
}

export function deriveSuffixLength(
    masterKey: Buffer,
    correlationId: string,
    sequence: number,
    timestampMs: number
): number {
    const salt = deriveMessageSalt(masterKey, correlationId, sequence, timestampMs);
    return 8 + (salt[3] ^ salt[4]) % 120;
}

/** Prefix + body + suffix — ciphertext length never matches plaintext length. */
export function applyChaoticPadding(
    body: Buffer,
    masterKey: Buffer,
    correlationId: string,
    sequence: number,
    timestampMs: number
): Buffer {
    const prefixLen = derivePadLength(masterKey, correlationId, sequence, timestampMs);
    const suffixLen = deriveSuffixLength(masterKey, correlationId, sequence, timestampMs);
    const prefix = randomBytes(prefixLen);
    const suffix = randomBytes(suffixLen);
    const header = Buffer.alloc(4);
    header.writeUInt16BE(prefixLen, 0);
    header.writeUInt16BE(suffixLen, 2);
    return Buffer.concat([header, prefix, body, suffix]);
}

export function stripChaoticPadding(
    padded: Buffer,
    masterKey: Buffer,
    correlationId: string,
    sequence: number,
    timestampMs: number
): Buffer {
    if (padded.length < 4) {
        throw new Error('Chaotic padding header missing.');
    }
    const prefixLen = padded.readUInt16BE(0);
    const suffixLen = padded.readUInt16BE(2);
    const expectedPrefix = derivePadLength(masterKey, correlationId, sequence, timestampMs);
    const expectedSuffix = deriveSuffixLength(masterKey, correlationId, sequence, timestampMs);
    if (prefixLen !== expectedPrefix || suffixLen !== expectedSuffix) {
        throw new Error('Chaotic padding length mismatch — possible tamper.');
    }
    const bodyStart = 4 + prefixLen;
    const bodyEnd = padded.length - suffixLen;
    if (bodyStart > bodyEnd) {
        throw new Error('Chaotic padding bounds invalid.');
    }
    return padded.subarray(bodyStart, bodyEnd);
}

/** Fisher-Yates shuffle driven by key material — same inputs always yield same order. */
export function deriveShuffledOrder<T extends string>(
    items: readonly T[],
    masterKey: Buffer,
    correlationId: string,
    sequence: number,
    timestampMs: number,
    label: string
): T[] {
    const seed = createHmac('sha256', masterKey)
        .update(`chaos-order:${label}:${correlationId}:${sequence}:${timestampMs}`)
        .digest();
    const arr = [...items];
    for (let i = arr.length - 1; i > 0; i--) {
        const j = seed[i % seed.length] % (i + 1);
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}

export function deriveChaosFingerprint(
    masterKey: Buffer,
    correlationId: string,
    sequence: number,
    timestampMs: number
): Buffer {
    return createHmac('sha256', masterKey)
        .update('chaos-fingerprint')
        .update(correlationId)
        .update(sequence.toString())
        .update(timestampMs.toString())
        .digest()
        .subarray(0, 8);
}
