export interface ReplayGuardOptions {
    maxClockSkewMs: number;
    nonceTtlMs: number;
    maxEntries: number;
}

interface NonceEntry {
    expiresAt: number;
}

export class ReplayGuard {
    private seenNonces = new Map<string, NonceEntry>();

    constructor(private options: ReplayGuardOptions = {
        maxClockSkewMs: 60_000,
        nonceTtlMs: 120_000,
        maxEntries: 10_000,
    }) {}

    validate(nonce: string, timestamp: number, correlationId: string): void {
        this.purge();
        if (this.seenNonces.size >= this.options.maxEntries) {
            const oldest = this.seenNonces.keys().next().value;
            if (oldest) this.seenNonces.delete(oldest);
        }
        const now = Date.now();
        if (timestamp <= 0 || Math.abs(now - timestamp) > this.options.maxClockSkewMs) {
            throw new Error('Message timestamp outside allowed clock skew window.');
        }
        const key = `${correlationId}:${nonce}`;
        if (this.seenNonces.has(key)) {
            throw new Error('Replay detected: duplicate nonce.');
        }
        this.seenNonces.set(key, { expiresAt: now + this.options.nonceTtlMs });
    }

    private purge(): void {
        const now = Date.now();
        for (const [key, entry] of this.seenNonces) {
            if (entry.expiresAt <= now) {
                this.seenNonces.delete(key);
            }
        }
    }
}
