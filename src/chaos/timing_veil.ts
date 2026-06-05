import { randomInt } from 'crypto';

/**
 * Response timing jitter — defeats traffic-analysis pattern matching.
 */

export function deriveJitterMs(
    maxJitterMs: number,
    sequence: number,
    correlationId: string
): number {
    if (maxJitterMs <= 0) return 0;
    const cidByte = correlationId.length > 0 ? correlationId.charCodeAt(0) : 0;
    const slot = (sequence * 31 + cidByte) % (maxJitterMs + 1);
    const noise = randomInt(0, Math.max(1, Math.floor(maxJitterMs / 4) + 1));
    return Math.min(maxJitterMs, slot + noise);
}

export function jitteredDelay(maxJitterMs: number, sequence: number, correlationId: string): Promise<void> {
    const ms = deriveJitterMs(maxJitterMs, sequence, correlationId);
    if (ms <= 0) return Promise.resolve();
    return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Heartbeat interval varies ±spread so heartbeats are not clock-regular. */
export function chaoticHeartbeatInterval(baseMs: number, spreadMs: number): number {
    const delta = randomInt(-spreadMs, spreadMs + 1);
    return Math.max(1000, baseMs + delta);
}
