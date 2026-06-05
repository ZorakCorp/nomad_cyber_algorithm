import { NomadConfig } from '../config';
import { StructuredLogger } from '../ops/logger';

/** Minimal Redis surface — satisfied by ioredis Redis client. */
export interface RedisLike {
    incr(key: string): Promise<number>;
    expire(key: string, seconds: number): Promise<number>;
    ping?(): Promise<string>;
}

export interface DistributedRateLimiter {
    tryAcquireConnection(ip: string): Promise<boolean>;
    tryAcquireHandshake(ip: string): Promise<boolean>;
}

export class RedisDistributedRateLimiter implements DistributedRateLimiter {
    constructor(
        private redis: RedisLike,
        private maxConnections: number,
        private maxHandshakesPerMinute: number,
        private windowMs = 60_000
    ) {}

    async tryAcquireConnection(ip: string): Promise<boolean> {
        return this.checkLimit('conn', ip, this.maxConnections);
    }

    async tryAcquireHandshake(ip: string): Promise<boolean> {
        return this.checkLimit('handshake', ip, this.maxHandshakesPerMinute);
    }

    private async checkLimit(type: string, ip: string, limit: number): Promise<boolean> {
        const windowSlot = Math.floor(Date.now() / this.windowMs);
        const key = `ratelimit:${type}:${ip}:${windowSlot}`;
        const count = await this.redis.incr(key);
        if (count === 1) {
            await this.redis.expire(key, Math.ceil((this.windowMs * 2) / 1000));
        }
        return count <= limit;
    }
}

export class NullDistributedRateLimiter implements DistributedRateLimiter {
    private warned = false;

    constructor(private logger?: StructuredLogger) {}

    async tryAcquireConnection(_ip: string): Promise<boolean> {
        this.warnOnce();
        return true;
    }

    async tryAcquireHandshake(_ip: string): Promise<boolean> {
        this.warnOnce();
        return true;
    }

    private warnOnce(): void {
        if (this.warned) return;
        this.warned = true;
        const msg = 'Distributed rate limiter unavailable — using in-memory limits only. Set NOMAD_REDIS_URL for multi-instance protection.';
        if (this.logger) {
            this.logger.warn(msg, { component: 'distributed_rate_limiter' });
        } else {
            console.warn(JSON.stringify({ ts: new Date().toISOString(), level: 'warn', message: msg }));
        }
    }
}

export function createDistributedRateLimiter(
    config: NomadConfig,
    redisClient?: RedisLike | null,
    logger?: StructuredLogger
): DistributedRateLimiter {
    if (redisClient) {
        return new RedisDistributedRateLimiter(
            redisClient,
            config.maxConnections,
            config.maxHandshakesPerMinute
        );
    }
    return new NullDistributedRateLimiter(logger);
}
