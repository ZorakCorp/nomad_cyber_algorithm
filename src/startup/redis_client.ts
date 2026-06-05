import { RedisLike } from '../security/distributed_rate_limiter';
import { StructuredLogger } from '../ops/logger';

export async function createRedisClient(url: string | null, logger?: StructuredLogger): Promise<RedisLike | null> {
    if (!url) return null;
    try {
        const { default: Redis } = await import('ioredis');
        const client = new Redis(url, {
            maxRetriesPerRequest: 1,
            connectTimeout: 5_000,
            lazyConnect: true,
        });
        await client.connect();
        await client.ping();
        logger?.info('Redis connected for distributed rate limiting', { component: 'redis_client' });
        return client;
    } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        logger?.warn(`Redis unavailable (${msg}) — falling back to in-memory rate limits only.`, {
            component: 'redis_client',
        });
        return null;
    }
}
