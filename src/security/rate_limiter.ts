export class RateLimiter {
    private activeConnections = 0;
    private activeHandshakes = 0;
    private handshakeTimestamps: number[] = [];

    constructor(
        private maxConnections: number,
        private maxHandshakesPerMinute: number
    ) {}

    tryAcquireConnection(): boolean {
        if (this.activeConnections >= this.maxConnections) {
            return false;
        }
        this.activeConnections++;
        return true;
    }

    releaseConnection(): void {
        this.activeConnections = Math.max(0, this.activeConnections - 1);
    }

    tryAcquireHandshake(): boolean {
        const now = Date.now();
        const windowStart = now - 60_000;
        this.handshakeTimestamps = this.handshakeTimestamps.filter((t) => t >= windowStart);
        if (this.handshakeTimestamps.length >= this.maxHandshakesPerMinute) {
            return false;
        }
        this.handshakeTimestamps.push(now);
        this.activeHandshakes++;
        return true;
    }

    releaseHandshake(): void {
        this.activeHandshakes = Math.max(0, this.activeHandshakes - 1);
    }

    snapshot(): { activeConnections: number; handshakesLastMinute: number; activeHandshakes: number } {
        const now = Date.now();
        const windowStart = now - 60_000;
        const recent = this.handshakeTimestamps.filter((t) => t >= windowStart);
        return {
            activeConnections: this.activeConnections,
            handshakesLastMinute: recent.length,
            activeHandshakes: this.activeHandshakes,
        };
    }
}
