export interface MetricsSnapshot {
    handshakesSucceeded: number;
    handshakesFailed: number;
    sessionsResumed: number;
    messagesEncrypted: number;
    messagesDecrypted: number;
    heartbeatsSent: number;
    heartbeatsReceived: number;
    replayRejected: number;
    rateLimitRejected: number;
    allowlistRejected: number;
    avgHandshakeMs: number;
    activeConnections: number;
}

export class MetricsCollector {
    private handshakesSucceeded = 0;
    private handshakesFailed = 0;
    private sessionsResumed = 0;
    private messagesEncrypted = 0;
    private messagesDecrypted = 0;
    private heartbeatsSent = 0;
    private heartbeatsReceived = 0;
    private replayRejected = 0;
    private rateLimitRejected = 0;
    private allowlistRejected = 0;
    private handshakeDurations: number[] = [];
    private activeConnections = 0;

    increment(metric: keyof Omit<MetricsSnapshot, 'avgHandshakeMs' | 'activeConnections'>, n = 1): void {
        switch (metric) {
            case 'handshakesSucceeded': this.handshakesSucceeded += n; break;
            case 'handshakesFailed': this.handshakesFailed += n; break;
            case 'sessionsResumed': this.sessionsResumed += n; break;
            case 'messagesEncrypted': this.messagesEncrypted += n; break;
            case 'messagesDecrypted': this.messagesDecrypted += n; break;
            case 'heartbeatsSent': this.heartbeatsSent += n; break;
            case 'heartbeatsReceived': this.heartbeatsReceived += n; break;
            case 'replayRejected': this.replayRejected += n; break;
            case 'rateLimitRejected': this.rateLimitRejected += n; break;
            case 'allowlistRejected': this.allowlistRejected += n; break;
        }
    }

    recordHandshakeDuration(ms: number): void {
        this.handshakeDurations.push(ms);
        if (this.handshakeDurations.length > 200) {
            this.handshakeDurations.shift();
        }
    }

    setActiveConnections(n: number): void {
        this.activeConnections = n;
    }

    snapshot(): MetricsSnapshot {
        const avg = this.handshakeDurations.length === 0
            ? 0
            : this.handshakeDurations.reduce((a, b) => a + b, 0) / this.handshakeDurations.length;
        return {
            handshakesSucceeded: this.handshakesSucceeded,
            handshakesFailed: this.handshakesFailed,
            sessionsResumed: this.sessionsResumed,
            messagesEncrypted: this.messagesEncrypted,
            messagesDecrypted: this.messagesDecrypted,
            heartbeatsSent: this.heartbeatsSent,
            heartbeatsReceived: this.heartbeatsReceived,
            replayRejected: this.replayRejected,
            rateLimitRejected: this.rateLimitRejected,
            allowlistRejected: this.allowlistRejected,
            avgHandshakeMs: Math.round(avg),
            activeConnections: this.activeConnections,
        };
    }
}
