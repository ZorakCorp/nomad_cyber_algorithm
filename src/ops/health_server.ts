import * as http from 'http';
import { MetricsCollector, MetricsSnapshot } from './metrics';

export interface HealthStatus {
    status: 'ok' | 'draining' | 'down';
    ready: boolean;
    metrics: MetricsSnapshot;
    uptimeSec: number;
}

export class HealthServer {
    private server: http.Server | null = null;
    private startedAt = Date.now();
    private draining = false;
    private ready = false;

    constructor(
        private port: number,
        private metrics: MetricsCollector,
        private getActiveConnections: () => number
    ) {}

    start(): void {
        this.server = http.createServer((req, res) => {
            if (req.url === '/health' && req.method === 'GET') {
                this.respond(res, this.buildStatus());
                return;
            }
            if (req.url === '/ready' && req.method === 'GET') {
                const status = this.buildStatus();
                res.writeHead(status.ready ? 200 : 503, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ ready: status.ready }));
                return;
            }
            if (req.url === '/metrics' && req.method === 'GET') {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(this.metrics.snapshot()));
                return;
            }
            res.writeHead(404);
            res.end();
        });
        this.server.listen(this.port, '127.0.0.1', () => {
            this.ready = true;
        });
    }

    setDraining(draining: boolean): void {
        this.draining = draining;
        if (draining) {
            this.ready = false;
        }
    }

    stop(): void {
        this.ready = false;
        this.server?.close();
    }

    private buildStatus(): HealthStatus {
        this.metrics.setActiveConnections(this.getActiveConnections());
        return {
            status: this.draining ? 'draining' : 'ok',
            ready: this.ready && !this.draining,
            metrics: this.metrics.snapshot(),
            uptimeSec: Math.floor((Date.now() - this.startedAt) / 1000),
        };
    }

    private respond(res: http.ServerResponse, status: HealthStatus): void {
        const code = status.status === 'down' ? 503 : 200;
        res.writeHead(code, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(status));
    }
}
