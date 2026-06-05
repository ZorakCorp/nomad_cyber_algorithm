import * as http from 'http';
import { NomadConfig } from '../config';
import { RbacPolicy, Principal } from './rbac';
import { applySecurityHeaders } from './security_headers';
import { RateLimiter } from '../security/rate_limiter';
import { DistributedRateLimiter, createDistributedRateLimiter } from '../security/distributed_rate_limiter';
import { StructuredLogger } from '../ops/logger';
import { AuditLog } from '../ops/audit_log';
import { VitalGuard } from '../organism/vital_guard';

export interface GatewayContext {
    principal: Principal | null;
    correlationId: string;
    body: Buffer;
    query: URLSearchParams;
}

export type GatewayHandler = (ctx: GatewayContext) => Promise<{ status: number; body: unknown }>;
export type SessionResolver = (token: string) => Principal | null;

export class ApiGateway {
    private server: http.Server | null = null;
    private routes = new Map<string, GatewayHandler>();
    private publicRoutes = new Set<string>(['GET /health', 'GET /organism/vitals']);
    private rbac = new RbacPolicy();
    private rateLimiter: RateLimiter;
    private distributedLimiter: DistributedRateLimiter;

    constructor(
        private config: NomadConfig,
        private logger: StructuredLogger,
        private audit: AuditLog,
        private resolveSession?: SessionResolver,
        distributedLimiter?: DistributedRateLimiter,
        private vitalGuard?: VitalGuard
    ) {
        this.rateLimiter = new RateLimiter(config.maxConnections, config.maxHandshakesPerMinute);
        this.distributedLimiter = distributedLimiter ??
            createDistributedRateLimiter(config, null, logger);
    }

    getRbac(): RbacPolicy {
        return this.rbac;
    }

    route(method: string, path: string, handler: GatewayHandler, minRole: 'viewer' | 'operator' | 'admin' | 'sovereign' = 'operator'): void {
        this.rbac.register(method, path, minRole);
        this.routes.set(`${method.toUpperCase()} ${path}`, handler);
    }

    start(): void {
        this.server = http.createServer((req, res) => {
            applySecurityHeaders(res);
            void this.handle(req, res);
        });
        this.server.listen(this.config.gatewayPort, this.config.bindHost, () => {
            this.logger.info('API gateway listening', {
                component: 'gateway',
                host: this.config.bindHost,
                port: this.config.gatewayPort,
            });
        });
    }

    stop(): void {
        this.server?.close();
    }

    private async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
        const method = req.method ?? 'GET';
        const url = new URL(req.url ?? '/', `http://${this.config.bindHost}`);
        const path = url.pathname;
        const routeKey = `${method.toUpperCase()} ${path}`;
        const correlationId = req.headers['x-correlation-id']?.toString() ?? `gw-${Date.now()}`;

        const clientIp = req.socket.remoteAddress ?? 'unknown';
        if (!this.rateLimiter.tryAcquireConnection()) {
            this.audit.record('rate_limit_exceeded', { correlationId, detail: 'gateway connection cap' });
            res.writeHead(429, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'RATE_LIMITED' }));
            return;
        }
        if (!(await this.distributedLimiter.tryAcquireConnection(clientIp))) {
            this.audit.record('rate_limit_exceeded', { correlationId, detail: 'gateway distributed cap' });
            this.rateLimiter.releaseConnection();
            res.writeHead(429, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'RATE_LIMITED' }));
            return;
        }

        try {
            const body = await this.readBody(req);
            if (body.length > this.config.gatewayMaxBodyBytes) {
                res.writeHead(413, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'PAYLOAD_TOO_LARGE' }));
                return;
            }

            const principal = this.parsePrincipal(req);
            const isPublic = this.publicRoutes.has(routeKey);
            if (!isPublic && this.vitalGuard && !this.vitalGuard.isVital()) {
                this.audit.record('handshake_failed', { correlationId, detail: `gateway lockdown: ${method} ${path}` });
                res.writeHead(503, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    error: 'ORGANISM_LOCKDOWN',
                    message: 'All security organs must be vital simultaneously. Partial breach = total shutdown.',
                }));
                return;
            }
            if (!isPublic && !this.rbac.authorize(principal, method, path)) {
                this.audit.record('client_rejected_allowlist', { correlationId, detail: `${method} ${path}` });
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'FORBIDDEN' }));
                return;
            }

            const handler = this.routes.get(routeKey);
            if (!handler) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'NOT_FOUND' }));
                return;
            }

            const result = await handler({ principal, correlationId, body, query: url.searchParams });
            res.writeHead(result.status, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(result.body));
        } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            this.logger.error('Gateway error', { component: 'gateway', correlationId, error: msg });
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'INTERNAL_ERROR' }));
        } finally {
            this.rateLimiter.releaseConnection();
        }
    }

    private parsePrincipal(req: http.IncomingMessage): Principal | null {
        const auth = req.headers.authorization;
        if (!auth?.startsWith('Bearer ') || !this.resolveSession) return null;
        const token = auth.slice(7).trim();
        if (!token) return null;
        return this.resolveSession(token);
    }

    private readBody(req: http.IncomingMessage): Promise<Buffer> {
        return new Promise((resolve, reject) => {
            const chunks: Buffer[] = [];
            let size = 0;
            req.on('data', (chunk: Buffer) => {
                size += chunk.length;
                if (size > this.config.gatewayMaxBodyBytes) {
                    reject(new Error('Body too large'));
                    req.destroy();
                    return;
                }
                chunks.push(chunk);
            });
            req.on('end', () => resolve(Buffer.concat(chunks)));
            req.on('error', reject);
        });
    }
}
