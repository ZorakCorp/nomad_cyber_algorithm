import * as http from 'http';
import { NomadConfig } from '../config';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import { ConsoleAuthService } from './console_auth';
import type { ZkProof } from './zk_auth';
import { applySecurityHeaders } from '../gateway/security_headers';
import { StructuredLogger } from '../ops/logger';
import { AuditLog } from '../ops/audit_log';

export class ConsoleServer {
    private server: http.Server | null = null;

    constructor(
        private config: NomadConfig,
        private auth: ConsoleAuthService,
        private logger: StructuredLogger,
        private audit: AuditLog,
        private onRotateKeys?: () => Promise<void>
    ) {}

    start(): void {
        this.server = http.createServer((req, res) => {
            applySecurityHeaders(res);
            void this.handle(req, res).catch((err) => {
                const msg = err instanceof Error ? err.message : String(err);
                this.logger.error('Console handler error', { component: 'console', error: msg });
                if (!res.headersSent) {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'INTERNAL_ERROR' }));
                }
            });
        });
        this.server.listen(this.config.consolePort, this.config.bindHost, () => {
            this.logger.info('Console server listening', {
                component: 'console',
                host: this.config.bindHost,
                port: this.config.consolePort,
                mfa: this.config.consoleMfaRequired,
            });
        });
    }

    stop(): void {
        this.server?.close();
    }

    private async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
        const url = new URL(req.url ?? '/', `http://${this.config.bindHost}`);
        const path = url.pathname;
        const method = req.method ?? 'GET';

        if (method === 'POST' && path === '/console/login') {
            const body = await this.readJson(req);
            const result = await this.auth.login(String(body.username ?? ''), String(body.password ?? ''));
            if (!result) {
                res.writeHead(401, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'INVALID_CREDENTIALS' }));
                return;
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(result));
            return;
        }

        if (method === 'POST' && path === '/console/mfa') {
            const body = await this.readJson(req);
            const ok = this.auth.verifyMfa(String(body.sessionToken ?? ''), String(body.code ?? ''));
            res.writeHead(ok ? 200 : 401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ verified: ok }));
            return;
        }

        if (method === 'POST' && path === '/console/webauthn/begin') {
            const body = await this.readJson(req);
            const result = await this.auth.beginWebAuthn(String(body.username ?? ''));
            if (!result) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'USER_NOT_FOUND' }));
                return;
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(result));
            return;
        }

        if (method === 'POST' && path === '/console/webauthn/verify') {
            const body = await this.readJson(req);
            const ok = await this.auth.verifyWebAuthn(
                String(body.sessionToken ?? ''),
                String(body.sessionId ?? ''),
                body.response as AuthenticationResponseJSON
            );
            res.writeHead(ok ? 200 : 401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ verified: ok }));
            return;
        }

        if (method === 'POST' && path === '/console/zk/challenge') {
            const body = await this.readJson(req);
            const challenge = this.auth.issueZkChallenge(String(body.username ?? ''));
            if (!challenge) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'ZK_NOT_APPLICABLE' }));
                return;
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(challenge));
            return;
        }

        if (method === 'POST' && path === '/console/zk/verify') {
            const body = await this.readJson(req);
            const ok = this.auth.verifyZkProof(String(body.sessionToken ?? ''), body.proof as ZkProof);
            res.writeHead(ok ? 200 : 401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ verified: ok }));
            return;
        }

        const session = this.extractSession(req);
        if (!session) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'UNAUTHORIZED' }));
            return;
        }

        if (method === 'GET' && path === '/console/status') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                user: session.username,
                roles: session.roles,
                chaosMode: this.config.chaosModeEnabled,
                mfaVerified: session.mfaVerified,
            }));
            return;
        }

        if (method === 'POST' && path === '/console/rotate-keys') {
            if (!session.roles.includes('sovereign')) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'FORBIDDEN' }));
                return;
            }
            if (!this.onRotateKeys) {
                res.writeHead(503, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'ROTATION_NOT_CONFIGURED' }));
                return;
            }
            await this.onRotateKeys();
            this.audit.record('key_rotated', { detail: `console:${session.username}` });
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ rotated: true }));
            return;
        }

        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'NOT_FOUND' }));
    }

    private extractSession(req: http.IncomingMessage) {
        const auth = req.headers.authorization;
        if (!auth?.startsWith('Bearer ')) return null;
        return this.auth.resolveSession(auth.slice(7).trim());
    }

    private readJson(req: http.IncomingMessage): Promise<Record<string, unknown>> {
        const maxBytes = this.config.gatewayMaxBodyBytes;
        return new Promise((resolve, reject) => {
            const chunks: Buffer[] = [];
            let size = 0;
            req.on('data', (c: Buffer) => {
                size += c.length;
                if (size > maxBytes) {
                    reject(new Error('Body too large'));
                    req.destroy();
                    return;
                }
                chunks.push(c);
            });
            req.on('end', () => {
                try {
                    resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
                } catch {
                    reject(new Error('Invalid JSON'));
                }
            });
            req.on('error', reject);
        });
    }
}
