import * as fs from 'fs';
import { randomBytes } from 'crypto';
import { NomadConfig } from './config';
import { PQCServerService } from './pqc_server_service';
import { ApiGateway } from './gateway/api_gateway';
import { ConsoleAuthService } from './console/console_auth';
import { ConsoleServer } from './console/console_server';
import { DbVault } from './data/db_vault';
import { FileVault } from './vault/file_vault';
import { StructuredLogger } from './ops/logger';
import { AuditLog } from './ops/audit_log';
import { MetricsCollector } from './ops/metrics';
import { createDistributedRateLimiter } from './security/distributed_rate_limiter';
import { createRedisClient } from './startup/redis_client';
import { SessionStore } from './session/session_store';

const OBJECT_ID_RE = /^[a-f0-9]{24}$/;

function loadOrCreateVaultKey(path: string | null, devMode: boolean): Buffer {
    if (path && fs.existsSync(path)) {
        const raw = fs.readFileSync(path, 'utf8').trim();
        const key = Buffer.from(raw, 'hex');
        if (key.length !== 32) throw new Error(`Vault key at ${path} must be 64 hex chars.`);
        return key;
    }
    if (!devMode) {
        throw new Error('NOMAD_FILE_VAULT_KEY_PATH required when not in dev mode.');
    }
    return randomBytes(32);
}

/**
 * Full sovereign security stack — edge gateway, PQC mesh, console, DB/file vaults.
 */
export class SovereignStack {
    readonly pqc: PQCServerService;
    readonly gateway: ApiGateway;
    readonly consoleAuth: ConsoleAuthService;
    readonly console: ConsoleServer;
    readonly dbVault: DbVault;
    readonly fileVault: FileVault;
    readonly logger: StructuredLogger;
    readonly audit: AuditLog;
    readonly metrics: MetricsCollector;

    private constructor(
        private config: NomadConfig,
        distributedLimiter: ReturnType<typeof createDistributedRateLimiter>,
        consoleAuth: ConsoleAuthService,
        audit: AuditLog
    ) {
        this.logger = new StructuredLogger(config.logLevel);
        this.audit = audit;
        this.metrics = new MetricsCollector();
        this.consoleAuth = consoleAuth;
        const sessionStore = SessionStore.fromEnv(this.logger);
        this.pqc = new PQCServerService(config, {
            audit: this.audit,
            metrics: this.metrics,
            sessionStore,
            distributedLimiter,
        });
        this.gateway = new ApiGateway(
            config,
            this.logger,
            this.audit,
            (token) => this.consoleAuth.resolvePrincipal(token),
            distributedLimiter
        );
        this.console = new ConsoleServer(config, this.consoleAuth, this.logger, this.audit, async () => {
            this.pqc.rotateKeys();
        });
        this.dbVault = DbVault.fromEnv(this.audit, this.logger, config.devMode);
        const fileVaultKey = loadOrCreateVaultKey(config.fileVaultKeyPath, config.devMode);
        this.fileVault = new FileVault(config.vaultDir, this.audit, fileVaultKey);
        this.wireRoutes();
    }

    static async create(config: NomadConfig): Promise<SovereignStack> {
        const logger = new StructuredLogger(config.logLevel);
        const audit = new AuditLog();
        const redis = await createRedisClient(config.redisUrl, logger);
        const distributedLimiter = createDistributedRateLimiter(config, redis, logger);
        const consoleAuth = await ConsoleAuthService.create(config, audit);
        return new SovereignStack(config, distributedLimiter, consoleAuth, audit);
    }

    private wireRoutes(): void {
        this.gateway.route('GET', '/health', async () => ({
            status: 200,
            body: { status: 'ok', chaosMode: this.config.chaosModeEnabled },
        }), 'viewer');

        this.gateway.route('GET', '/metrics', async () => ({
            status: 200,
            body: this.metrics.snapshot(),
        }), 'operator');

        this.gateway.route('GET', '/api/audit', async () => ({
            status: 200,
            body: { events: this.audit.query(50) },
        }), 'admin');

        this.gateway.route('POST', '/api/encrypt', async (ctx) => {
            if (!ctx.principal) {
                return { status: 401, body: { error: 'UNAUTHORIZED' } };
            }
            const payload = JSON.parse(ctx.body.toString('utf8') || '{}') as { field?: string; value?: string };
            const tenant = ctx.principal.subject;
            const sealed = this.dbVault.encryptField(
                'api',
                String(payload.field ?? 'payload'),
                String(payload.value ?? ''),
                tenant
            );
            return { status: 200, body: { sealed } };
        }, 'operator');

        this.gateway.route('POST', '/vault/upload', async (ctx) => {
            if (!ctx.principal) {
                return { status: 401, body: { error: 'UNAUTHORIZED' } };
            }
            const payload = JSON.parse(ctx.body.toString('utf8') || '{}') as { filename?: string; data?: string };
            const buf = Buffer.from(String(payload.data ?? ''), 'base64');
            const owner = ctx.principal.subject;
            const objectId = await this.fileVault.store(String(payload.filename ?? 'blob.bin'), buf, owner);
            return { status: 200, body: { objectId } };
        }, 'operator');

        this.gateway.route('GET', '/vault/download', async (ctx) => {
            if (!ctx.principal) {
                return { status: 401, body: { error: 'UNAUTHORIZED' } };
            }
            const objectId = ctx.query.get('id') ?? '';
            if (!OBJECT_ID_RE.test(objectId)) {
                return { status: 400, body: { error: 'INVALID_OBJECT_ID' } };
            }
            const owner = ctx.principal.subject;
            try {
                const data = this.fileVault.retrieve(objectId, owner);
                return { status: 200, body: { data: data.toString('base64') } };
            } catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                if (msg.includes('access denied') || msg.includes('Access denied')) {
                    return { status: 403, body: { error: 'FORBIDDEN' } };
                }
                return { status: 404, body: { error: 'NOT_FOUND' } };
            }
        }, 'operator');
    }

    start(): void {
        this.pqc.start();
        this.gateway.start();
        this.console.start();
        this.logger.info('Sovereign stack online', {
            component: 'sovereign',
            pqcPort: this.config.port,
            gatewayPort: this.config.gatewayPort,
            consolePort: this.config.consolePort,
            chaosMode: this.config.chaosModeEnabled,
        });
    }

    async stop(): Promise<void> {
        this.gateway.stop();
        this.console.stop();
        await this.pqc.stop();
    }

    getPqc(): PQCServerService {
        return this.pqc;
    }
}
