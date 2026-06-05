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
import { SovereignOrganism } from './organism/sovereign_organism';
import { CryptoService } from './crypto/crypto_service';
import { QuantumSafeCA } from './crypto/qs_ca';

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
 * Full sovereign security stack — every organ wired through SovereignOrganism.
 * Gateway, PQC, console, and vaults share one vital pulse. Compromise one organ → total lockdown.
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
    readonly organism: SovereignOrganism;

    private constructor(
        private config: NomadConfig,
        distributedLimiter: ReturnType<typeof createDistributedRateLimiter>,
        consoleAuth: ConsoleAuthService,
        audit: AuditLog,
        organism: SovereignOrganism,
        qsCa: QuantumSafeCA
    ) {
        this.logger = new StructuredLogger(config.logLevel);
        this.audit = audit;
        this.metrics = new MetricsCollector();
        this.organism = organism;
        this.consoleAuth = consoleAuth;
        this.consoleAuth.setVitalGuard(organism);

        const sessionStore = SessionStore.fromEnv(this.logger);
        this.pqc = new PQCServerService(config, {
            audit: this.audit,
            metrics: this.metrics,
            sessionStore,
            distributedLimiter,
            vitalGuard: organism,
            qsCa,
        });
        this.gateway = new ApiGateway(
            config,
            this.logger,
            this.audit,
            (token) => this.consoleAuth.resolvePrincipal(token),
            distributedLimiter,
            organism
        );
        this.console = new ConsoleServer(config, this.consoleAuth, this.logger, this.audit, async () => {
            organism.requireVital('console.key_rotation');
            this.pqc.rotateKeys();
        });
        this.dbVault = new DbVault({
            keyPath: config.dbVaultKeyPath,
            audit: this.audit,
            devMode: config.devMode,
            logger: this.logger,
            vitalGuard: organism,
        });
        const fileVaultKey = loadOrCreateVaultKey(config.fileVaultKeyPath, config.devMode);
        this.fileVault = new FileVault(config.vaultDir, this.audit, fileVaultKey, undefined, organism);
        this.wireRoutes();
    }

    static async create(config: NomadConfig): Promise<SovereignStack> {
        const logger = new StructuredLogger(config.logLevel);
        const audit = new AuditLog();
        const crypto = new CryptoService(config.algorithmSuite);
        const qsCa = new QuantumSafeCA(crypto);

        const redis = await createRedisClient(config.redisUrl, logger);
        const distributedLimiter = createDistributedRateLimiter(config, redis, logger);

        const consoleAuth = await ConsoleAuthService.create(config, audit);

        const redisPing = config.redisUrl && redis?.ping
            ? async () => {
                try {
                    await redis.ping!();
                    return true;
                } catch {
                    return false;
                }
            }
            : undefined;

        const organism = new SovereignOrganism(
            config,
            {
                audit,
                ctLog: qsCa.ctLog,
                redisPing,
                webauthnReady: () => consoleAuth.webauthn.hasCredentials('admin'),
            },
            logger
        );

        await organism.awaken();
        consoleAuth.setVitalGuard(organism);

        return new SovereignStack(config, distributedLimiter, consoleAuth, audit, organism, qsCa);
    }

    private wireRoutes(): void {
        this.gateway.route('GET', '/health', async () => ({
            status: 200,
            body: {
                status: this.organism.isVital() ? 'ok' : 'lockdown',
                chaosMode: this.config.chaosModeEnabled,
                organism: this.organism.isVital(),
            },
        }), 'viewer');

        this.gateway.route('GET', '/organism/vitals', async () => ({
            status: 200,
            body: this.organism.getVitalsReport(),
        }), 'viewer');

        this.gateway.route('GET', '/metrics', async () => {
            this.organism.requireVital('gateway.metrics');
            return { status: 200, body: this.metrics.snapshot() };
        }, 'operator');

        this.gateway.route('GET', '/api/audit', async () => {
            this.organism.requireVital('gateway.audit');
            return { status: 200, body: { events: this.audit.query(50) } };
        }, 'admin');

        this.gateway.route('POST', '/api/encrypt', async (ctx) => {
            this.organism.requireVital('gateway.encrypt');
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
            this.organism.requireVital('gateway.vault_upload');
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
            this.organism.requireVital('gateway.vault_download');
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
        this.logger.info('Sovereign organism online — interlocking organs active', {
            component: 'sovereign',
            pqcPort: this.config.port,
            gatewayPort: this.config.gatewayPort,
            consolePort: this.config.consolePort,
            chaosMode: this.config.chaosModeEnabled,
            fingerprint: this.organism.getFingerprint(),
            vital: this.organism.isVital(),
        });
    }

    async stop(): Promise<void> {
        this.organism.stopPulse();
        this.gateway.stop();
        this.console.stop();
        await this.pqc.stop();
    }

    getPqc(): PQCServerService {
        return this.pqc;
    }
}
