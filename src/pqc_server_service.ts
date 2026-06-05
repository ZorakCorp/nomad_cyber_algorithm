import { Signature } from '@open-quantum-safe/oqs-javascript';
import * as net from 'net';
import { NomadConfig, loadConfig } from './config';
import { CryptoService } from './crypto/crypto_service';
import { QuantumSafeCA, PQCertificate } from './crypto/qs_ca';
import { createKeyStore } from './crypto/hsm_adapter';
import { RecordLayer } from './crypto/record_layer';
import { KeyRotationManager, RotatingKemKeys } from './security/key_rotation';
import { ClientAllowlist } from './security/client_allowlist';
import { RateLimiter } from './security/rate_limiter';
import { ReplayGuard } from './security/replay_guard';
import {
    ServerHandshakePhase,
    WireMessage,
    encodeBinary,
    decodeBinary,
    serializeMessage,
    parseWireMessage,
    attachSecurityFields,
    buildClientAuthSignedPayload,
    buildServerAuthSignedPayload,
    buildSessionResumeSignedPayload,
} from './protocol';
import { validateWireMessage } from './schema';
import { SessionStore } from './session/session_store';
import { HeartbeatManager } from './session/heartbeat';
import { GracefulShutdown } from './session/graceful_shutdown';
import { TenantRouter } from './routing/tenant_router';
import { StructuredLogger } from './ops/logger';
import { MetricsCollector } from './ops/metrics';
import { AuditLog } from './ops/audit_log';
import { HealthServer } from './ops/health_server';
import { frameMessage, parseMessages, configureFraming } from './utils';
import { imperialConfigFromNomad } from './imperial/config';
import { MessageQueue } from './utils/message_queue';
import { jitteredDelay } from './chaos/timing_veil';
import { DistributedRateLimiter, createDistributedRateLimiter } from './security/distributed_rate_limiter';
import { VitalGuard } from './organism/vital_guard';

class PQCConnection {
    private clientSigPublicKey: Uint8Array | null = null;
    private aesKey: Buffer | null = null;
    private receivedBuffer: Buffer = Buffer.alloc(0);
    private phase: ServerHandshakePhase = 'idle';
    private correlationId: string | null = null;
    private handshakeTimer: NodeJS.Timeout | null = null;
    private handshakeStartedAt = 0;
    private handshakeSucceeded = false;
    private handshakeSlotReleased = false;
    private sendSequence = 0;
    private recvSequence = 0;
    private pinnedKem: RotatingKemKeys | null = null;

    private replayGuard = new ReplayGuard();
    private heartbeat: HeartbeatManager;
    private recordLayer: RecordLayer;
    private messageQueue = new MessageQueue();

    constructor(
        private socket: net.Socket,
        private crypto: CryptoService,
        private kemRotation: KeyRotationManager,
        private qsCa: QuantumSafeCA,
        private serverSig: Signature,
        private serverSigPrivateKey: Uint8Array,
        private serverSigPublicKey: Uint8Array,
        private config: NomadConfig,
        private allowlist: ClientAllowlist,
        private sessionStore: SessionStore,
        private router: TenantRouter,
        private logger: StructuredLogger,
        private metrics: MetricsCollector,
        private audit: AuditLog,
        private onReleaseHandshake: () => void,
        private onClose: () => void,
    ) {
        this.recordLayer = new RecordLayer(crypto);
        this.heartbeat = new HeartbeatManager(
            config.heartbeatIntervalMs,
            () => this.fail('Heartbeat timeout', 'HEARTBEAT_TIMEOUT')
        );
        this.bindSocket();
    }

    private log(message: string, extra: Record<string, unknown> = {}): void {
        this.logger.info(message, { component: 'server', correlationId: this.correlationId ?? 'pending', ...extra });
    }

    private releaseHandshakeSlot(): void {
        if (!this.handshakeSlotReleased) {
            this.handshakeSlotReleased = true;
            this.onReleaseHandshake();
        }
    }

    private fail(reason: string, code = 'HANDSHAKE_FAILED'): void {
        this.log(`Handshake failed: ${reason}`, { code });
        this.metrics.increment('handshakesFailed');
        this.audit.record('handshake_failed', { correlationId: this.correlationId ?? undefined, detail: reason });
        this.sendHandshakeError(reason, code);
        this.releaseHandshakeSlot();
        this.socket.end();
        this.clearHandshakeTimer();
        this.heartbeat.stop();
    }

    private sendHandshakeError(reason: string, code: string): void {
        if (this.phase === 'established' || this.phase === 'resumed') return;
        const errorMessage = attachSecurityFields({
            type: 'handshake_error',
            error: reason,
            errorCode: code,
        }, this.correlationId ?? 'unknown');
        try {
            this.socket.write(frameMessage(serializeMessage(errorMessage)));
        } catch { /* ignore */ }
    }

    private clearHandshakeTimer(): void {
        if (this.handshakeTimer) {
            clearTimeout(this.handshakeTimer);
            this.handshakeTimer = null;
        }
    }

    private startHandshakeTimer(): void {
        this.clearHandshakeTimer();
        this.handshakeTimer = setTimeout(() => {
            this.fail(`Handshake timed out after ${this.config.handshakeTimeoutMs}ms`, 'HANDSHAKE_TIMEOUT');
        }, this.config.handshakeTimeoutMs);
    }

    private validateIncoming(msg: WireMessage): void {
        validateWireMessage(msg);
        if (msg.nonce && msg.timestamp && msg.correlationId) {
            try {
                this.replayGuard.validate(msg.nonce, msg.timestamp, msg.correlationId);
            } catch (err) {
                this.metrics.increment('replayRejected');
                this.audit.record('replay_detected', { correlationId: msg.correlationId });
                throw err;
            }
        }
    }

    private bindSocket(): void {
        this.socket.on('data', (data) => {
            try {
                this.receivedBuffer = Buffer.concat([this.receivedBuffer, data]);
                this.receivedBuffer = parseMessages(this.receivedBuffer, (message) => {
                    this.messageQueue.enqueue(
                        () => this.processMessage(message),
                        (err) => this.fail(err instanceof Error ? err.message : String(err), 'MESSAGE_ERROR')
                    );
                });
            } catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                this.fail(`Framing error: ${msg}`);
            }
        });

        this.socket.on('close', () => {
            this.log('Client disconnected');
            this.releaseHandshakeSlot();
            this.clearHandshakeTimer();
            this.heartbeat.stop();
            this.wipeSecrets();
            this.audit.record('connection_closed', { correlationId: this.correlationId ?? undefined });
            this.onClose();
        });

        this.socket.on('error', (err) => {
            this.logger.error('Socket error', { component: 'server', correlationId: this.correlationId ?? 'pending', error: err.message });
            this.clearHandshakeTimer();
            this.onClose();
        });
    }

    private async processMessage(message: Buffer): Promise<void> {
        const parsed = parseWireMessage(message);
        this.validateIncoming(parsed);

        if (this.correlationId && parsed.correlationId && parsed.correlationId !== this.correlationId) {
            this.fail('Correlation ID mismatch', 'CORRELATION_MISMATCH');
            return;
        }

        switch (parsed.type) {
            case 'client_hello':
                this.handleClientHello(parsed);
                break;
            case 'session_resume':
                this.handleSessionResume(parsed);
                break;
            case 'client_auth_response':
                await this.handleClientAuthResponse(parsed);
                break;
            case 'encrypted_data':
                await this.handleEncryptedData(parsed);
                break;
            case 'heartbeat_ping':
                if (parsed.sequence !== undefined && this.correlationId) {
                    this.metrics.increment('heartbeatsReceived');
                    this.heartbeat.sendPong(this.socket, this.correlationId, parsed.sequence);
                }
                break;
            case 'heartbeat_pong':
                this.heartbeat.handlePong();
                break;
            case 'close_notify':
                this.log('Received close_notify');
                this.socket.end();
                break;
            default:
                this.fail(`Unexpected message: ${parsed.type}`, 'UNEXPECTED_MESSAGE');
        }
    }

    private handleClientHello(parsed: WireMessage): void {
        if (this.phase !== 'idle') {
            this.fail(`client_hello in invalid phase: ${this.phase}`);
            return;
        }
        this.correlationId = parsed.correlationId!;
        this.handshakeStartedAt = Date.now();
        this.audit.record('handshake_started', { correlationId: this.correlationId, peer: this.socket.remoteAddress ?? undefined });
        this.startHandshakeTimer();

        this.pinnedKem = this.kemRotation.getActiveKeys();
        const liveCert = this.qsCa.issueCertificate(
            'nomad-server',
            this.serverSigPublicKey,
            this.pinnedKem.pair.publicKey
        );

        const serverHello = attachSecurityFields({
            type: 'server_hello',
            kemPublicKey: encodeBinary(this.pinnedKem.pair.publicKey),
            sigPublicKey: encodeBinary(this.serverSigPublicKey),
            certificate: liveCert,
        }, this.correlationId);
        this.socket.write(frameMessage(serializeMessage(serverHello)));
        this.phase = 'server_hello_sent';
    }

    private handleSessionResume(parsed: WireMessage): void {
        if (this.phase !== 'idle' || !parsed.sessionTicket) {
            this.fail('Invalid session_resume');
            return;
        }

        if (!parsed.signature || !parsed.clientPublicKeySig) {
            this.fail('session_resume missing proof-of-possession signature', 'RESUME_PROOF_MISSING');
            return;
        }

        const payload = this.sessionStore.redeem(parsed.sessionTicket);
        if (!payload) {
            this.fail('Invalid or expired session ticket', 'SESSION_EXPIRED');
            return;
        }

        const clientSigPublicKey = decodeBinary(parsed.clientPublicKeySig, 'clientPublicKeySig');
        if (encodeBinary(clientSigPublicKey) !== payload.clientSigPublicKey) {
            this.fail('Resume client key does not match ticket', 'RESUME_KEY_MISMATCH');
            return;
        }

        if (!this.allowlist.isAllowed(clientSigPublicKey)) {
            this.metrics.increment('allowlistRejected');
            this.fail('Client not on allowlist', 'ALLOWLIST_REJECTED');
            return;
        }

        const resumeData = buildSessionResumeSignedPayload(
            parsed.sessionTicket,
            clientSigPublicKey,
            payload.correlationId,
            parsed.nonce!,
            parsed.timestamp!
        );
        const resumeSig = decodeBinary(parsed.signature, 'signature');
        if (!this.crypto.verify(this.serverSig, clientSigPublicKey, resumeData, resumeSig)) {
            this.fail('Session resume signature verification failed', 'RESUME_SIG_INVALID');
            return;
        }

        this.correlationId = payload.correlationId;
        this.aesKey = Buffer.from(payload.aesKeyHex, 'hex');
        this.clientSigPublicKey = clientSigPublicKey;
        this.handshakeStartedAt = Date.now();
        this.activateImperialLayers();

        const serverAuth = attachSecurityFields({
            type: 'server_auth_response',
            sigPublicKey: encodeBinary(this.serverSigPublicKey),
            sessionTicket: parsed.sessionTicket,
        }, this.correlationId);

        const serverAuthData = buildServerAuthSignedPayload(
            this.serverSigPublicKey,
            this.correlationId,
            serverAuth.nonce!,
            serverAuth.timestamp!,
            parsed.sessionTicket
        );
        const serverSignature = this.crypto.sign(this.serverSig, this.serverSigPrivateKey, serverAuthData);
        serverAuth.signature = encodeBinary(serverSignature);
        this.socket.write(frameMessage(serializeMessage(serverAuth)));
        this.phase = 'resumed';
        this.handshakeComplete();
        this.metrics.increment('sessionsResumed');
        this.audit.record('session_resumed', { correlationId: this.correlationId });
    }

    private async handleClientAuthResponse(parsed: WireMessage): Promise<void> {
        if (this.phase !== 'server_hello_sent') {
            this.fail(`client_auth_response in invalid phase: ${this.phase}`);
            return;
        }

        const clientSigPublicKey = decodeBinary(parsed.clientPublicKeySig!, 'clientPublicKeySig');
        if (!this.allowlist.isAllowed(clientSigPublicKey)) {
            this.metrics.increment('allowlistRejected');
            this.audit.record('client_rejected_allowlist', { correlationId: this.correlationId ?? undefined });
            this.fail('Client not on allowlist', 'ALLOWLIST_REJECTED');
            return;
        }

        const clientKemPublicKey = decodeBinary(parsed.kemPublicKey!, 'kemPublicKey');
        const encapsulatedKey = decodeBinary(parsed.encapsulatedKey!, 'encapsulatedKey');
        const clientSignature = decodeBinary(parsed.signature!, 'signature');
        this.clientSigPublicKey = clientSigPublicKey;

        const clientSignedData = buildClientAuthSignedPayload(
            clientSigPublicKey,
            clientKemPublicKey,
            this.correlationId!,
            parsed.nonce!,
            parsed.timestamp!
        );
        if (!this.crypto.verify(this.serverSig, clientSigPublicKey, clientSignedData, clientSignature)) {
            this.fail('Client signature verification failed', 'CLIENT_SIG_INVALID');
            return;
        }

        const kemKeys = this.pinnedKem ?? this.kemRotation.getActiveKeys();
        const sharedSecret = this.crypto.decapsulate(
            this.kemRotation.getKem(),
            kemKeys.pair.privateKey,
            encapsulatedKey
        );
        if (!sharedSecret) {
            this.fail('KEM decapsulation failed');
            return;
        }
        this.aesKey = this.crypto.deriveChannelKey(sharedSecret, this.correlationId!);
        this.activateImperialLayers();

        const sessionTicket = this.sessionStore.issue(
            this.correlationId!,
            this.aesKey,
            encodeBinary(clientSigPublicKey),
            encodeBinary(this.serverSigPublicKey),
            this.config.sessionTtlMs
        );

        const serverAuth = attachSecurityFields({
            type: 'server_auth_response',
            sigPublicKey: encodeBinary(this.serverSigPublicKey),
            sessionTicket,
        }, this.correlationId!);

        const serverAuthData = buildServerAuthSignedPayload(
            this.serverSigPublicKey,
            this.correlationId!,
            serverAuth.nonce!,
            serverAuth.timestamp!,
            sessionTicket
        );
        const serverSignature = this.crypto.sign(this.serverSig, this.serverSigPrivateKey, serverAuthData);
        serverAuth.signature = encodeBinary(serverSignature);
        this.socket.write(frameMessage(serializeMessage(serverAuth)));
        this.phase = 'established';
        this.handshakeComplete();
    }

    private activateImperialLayers(): void {
        if (!this.aesKey || !this.correlationId) return;
        this.recordLayer.setImperialChannel(
            this.aesKey,
            this.correlationId,
            imperialConfigFromNomad(this.config)
        );
    }

    private handshakeComplete(): void {
        this.handshakeSucceeded = true;
        this.clearHandshakeTimer();
        this.activateImperialLayers();
        this.heartbeat.start((buf) => this.socket.write(buf), this.correlationId!);
        const duration = Date.now() - this.handshakeStartedAt;
        this.metrics.increment('handshakesSucceeded');
        this.metrics.recordHandshakeDuration(duration);
        this.audit.record('handshake_succeeded', { correlationId: this.correlationId ?? undefined, detail: `${duration}ms` });
        this.log('Secure channel established', { durationMs: duration });
    }

    private async handleEncryptedData(parsed: WireMessage): Promise<void> {
        if ((this.phase !== 'established' && this.phase !== 'resumed') || !this.aesKey) {
            this.fail('encrypted_data before secure channel');
            return;
        }
        if (parsed.sequence === undefined) {
            this.fail('encrypted_data missing sequence');
            return;
        }
        if (parsed.sequence !== this.recvSequence + 1) {
            this.fail(
                parsed.sequence <= this.recvSequence ? 'Sequence replay detected' : 'Sequence gap detected',
                'SEQUENCE_ERROR'
            );
            return;
        }
        this.recvSequence = parsed.sequence;

        let record;
        try {
            record = this.recordLayer.open(this.aesKey, {
                ciphertext: Buffer.from(parsed.data!, 'hex'),
                iv: Buffer.from(parsed.iv!, 'hex'),
                authTag: Buffer.from(parsed.authTag!, 'hex'),
                sequence: parsed.sequence,
            }, parsed.timestamp);
        } catch {
            this.fail('Decryption failed', 'DECRYPT_FAILED');
            return;
        }

        this.metrics.increment('messagesDecrypted');
        this.audit.record('message_decrypted', { correlationId: this.correlationId ?? undefined, detail: record.recordType });

        const responseBody = await this.router.route(record.serviceId, record.body, this.correlationId!);
        if (this.config.chaosModeEnabled && this.config.chaosJitterMs > 0) {
            await jitteredDelay(this.config.chaosJitterMs, parsed.sequence, this.correlationId!);
        }
        this.sendSequence++;
        const imperialTs = parsed.timestamp ?? Date.now();
        const sealed = this.recordLayer.seal(this.aesKey, {
            recordType: 'application',
            serviceId: record.serviceId,
            body: responseBody,
            imperialTimestamp: imperialTs,
        }, this.sendSequence);

        const wire = attachSecurityFields({
            type: 'encrypted_data',
            sequence: this.sendSequence,
            serviceId: record.serviceId,
            data: sealed.ciphertext.toString('hex'),
            iv: sealed.iv.toString('hex'),
            authTag: sealed.authTag.toString('hex'),
        }, this.correlationId!, imperialTs);
        this.socket.write(frameMessage(serializeMessage(wire)));
        this.metrics.increment('messagesEncrypted');
        this.audit.record('message_encrypted', { correlationId: this.correlationId ?? undefined });
    }

    private wipeSecrets(): void {
        this.crypto.destroyKey(this.aesKey);
        this.aesKey = null;
    }
}

export class PQCServerService {
    private crypto: CryptoService;
    private kemRotation: KeyRotationManager;
    private serverSig: Signature;
    private serverSigPrivateKey: Uint8Array;
    private serverSigPublicKey: Uint8Array;
    private qsCa: QuantumSafeCA;

    private allowlist: ClientAllowlist;
    private rateLimiter: RateLimiter;
    private sessionStore: SessionStore;
    private router = new TenantRouter();
    private logger: StructuredLogger;
    private metrics = new MetricsCollector();
    private audit = new AuditLog();
    private shutdown = new GracefulShutdown();
    private health: HealthServer;

    private server: net.Server | null = null;
    private distributedLimiter: DistributedRateLimiter;
    private vitalGuard?: VitalGuard;

    constructor(
        private config: NomadConfig = loadConfig(),
        deps?: {
            audit?: AuditLog;
            metrics?: MetricsCollector;
            sessionStore?: SessionStore;
            distributedLimiter?: DistributedRateLimiter;
            vitalGuard?: VitalGuard;
            qsCa?: QuantumSafeCA;
        }
    ) {
        configureFraming(this.config);
        this.crypto = new CryptoService(this.config.algorithmSuite);
        this.logger = new StructuredLogger(this.config.logLevel);
        if (deps?.audit) this.audit = deps.audit;
        if (deps?.metrics) this.metrics = deps.metrics;
        this.sessionStore = deps?.sessionStore ?? SessionStore.fromEnv(this.logger, this.config.devMode);
        this.distributedLimiter = deps?.distributedLimiter ??
            createDistributedRateLimiter(this.config, null, this.logger);
        this.vitalGuard = deps?.vitalGuard;
        this.qsCa = deps?.qsCa ?? new QuantumSafeCA(this.crypto);
        createKeyStore(this.crypto, this.config.hsmEnabled);
        this.kemRotation = new KeyRotationManager(this.crypto, 'server-kem');
        this.allowlist = new ClientAllowlist(this.config.clientAllowlist, this.config.requireAllowlist);
        this.rateLimiter = new RateLimiter(this.config.maxConnections, this.config.maxHandshakesPerMinute);

        this.serverSig = this.crypto.createSig();
        const sigPair = this.crypto.generateSigKeyPair(this.serverSig);
        this.serverSigPrivateKey = sigPair.privateKey;
        this.serverSigPublicKey = sigPair.publicKey;

        this.router.register('default', async (body) => {
            const text = body.toString('utf8');
            return Buffer.from(`Processed secure data (${text.length} chars).`);
        });

        this.health = new HealthServer(
            this.config.healthPort,
            this.metrics,
            () => this.shutdown.activeCount()
        );
    }

    getQuantumSafeCA(): QuantumSafeCA {
        return this.qsCa;
    }

    getRouter(): TenantRouter {
        return this.router;
    }

    registerClient(publicKey: Uint8Array): void {
        this.allowlist.register(publicKey);
    }

    private async acceptConnection(socket: net.Socket): Promise<void> {
        if (this.vitalGuard && !this.vitalGuard.isVital()) {
            this.audit.record('handshake_failed', { detail: 'PQC blocked — organism not vital' });
            socket.destroy();
            return;
        }
        if (this.shutdown.isShuttingDown()) {
            socket.destroy();
            return;
        }
        const peerIp = socket.remoteAddress ?? 'unknown';
        if (!this.rateLimiter.tryAcquireConnection()) {
            this.metrics.increment('rateLimitRejected');
            this.audit.record('rate_limit_exceeded', { detail: 'max connections' });
            socket.destroy();
            return;
        }
        if (!(await this.distributedLimiter.tryAcquireConnection(peerIp))) {
            this.metrics.increment('rateLimitRejected');
            this.audit.record('rate_limit_exceeded', { detail: 'distributed connection cap' });
            socket.destroy();
            this.rateLimiter.releaseConnection();
            return;
        }
        if (!this.rateLimiter.tryAcquireHandshake()) {
            this.metrics.increment('rateLimitRejected');
            this.audit.record('rate_limit_exceeded', { detail: 'handshake rate' });
            socket.destroy();
            this.rateLimiter.releaseConnection();
            return;
        }
        if (!(await this.distributedLimiter.tryAcquireHandshake(peerIp))) {
            this.metrics.increment('rateLimitRejected');
            this.audit.record('rate_limit_exceeded', { detail: 'distributed handshake rate' });
            socket.destroy();
            this.rateLimiter.releaseConnection();
            return;
        }

        let connectionReleased = false;
        const releaseConnection = () => {
            if (!connectionReleased) {
                connectionReleased = true;
                this.rateLimiter.releaseConnection();
            }
        };
        const releaseHandshake = () => {
            this.rateLimiter.releaseHandshake();
        };

        this.shutdown.track(socket);
        this.logger.info('Client connected', { component: 'server', peer: peerIp });

        new PQCConnection(
            socket,
            this.crypto,
            this.kemRotation,
            this.qsCa,
            this.serverSig,
            this.serverSigPrivateKey,
            this.serverSigPublicKey,
            this.config,
            this.allowlist,
            this.sessionStore,
            this.router,
            this.logger,
            this.metrics,
            this.audit,
            releaseHandshake,
            releaseConnection,
        );
    }

    start(): void {
        if (this.config.requireAllowlist && this.allowlist.size() === 0) {
            throw new Error('Allowlist is required but no client keys are registered or configured.');
        }
        this.health.start();
        this.server = net.createServer((socket) => {
            void this.acceptConnection(socket);
        });

        this.server.listen(this.config.port, this.config.bindHost, () => {
            this.logger.info('Server listening', {
                component: 'server',
                host: this.config.bindHost,
                port: this.config.port,
                healthPort: this.config.healthPort,
                devMode: this.config.devMode,
            });
        });
    }

    async stop(): Promise<void> {
        this.health.setDraining(true);
        await this.shutdown.shutdown(this.config.gracefulShutdownMs);
        this.server?.close();
        this.health.stop();
        this.logger.info('Server stopped', { component: 'server' });
    }

    getMetrics() {
        return this.metrics.snapshot();
    }

    getAuditLog() {
        return this.audit.query();
    }

    rotateKeys(): void {
        this.kemRotation.rotate();
        this.audit.record('key_rotated', { detail: 'server-kem' });
    }
}
