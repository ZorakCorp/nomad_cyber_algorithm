import { Signature } from '@open-quantum-safe/oqs-javascript';
import { randomBytes } from 'crypto';
import * as net from 'net';
import { NomadConfig, loadConfig } from './config';
import { CryptoService } from './crypto/crypto_service';
import { verifyServerHelloIdentity } from './crypto/cert_verify';
import { QuantumSafeCA, PQCertificate } from './crypto/qs_ca';
import { RecordLayer } from './crypto/record_layer';
import { imperialConfigFromNomad } from './imperial/config';
import {
    HandshakePhase,
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
import { ClientSessionCache } from './session/client_session_cache';
import { validateWireMessage } from './schema';
import { ReplayGuard } from './security/replay_guard';
import { HeartbeatManager } from './session/heartbeat';
import { StructuredLogger } from './ops/logger';
import { frameMessage, parseMessages, configureFraming } from './utils';
import { MessageQueue } from './utils/message_queue';

export class PQCClientService {
    private crypto: CryptoService;
    private clientKem: ReturnType<CryptoService['createKem']>;
    private clientKemPublicKey: Uint8Array;
    private clientSig: Signature;
    private clientSigPrivateKey: Uint8Array;
    private clientSigPublicKey: Uint8Array;

    private serverKemPublicKey: Uint8Array | null = null;
    private serverSigPublicKey: Uint8Array | null = null;
    private pinnedServerSigPublicKey: string | null = null;

    private aesKey: Buffer | null = null;
    private sendSequence = 0;
    private recvSequence = 0;

    private socket: net.Socket | null = null;
    private receivedBuffer: Buffer = Buffer.alloc(0);
    private phase: HandshakePhase = 'idle';
    private handshakeComplete = false;
    private handshakeSettled = false;
    private correlationId: string;
    private sessionTicket: string | null = null;

    private handshakePromise: Promise<void>;
    private resolveHandshake: (() => void) | null = null;
    private rejectHandshake: ((reason?: unknown) => void) | null = null;
    private handshakeTimer: NodeJS.Timeout | null = null;
    private handshakeStartedAt = 0;

    private replayGuard = new ReplayGuard();
    private recordLayer: RecordLayer;
    private heartbeat: HeartbeatManager;
    private logger: StructuredLogger;
    private sessionCache = new ClientSessionCache();
    private messageQueue = new MessageQueue();
    private applicationResponseHandler: ((body: Buffer, serviceId: string) => void) | null = null;

    constructor(
        private host: string = '127.0.0.1',
        private port: number = 8443,
        private qsCa: QuantumSafeCA,
        private config: NomadConfig = loadConfig()
    ) {
        if (!qsCa) {
            throw new Error('QS-CA is required — refuse to connect without trusted root.');
        }
        configureFraming(this.config);
        this.crypto = new CryptoService(this.config.algorithmSuite);
        this.clientKem = this.crypto.createKem();
        this.recordLayer = new RecordLayer(this.crypto);
        this.logger = new StructuredLogger(this.config.logLevel);
        this.correlationId = randomBytes(16).toString('hex');

        const kemPair = this.crypto.generateKemKeyPair(this.clientKem);
        this.clientKemPublicKey = kemPair.publicKey;

        this.clientSig = this.crypto.createSig();
        const sigPair = this.crypto.generateSigKeyPair(this.clientSig);
        this.clientSigPrivateKey = sigPair.privateKey;
        this.clientSigPublicKey = sigPair.publicKey;

        this.heartbeat = new HeartbeatManager(
            this.config.heartbeatIntervalMs,
            () => this.failHandshake('Heartbeat timeout — peer presumed dead')
        );

        this.handshakePromise = this.createHandshakePromise();
        this.logger.info('Client initialized', { component: 'client', correlationId: this.correlationId });
    }

    getClientSigPublicKey(): Uint8Array {
        return this.clientSigPublicKey;
    }

    setApplicationResponseHandler(handler: (body: Buffer, serviceId: string) => void): void {
        this.applicationResponseHandler = handler;
    }

    setSessionTicket(ticket: string): void {
        this.sessionTicket = ticket;
        const cached = this.sessionCache.load(ticket, this.config.sessionTtlMs);
        if (cached) {
            this.aesKey = cached.aesKey;
            this.correlationId = cached.correlationId;
            this.pinnedServerSigPublicKey = cached.serverSigPublicKey;
        }
    }

    private createHandshakePromise(): Promise<void> {
        return new Promise((resolve, reject) => {
            this.resolveHandshake = resolve;
            this.rejectHandshake = reject;
        });
    }

    private settleHandshakeSuccess(): void {
        if (this.handshakeSettled) return;
        this.handshakeSettled = true;
        this.resolveHandshake?.();
    }

    private settleHandshakeFailure(reason: unknown): void {
        if (this.handshakeSettled) return;
        this.handshakeSettled = true;
        this.rejectHandshake?.(reason);
    }

    private failHandshake(reason: string, code = 'HANDSHAKE_FAILED'): void {
        this.logger.error(reason, { component: 'client', correlationId: this.correlationId, code });
        this.clearHandshakeTimer();
        this.heartbeat.stop();
        this.socket?.end();
        if (!this.handshakeComplete) {
            this.settleHandshakeFailure(new Error(reason));
        }
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
            this.failHandshake(`Handshake timed out after ${this.config.handshakeTimeoutMs}ms`, 'HANDSHAKE_TIMEOUT');
        }, this.config.handshakeTimeoutMs);
    }

    private validateIncoming(msg: WireMessage): void {
        validateWireMessage(msg);
        if (msg.nonce && msg.timestamp && msg.correlationId) {
            this.replayGuard.validate(msg.nonce, msg.timestamp, msg.correlationId);
        }
        if (msg.protocolVersion && msg.protocolVersion !== this.config.protocolVersion) {
            throw new Error(`Protocol version mismatch: ${msg.protocolVersion}`);
        }
    }

    public async connect(): Promise<void> {
        this.socket = new net.Socket();
        this.handshakeStartedAt = Date.now();

        this.socket.on('data', (data) => {
            try {
                this.receivedBuffer = Buffer.concat([this.receivedBuffer, data]);
                this.receivedBuffer = parseMessages(this.receivedBuffer, (message) => {
                    this.messageQueue.enqueue(
                        () => this.processMessage(message),
                        (err) => this.failHandshake(err instanceof Error ? err.message : String(err), 'MESSAGE_ERROR')
                    );
                });
            } catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                this.failHandshake(`Framing error: ${msg}`);
            }
        });

        this.socket.on('close', () => {
            this.logger.info('Connection closed', { component: 'client', correlationId: this.correlationId });
            this.clearHandshakeTimer();
            this.heartbeat.stop();
            if (!this.handshakeComplete) {
                this.settleHandshakeFailure(new Error('Connection closed before handshake complete.'));
            }
            this.wipeSecrets();
        });

        this.socket.on('error', (err) => {
            this.logger.error('Socket error', { component: 'client', correlationId: this.correlationId, error: err.message });
            this.clearHandshakeTimer();
            if (!this.handshakeComplete) {
                this.settleHandshakeFailure(err);
            }
        });

        return new Promise<void>((resolve, reject) => {
            this.socket?.connect(this.port, this.host, () => {
                this.logger.info('Connected', { component: 'client', correlationId: this.correlationId, host: this.host, port: this.port });
                this.sendClientHello();
                this.startHandshakeTimer();
                resolve();
            });
            this.socket?.once('error', reject);
        });
    }

    public async waitForHandshake(): Promise<void> {
        return this.handshakePromise;
    }

    private sendClientHello(): void {
        const base: WireMessage = this.sessionTicket
            ? { type: 'session_resume', sessionTicket: this.sessionTicket }
            : { type: 'client_hello' };

        const clientHello = attachSecurityFields(base, this.correlationId);

        if (this.sessionTicket) {
            const resumeData = buildSessionResumeSignedPayload(
                this.sessionTicket,
                this.clientSigPublicKey,
                this.correlationId,
                clientHello.nonce!,
                clientHello.timestamp!
            );
            const resumeSig = this.crypto.sign(this.clientSig, this.clientSigPrivateKey, resumeData);
            clientHello.signature = encodeBinary(resumeSig);
            clientHello.clientPublicKeySig = encodeBinary(this.clientSigPublicKey);
        }

        this.socket?.write(frameMessage(serializeMessage(clientHello)));
        this.phase = 'client_hello_sent';
    }

    private async processMessage(message: Buffer): Promise<void> {
        const parsed = parseWireMessage(message);
        this.validateIncoming(parsed);

        if (parsed.type !== 'close_notify' && parsed.correlationId &&
            parsed.correlationId !== this.correlationId) {
            this.failHandshake('Correlation ID mismatch', 'CORRELATION_MISMATCH');
            return;
        }

        switch (parsed.type) {
            case 'server_hello':
                await this.handleServerHello(parsed);
                break;
            case 'server_auth_response':
                await this.handleServerAuthResponse(parsed);
                break;
            case 'encrypted_data':
                this.handleEncryptedData(parsed);
                break;
            case 'heartbeat_ping':
                if (parsed.sequence !== undefined) {
                    this.heartbeat.sendPong(this.socket!, this.correlationId, parsed.sequence);
                }
                break;
            case 'heartbeat_pong':
                this.heartbeat.handlePong();
                break;
            case 'close_notify':
                this.logger.info('Received close_notify', { component: 'client', correlationId: this.correlationId });
                this.disconnect();
                break;
            case 'handshake_error':
                this.failHandshake(parsed.error ?? 'Server handshake error', parsed.errorCode ?? 'SERVER_HANDSHAKE_ERROR');
                break;
            default:
                this.failHandshake(`Unexpected message: ${parsed.type}`, 'UNEXPECTED_MESSAGE');
        }
    }

    private async handleServerHello(parsed: WireMessage): Promise<void> {
        if (this.phase !== 'client_hello_sent') {
            this.failHandshake(`server_hello in invalid phase: ${this.phase}`);
            return;
        }

        if (!parsed.kemPublicKey || !parsed.sigPublicKey || !parsed.certificate) {
            this.failHandshake('Incomplete server_hello');
            return;
        }

        this.serverKemPublicKey = decodeBinary(parsed.kemPublicKey, 'kemPublicKey');
        this.serverSigPublicKey = decodeBinary(parsed.sigPublicKey, 'sigPublicKey');

        const cert = parsed.certificate as PQCertificate;
        if (!verifyServerHelloIdentity(cert, this.serverKemPublicKey, this.serverSigPublicKey, this.qsCa)) {
            this.failHandshake('QS-CA certificate or hello identity verification failed', 'CERT_INVALID');
            return;
        }

        const { ciphertext, sharedSecret } = this.crypto.encapsulate(this.clientKem, this.serverKemPublicKey);
        if (!sharedSecret) {
            this.failHandshake('KEM encapsulation failed');
            return;
        }
        this.aesKey = this.crypto.deriveChannelKey(sharedSecret, this.correlationId);
        this.activateImperialLayers();

        const clientAuth = attachSecurityFields({
            type: 'client_auth_response',
            encapsulatedKey: encodeBinary(ciphertext),
            clientPublicKeySig: encodeBinary(this.clientSigPublicKey),
            kemPublicKey: encodeBinary(this.clientKemPublicKey),
        }, this.correlationId);

        const clientSignedData = buildClientAuthSignedPayload(
            this.clientSigPublicKey,
            this.clientKemPublicKey,
            this.correlationId,
            clientAuth.nonce!,
            clientAuth.timestamp!
        );
        const clientSignature = this.crypto.sign(this.clientSig, this.clientSigPrivateKey, clientSignedData);
        clientAuth.signature = encodeBinary(clientSignature);
        this.socket?.write(frameMessage(serializeMessage(clientAuth)));
        this.phase = 'client_auth_sent';
    }

    private async handleServerAuthResponse(parsed: WireMessage): Promise<void> {
        if (this.phase !== 'client_auth_sent' && this.phase !== 'client_hello_sent') {
            this.failHandshake(`server_auth_response in invalid phase: ${this.phase}`);
            return;
        }

        if (!parsed.signature || !parsed.sigPublicKey) {
            this.failHandshake('Incomplete server_auth_response');
            return;
        }

        const serverSigPublicKey = decodeBinary(parsed.sigPublicKey, 'sigPublicKey');
        const serverSignature = decodeBinary(parsed.signature, 'signature');

        if (this.pinnedServerSigPublicKey &&
            parsed.sigPublicKey !== this.pinnedServerSigPublicKey &&
            this.serverSigPublicKey &&
            Buffer.from(serverSigPublicKey).compare(Buffer.from(this.serverSigPublicKey)) !== 0) {
            this.failHandshake('Server signature key mismatch on resume', 'SERVER_ID_MISMATCH');
            return;
        }

        if (this.serverSigPublicKey &&
            Buffer.from(serverSigPublicKey).compare(Buffer.from(this.serverSigPublicKey)) !== 0) {
            this.failHandshake('Server signature key mismatch');
            return;
        }

        const serverAuthData = buildServerAuthSignedPayload(
            serverSigPublicKey,
            this.correlationId,
            parsed.nonce!,
            parsed.timestamp!,
            parsed.sessionTicket
        );
        if (!this.crypto.verify(this.clientSig, serverSigPublicKey, serverAuthData, serverSignature)) {
            this.failHandshake('Server signature verification failed');
            return;
        }

        this.serverSigPublicKey = serverSigPublicKey;
        this.pinnedServerSigPublicKey = encodeBinary(serverSigPublicKey);

        if (parsed.sessionTicket) {
            this.sessionTicket = parsed.sessionTicket;
        }

        const isResume = this.phase === 'client_hello_sent' && !!this.sessionTicket;
        if (!this.aesKey) {
            this.failHandshake('Secure channel key missing after handshake — resume requires local session cache', 'RESUME_KEY_MISSING');
            return;
        }

        this.phase = isResume ? 'resumed' : 'established';
        this.handshakeComplete = true;
        this.clearHandshakeTimer();
        this.heartbeat.start((buf) => this.socket?.write(buf), this.correlationId);
        this.logger.info('Secure channel established', {
            component: 'client',
            correlationId: this.correlationId,
            durationMs: Date.now() - this.handshakeStartedAt,
            resumed: isResume,
        });
        this.activateImperialLayers();

        if (this.sessionTicket && this.aesKey) {
            this.sessionCache.save(
                this.sessionTicket,
                this.aesKey,
                this.correlationId,
                this.pinnedServerSigPublicKey
            );
        }

        this.settleHandshakeSuccess();
    }

    private activateImperialLayers(): void {
        if (!this.aesKey) return;
        this.recordLayer.setImperialChannel(
            this.aesKey,
            this.correlationId,
            imperialConfigFromNomad(this.config)
        );
    }

    private handleEncryptedData(parsed: WireMessage): void {
        if (this.phase !== 'established' && this.phase !== 'resumed') {
            this.failHandshake('encrypted_data before secure channel', 'PHASE_VIOLATION');
            return;
        }
        if (!this.aesKey || parsed.sequence === undefined) {
            this.failHandshake('Incomplete encrypted_data', 'DECRYPT_FAILED');
            return;
        }

        if (parsed.sequence !== this.recvSequence + 1) {
            this.failHandshake(
                parsed.sequence <= this.recvSequence ? 'Sequence replay detected' : 'Sequence gap detected',
                'SEQUENCE_ERROR'
            );
            return;
        }
        this.recvSequence = parsed.sequence;

        try {
            const record = this.recordLayer.open(this.aesKey, {
                ciphertext: Buffer.from(parsed.data!, 'hex'),
                iv: Buffer.from(parsed.iv!, 'hex'),
                authTag: Buffer.from(parsed.authTag!, 'hex'),
                sequence: parsed.sequence,
            }, parsed.timestamp);
            this.logger.info('Decrypted record', {
                component: 'client',
                correlationId: this.correlationId,
                recordType: record.recordType,
                serviceId: record.serviceId,
            });
            if (record.recordType === 'application' && this.applicationResponseHandler) {
                this.applicationResponseHandler(record.body, record.serviceId ?? 'default');
            }
        } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            this.failHandshake(`Decryption failed: ${msg}`, 'DECRYPT_FAILED');
        }
    }

    public async sendEncryptedMessage(message: string, serviceId = 'default'): Promise<void> {
        await this.sendRaw(Buffer.from(message, 'utf8'), serviceId);
    }

    public async sendRaw(body: Buffer, serviceId = 'default'): Promise<void> {
        if ((this.phase !== 'established' && this.phase !== 'resumed') || !this.aesKey || !this.socket) {
            throw new Error('Secure channel not established');
        }
        this.sendSequence++;
        const imperialTs = Date.now();
        const sealed = this.recordLayer.seal(this.aesKey, {
            recordType: 'application',
            serviceId,
            body,
            imperialTimestamp: imperialTs,
        }, this.sendSequence);

        const wire = attachSecurityFields({
            type: 'encrypted_data',
            sequence: this.sendSequence,
            serviceId,
            data: sealed.ciphertext.toString('hex'),
            iv: sealed.iv.toString('hex'),
            authTag: sealed.authTag.toString('hex'),
        }, this.correlationId, imperialTs);
        this.socket.write(frameMessage(serializeMessage(wire)));
    }

    public getSessionTicket(): string | null {
        return this.sessionTicket;
    }

    private wipeSecrets(): void {
        this.crypto.destroyKey(this.aesKey);
        this.aesKey = null;
        this.crypto.destroyKeyMaterial(this.clientSigPrivateKey);
    }

    public async disconnect(): Promise<void> {
        this.clearHandshakeTimer();
        this.heartbeat.stop();
        if (this.socket && this.handshakeComplete) {
            const notify = attachSecurityFields({ type: 'close_notify' }, this.correlationId);
            try {
                this.socket.write(frameMessage(serializeMessage(notify)));
            } catch { /* ignore */ }
        }
        this.socket?.end();
        this.wipeSecrets();
    }
}
