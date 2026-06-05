import { KeyEncapsulation, Signature, OQS_KEM_ALG, OQS_SIG_ALG } from '@open-quantum-safe/oqs-javascript';
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';
import * as net from 'net';
import { frameMessage, parseMessages } from './utils';

interface HandshakeMessage {
    type: 'client_hello' | 'client_auth_response' | 'encrypted_data';
    kemPublicKey?: Uint8Array; // Client's ephemeral KEM public key
    encapsulatedKey?: Uint8Array; // Client's encapsulated shared secret
    signature?: Uint8Array; // Client's signature over handshake data
    clientPublicKeySig?: Uint8Array; // Client's public signature key
    data?: string; // Encrypted data
    iv?: string; // Initialization Vector
}

interface ServerHandshakeResponse {
    type: 'server_hello' | 'server_auth_response';
    kemPublicKey: Uint8Array; // Server's KEM public key
    sigPublicKey: Uint8Array; // Server's SIG public key
    certificate?: Uint8Array; // Server's PQC-signed certificate (self-signed for demo)
    signature?: Uint8Array; // Server's signature over handshake data
}

export class PQCClientService {
    private clientKem: KeyEncapsulation;
    private clientKemPrivateKey: Uint8Array;
    private clientKemPublicKey: Uint8Array;

    private clientSig: Signature;
    private clientSigPrivateKey: Uint8Array;
    private clientSigPublicKey: Uint8Array;

    private serverKemPublicKey: Uint8Array | null = null;
    private serverSigPublicKey: Uint8Array | null = null;
    private serverCertificate: Uint8Array | null = null;

    private clientSharedSecret: Uint8Array | null = null;
    private clientAesKey: Buffer | null = null;

    private socket: net.Socket | null = null;
    private receivedBuffer: Buffer = Buffer.alloc(0);
    private handshakePromise: Promise<void>;
    private resolveHandshake: (() => void) | null = null;
    private rejectHandshake: ((reason?: any) => void) | null = null;

    constructor(private host: string = 'localhost', private port: number = 8443) {
        // [CHEMIX]: Initialize Kyber768 for ephemeral Key Encapsulation
        this.clientKem = new KeyEncapsulation(OQS_KEM_ALG.Kyber768);
        const kemKeyPair = this.clientKem.generateKeyPair();
        this.clientKemPrivateKey = kemKeyPair.privateKey; // Not strictly needed for client's KEM, but good practice
        this.clientKemPublicKey = kemKeyPair.publicKey;
        console.log("[CLIENT] Kyber768 KEM ephemeral key pair generated.");

        // [CHEMIX]: Initialize Dilithium3 for Digital Signatures
        this.clientSig = new Signature(OQS_SIG_ALG.Dilithium3);
        const sigKeyPair = this.clientSig.generateKeyPair();
        this.clientSigPrivateKey = sigKeyPair.privateKey;
        this.clientSigPublicKey = sigKeyPair.publicKey;
        console.log("[CLIENT] Dilithium3 SIG key pair generated.");

        this.handshakePromise = new Promise((resolve, reject) => {
            this.resolveHandshake = resolve;
            this.rejectHandshake = reject;
        });
    }

    public async connect(): Promise<void> {
        this.socket = new net.Socket();

        this.socket.on('data', (data) => {
            this.receivedBuffer = Buffer.concat([this.receivedBuffer, data]);
            this.receivedBuffer = parseMessages(this.receivedBuffer, (message) => this.processMessage(message));
        });

        this.socket.on('close', () => {
            console.log("[CLIENT] Connection closed.");
            this.rejectHandshake?.(new Error("Connection closed before handshake complete."));
            this.resetState();
        });

        this.socket.on('error', (err) => {
            console.error(`[CLIENT] Socket error: ${err.message}`);
            this.rejectHandshake?.(err);
            this.resetState();
        });

        return new Promise<void>((resolve, reject) => {
            this.socket?.connect(this.port, this.host, () => {
                console.log(`[CLIENT] Connected to server at ${this.host}:${this.port}.`);
                this.sendClientHello();
                resolve();
            });
        });
    }

    public async waitForHandshake(): Promise<void> {
        return this.handshakePromise;
    }

    private resetState(): void {
        this.serverKemPublicKey = null;
        this.serverSigPublicKey = null;
        this.serverCertificate = null;
        this.clientSharedSecret = null;
        this.clientAesKey = null;
        this.socket = null;
        this.receivedBuffer = Buffer.alloc(0);
        // Re-initialize promise for potential reconnects
        this.handshakePromise = new Promise((resolve, reject) => {
            this.resolveHandshake = resolve;
            this.rejectHandshake = reject;
        });
    }

    private sendClientHello(): void {
        const clientHello: HandshakeMessage = {
            type: 'client_hello'
        };
        this.socket?.write(frameMessage(Buffer.from(JSON.stringify(clientHello))));
    }

    private async processMessage(message: Buffer): Promise<void> {
        const parsedMessage: ServerHandshakeResponse | HandshakeMessage = JSON.parse(message.toString());

        switch (parsedMessage.type) {
            case 'server_hello':
                console.log("[CLIENT] Received server_hello.");
                if (!parsedMessage.kemPublicKey || !parsedMessage.sigPublicKey || !parsedMessage.certificate) {
                    console.error("[CLIENT] Incomplete server_hello.");
                    this.socket?.end();
                    this.rejectHandshake?.(new Error("Incomplete server_hello."));
                    return;
                }

                this.serverKemPublicKey = parsedMessage.kemPublicKey;
                this.serverSigPublicKey = parsedMessage.sigPublicKey;
                this.serverCertificate = parsedMessage.certificate;

                // [ETHICA]: Verify server's self-signed certificate using its public SIG key
                // In a 'real' system, this would involve a QS-CA root certificate.
                const isServerCertValid = this.clientSig.verify(this.serverSigPublicKey, this.serverSigPublicKey, this.serverCertificate);
                if (!isServerCertValid) {
                    console.error("[CLIENT] Server certificate verification failed. Aborting connection.");
                    this.socket?.end();
                    this.rejectHandshake?.(new Error("Server certificate invalid."));
                    return;
                }
                console.log("[CLIENT] Server certificate verified (Dilithium3). Authenticated server.");

                // [CHEMIX]: Encapsulate a shared secret using server's public KEM key
                const { ciphertext, sharedSecret } = this.clientKem.encapsulate(this.serverKemPublicKey);
                this.clientSharedSecret = sharedSecret;
                if (!this.clientSharedSecret) {
                    console.error("[CLIENT] Failed to encapsulate shared secret. Aborting connection.");
                    this.socket?.end();
                    this.rejectHandshake?.(new Error("KEM encapsulation failed."));
                    return;
                }
                this.clientAesKey = scryptSync(this.clientSharedSecret, 'client_pqc_salt', 32); // 32 bytes for AES-256
                console.log(`[CLIENT] Shared secret encapsulated. AES key derived: ${this.clientAesKey.toString('hex').substring(0, 16)}...`);

                // [SYNTHIA]: Client signs its own public key and ephemeral KEM public key for mutual authentication
                const clientSignedData = Buffer.from(JSON.stringify({
                    clientPublicKeySig: this.clientSigPublicKey,
                    kemPublicKey: this.clientKemPublicKey // This is the ephemeral KEM public key
                }));
                const clientSignature = this.clientSig.sign(this.clientSigPrivateKey, clientSignedData);

                const clientAuthResponse: HandshakeMessage = {
                    type: 'client_auth_response',
                    encapsulatedKey: ciphertext,
                    signature: clientSignature,
                    clientPublicKeySig: this.clientSigPublicKey
                };
                this.socket?.write(frameMessage(Buffer.from(JSON.stringify(clientAuthResponse))));
                console.log("[CLIENT] Sent client_auth_response with PQC encapsulated key and signature.");
                break;

            case 'server_auth_response':
                if (!parsedMessage.signature || !parsedMessage.sigPublicKey) {
                    console.error("[CLIENT] Incomplete server_auth_response.");
                    this.socket?.end();
                    this.rejectHandshake?.(new Error("Incomplete server_auth_response."));
                    return;
                }

                // [OPTIMUS]: Verify server's signature to confirm handshake completion
                const serverAuthData = Buffer.from(JSON.stringify({
                    status: 'handshake_complete',
                    serverPublicKeySig: parsedMessage.sigPublicKey
                }));
                const isServerSignatureValid = this.clientSig.verify(parsedMessage.sigPublicKey, serverAuthData, parsedMessage.signature);
                if (!isServerSignatureValid) {
                    console.error("[CLIENT] Server signature verification failed. Aborting connection.");
                    this.socket?.end();
                    this.rejectHandshake?.(new Error("Server signature invalid."));
                    return;
                }
                console.log("[CLIENT] Server signature verified (Dilithium3). PQC Secure channel established for microservice communication.");
                this.resolveHandshake?.(); // Handshake complete
                break;

            case 'encrypted_data':
                if (!this.clientAesKey) {
                    console.error("[CLIENT] Attempted to decrypt without established AES key.");
                    this.socket?.end();
                    return;
                }
                const encryptedMessage = Buffer.from(parsedMessage.data as string, 'hex');
                const iv = Buffer.from(parsedMessage.iv as string, 'hex');
                const decrypted = this.decryptMessage(encryptedMessage, iv);
                console.log(`[CLIENT] Received and decrypted processing result: '${decrypted}'`);
                break;

            default:
                console.warn(`[CLIENT] Unknown message type: ${parsedMessage.type}`);
                this.socket?.end();
                this.rejectHandshake?.(new Error(`Unknown message type: ${parsedMessage.type}`));
                break;
        }
    }

    public async sendEncryptedMessage(message: string): Promise<void> {
        if (!this.clientAesKey) {
            throw new Error("PQC secure channel not established. Cannot send encrypted message.");
        }
        console.log(`[CLIENT] Sending application data: '${message}'`);
        const iv = randomBytes(16);
        const encrypted = this.encryptMessage(message, iv);
        const dataMessage: HandshakeMessage = {
            type: 'encrypted_data',
            data: encrypted.toString('hex'),
            iv: iv.toString('hex')
        };
        this.socket?.write(frameMessage(Buffer.from(JSON.stringify(dataMessage))));
    }

    private encryptMessage(message: string, iv: Buffer): Buffer {
        if (!this.clientAesKey) {
            throw new Error("AES key not established for encryption.");
        }
        const cipher = createCipheriv('aes-256-cbc', this.clientAesKey, iv);
        let encrypted = cipher.update(message, 'utf-8');
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return encrypted;
    }

    private decryptMessage(ciphertext: Buffer, iv: Buffer): string {
        if (!this.clientAesKey) {
            throw new Error("AES key not established for decryption.");
        }
        const decipher = createDecipheriv('aes-256-cbc', this.clientAesKey, iv);
        let decrypted = decipher.update(ciphertext);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString('utf-8');
    }

    public disconnect(): void {
        this.socket?.end();
    }
}
