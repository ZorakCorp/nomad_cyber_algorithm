import { KeyEncapsulation, Signature, OQS_KEM_ALG, OQS_SIG_ALG } from '@open-quantum-safe/oqs-javascript';
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';
import * as net from 'net';
import { frameMessage, parseMessages } from './utils';

interface HandshakeMessage {
    type: 'client_hello' | 'client_auth_response';
    kemPublicKey?: Uint8Array; // Client's ephemeral KEM public key
    encapsulatedKey?: Uint8Array; // Client's encapsulated shared secret
    signature?: Uint8Array; // Client's signature over handshake data
    clientPublicKeySig?: Uint8Array; // Client's public signature key
}

interface ServerHandshakeResponse {
    type: 'server_hello' | 'server_auth_response';
    kemPublicKey: Uint8Array; // Server's KEM public key
    sigPublicKey: Uint8Array; // Server's SIG public key
    certificate?: Uint8Array; // Server's PQC-signed certificate (self-signed for demo)
    signature?: Uint8Array; // Server's signature over handshake data
}

export class PQCServerService {
    private serverKem: KeyEncapsulation;
    private serverKemPrivateKey: Uint8Array;
    private serverKemPublicKey: Uint8Array;

    private serverSig: Signature;
    private serverSigPrivateKey: Uint8Array;
    private serverSigPublicKey: Uint8Array;
    private serverCertificate: Uint8Array; // Self-signed for demo

    private clientSigPublicKey: Uint8Array | null = null;
    private clientSharedSecret: Uint8Array | null = null;
    private clientAesKey: Buffer | null = null;

    private connectedSocket: net.Socket | null = null;
    private receivedBuffer: Buffer = Buffer.alloc(0);

    constructor(private port: number = 8443) {
        // [CHEMIX]: Initialize Kyber768 for Key Encapsulation
        this.serverKem = new KeyEncapsulation(OQS_KEM_ALG.Kyber768);
        const kemKeyPair = this.serverKem.generateKeyPair();
        this.serverKemPrivateKey = kemKeyPair.privateKey;
        this.serverKemPublicKey = kemKeyPair.publicKey;
        console.log("[SERVER] Kyber768 KEM key pair generated.");

        // [CHEMIX]: Initialize Dilithium3 for Digital Signatures
        this.serverSig = new Signature(OQS_SIG_ALG.Dilithium3);
        const sigKeyPair = this.serverSig.generateKeyPair();
        this.serverSigPrivateKey = sigKeyPair.privateKey;
        this.serverSigPublicKey = sigKeyPair.publicKey;
        console.log("[SERVER] Dilithium3 SIG key pair generated.");

        // [ECONIA]: For a 'real' system, a Quantum-Safe Certificate Authority (QS-CA)
        // would issue this certificate. Here, we self-sign for demonstration.
        // The certificate would typically contain the public KEM and SIG keys, and be signed by the CA.
        // For simplicity, we just sign our public SIG key as our 'certificate'.
        this.serverCertificate = this.serverSig.sign(this.serverSigPrivateKey, this.serverSigPublicKey);
        console.log("[SERVER] Self-signed PQC certificate generated.");
    }

    public start(): void {
        const server = net.createServer((socket) => {
            this.connectedSocket = socket;
            console.log("\n[SERVER] Client connected.");
            this.handleConnection(socket);
        });

        server.listen(this.port, () => {
            console.log(`[SERVER] Listening on port ${this.port}`);
        });
    }

    private handleConnection(socket: net.Socket): void {
        socket.on('data', (data) => {
            this.receivedBuffer = Buffer.concat([this.receivedBuffer, data]);
            this.receivedBuffer = parseMessages(this.receivedBuffer, (message) => this.processMessage(message));
        });

        socket.on('end', () => {
            console.log("[SERVER] Client disconnected.");
            this.resetState();
        });

        socket.on('error', (err) => {
            console.error(`[SERVER] Socket error: ${err.message}`);
            this.resetState();
        });
    }

    private resetState(): void {
        this.clientSigPublicKey = null;
        this.clientSharedSecret = null;
        this.clientAesKey = null;
        this.connectedSocket = null;
        this.receivedBuffer = Buffer.alloc(0);
    }

    private async processMessage(message: Buffer): Promise<void> {
        const parsedMessage: HandshakeMessage = JSON.parse(message.toString());

        switch (parsedMessage.type) {
            case 'client_hello':
                console.log("[SERVER] Received client_hello. Initiating handshake...");
                // Send server's public keys and certificate
                const serverHello: ServerHandshakeResponse = {
                    type: 'server_hello',
                    kemPublicKey: this.serverKemPublicKey,
                    sigPublicKey: this.serverSigPublicKey,
                    certificate: this.serverCertificate
                };
                this.connectedSocket?.write(frameMessage(Buffer.from(JSON.stringify(serverHello))));
                break;

            case 'client_auth_response':
                if (!parsedMessage.encapsulatedKey || !parsedMessage.signature || !parsedMessage.clientPublicKeySig) {
                    console.error("[SERVER] Incomplete client_auth_response.");
                    this.connectedSocket?.end();
                    return;
                }

                this.clientSigPublicKey = parsedMessage.clientPublicKeySig;

                // [ETHICA]: Verify client's signature first for authentication
                // The client signed its ephemeral KEM public key and its own public signature key
                const clientSignedData = Buffer.from(JSON.stringify({
                    clientPublicKeySig: parsedMessage.clientPublicKeySig,
                    kemPublicKey: parsedMessage.kemPublicKey // This is the ephemeral key from client_hello
                }));

                const isClientSignatureValid = this.serverSig.verify(this.clientSigPublicKey, clientSignedData, parsedMessage.signature);
                if (!isClientSignatureValid) {
                    console.error("[SERVER] Client signature verification failed. Aborting connection.");
                    this.connectedSocket?.end();
                    return;
                }
                console.log("[SERVER] Client signature verified (Dilithium3). Client authenticated.");

                // [CHEMIX]: Decapsulate shared secret using server's private KEM key
                this.clientSharedSecret = this.serverKem.decapsulate(this.serverKemPrivateKey, parsedMessage.encapsulatedKey);
                if (!this.clientSharedSecret) {
                    console.error("[SERVER] Failed to decapsulate shared secret. Aborting connection.");
                    this.connectedSocket?.end();
                    return;
                }
                this.clientAesKey = scryptSync(this.clientSharedSecret, 'server_pqc_salt', 32); // 32 bytes for AES-256
                console.log(`[SERVER] Shared secret decapsulated. AES key derived: ${this.clientAesKey.toString('hex').substring(0, 16)}...`);

                // [SYNTHIA]: Server signs its own confirmation of the handshake
                const serverAuthData = Buffer.from(JSON.stringify({
                    status: 'handshake_complete',
                    serverPublicKeySig: this.serverSigPublicKey // To allow client to verify server's signature
                }));
                const serverSignature = this.serverSig.sign(this.serverSigPrivateKey, serverAuthData);

                const serverAuthResponse: ServerHandshakeResponse = {
                    type: 'server_auth_response',
                    kemPublicKey: this.serverKemPublicKey, // Redundant, but for completeness
                    sigPublicKey: this.serverSigPublicKey,
                    signature: serverSignature
                };
                this.connectedSocket?.write(frameMessage(Buffer.from(JSON.stringify(serverAuthResponse))));
                console.log("[SERVER] Sent server_auth_response with PQC signature.");
                console.log("[SERVER] PQC Secure channel established for microservice communication.");

                // Now ready to receive encrypted application data
                break;

            case 'encrypted_data':
                if (!this.clientAesKey) {
                    console.error("[SERVER] Attempted to decrypt without established AES key.");
                    this.connectedSocket?.end();
                    return;
                }
                const encryptedMessage = Buffer.from(parsedMessage.data as string, 'hex');
                const iv = Buffer.from(parsedMessage.iv as string, 'hex');
                const decrypted = this.decryptMessage(encryptedMessage, iv);
                console.log(`[SERVER] Received and decrypted application data: '${decrypted}'`);

                // [BIOX]: Simulate processing of Top Secret / SCI data
                const processingResult = `Processed Top Secret data from client: ${decrypted.substring(0, 20)}...`;
                const responseIv = randomBytes(16);
                const encryptedResponse = this.encryptMessage(processingResult, responseIv);
                const responseMessage = {
                    type: 'encrypted_data',
                    data: encryptedResponse.toString('hex'),
                    iv: responseIv.toString('hex')
                };
                this.connectedSocket?.write(frameMessage(Buffer.from(JSON.stringify(responseMessage))));
                console.log(`[SERVER] Sent encrypted processing result.`);
                break;

            default:
                console.warn(`[SERVER] Unknown message type: ${parsedMessage.type}`);
                this.connectedSocket?.end();
                break;
        }
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
}
