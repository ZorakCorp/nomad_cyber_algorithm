import { randomBytes } from 'crypto';

export const PROTOCOL = {
    MAX_MESSAGE_BYTES: 1_048_576,
    HANDSHAKE_TIMEOUT_MS: 30_000,
    CURRENT_VERSION: 1,
    AES_KEY_BYTES: 32,
    GCM_IV_BYTES: 12,
    GCM_AUTH_TAG_BYTES: 16,
} as const;

export type MessageType =
    | 'client_hello'
    | 'server_hello'
    | 'client_auth_response'
    | 'server_auth_response'
    | 'encrypted_data'
    | 'handshake_error'
    | 'heartbeat_ping'
    | 'heartbeat_pong'
    | 'session_resume'
    | 'close_notify';

export type HandshakePhase =
    | 'idle'
    | 'client_hello_sent'
    | 'server_hello_received'
    | 'client_auth_sent'
    | 'established'
    | 'resumed';

export type ServerHandshakePhase =
    | 'idle'
    | 'client_hello_received'
    | 'server_hello_sent'
    | 'client_auth_received'
    | 'established'
    | 'resumed';

export interface ErrorEnvelope {
    code: string;
    message: string;
    correlationId?: string;
}

export interface WireMessage {
    type: MessageType;
    protocolVersion?: number;
    correlationId?: string;
    nonce?: string;
    timestamp?: number;
    sequence?: number;
    sessionTicket?: string;
    kemPublicKey?: string;
    sigPublicKey?: string;
    certificate?: string | Record<string, unknown> | import('./crypto/qs_ca').PQCertificate;
    encapsulatedKey?: string;
    signature?: string;
    clientPublicKeySig?: string;
    data?: string;
    iv?: string;
    authTag?: string;
    error?: string;
    errorCode?: string;
    serviceId?: string;
}

export function encodeBinary(data: Uint8Array): string {
    return Buffer.from(data).toString('base64');
}

export function decodeBinary(encoded: string, fieldName: string): Uint8Array {
    if (!encoded || typeof encoded !== 'string') {
        throw new Error(`Missing or invalid base64 field: ${fieldName}`);
    }
    const buf = Buffer.from(encoded, 'base64');
    if (buf.length === 0) {
        throw new Error(`Empty binary payload for field: ${fieldName}`);
    }
    return new Uint8Array(buf);
}

export function createNonce(): string {
    return randomBytes(16).toString('hex');
}

export function attachSecurityFields(
    message: WireMessage,
    correlationId: string,
    timestampMs?: number
): WireMessage {
    return {
        ...message,
        protocolVersion: PROTOCOL.CURRENT_VERSION,
        correlationId,
        nonce: createNonce(),
        timestamp: timestampMs ?? Date.now(),
    };
}

export function serializeMessage(message: WireMessage): Buffer {
    return Buffer.from(JSON.stringify(message));
}

export function parseWireMessage(raw: Buffer): WireMessage {
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw.toString('utf8'));
    } catch {
        throw new Error('Malformed JSON message');
    }
    if (!parsed || typeof parsed !== 'object' || !('type' in parsed)) {
        throw new Error('Message missing type field');
    }
    return parsed as WireMessage;
}

export function buildClientAuthSignedPayload(
    clientPublicKeySig: Uint8Array,
    kemPublicKey: Uint8Array,
    correlationId: string,
    nonce: string,
    timestamp: number
): Buffer {
    return Buffer.from(JSON.stringify({
        clientPublicKeySig: encodeBinary(clientPublicKeySig),
        kemPublicKey: encodeBinary(kemPublicKey),
        correlationId,
        nonce,
        timestamp,
    }));
}

export function buildSessionResumeSignedPayload(
    sessionTicket: string,
    clientPublicKeySig: Uint8Array,
    correlationId: string,
    nonce: string,
    timestamp: number
): Buffer {
    return Buffer.from(JSON.stringify({
        action: 'session_resume',
        sessionTicket,
        clientPublicKeySig: encodeBinary(clientPublicKeySig),
        correlationId,
        nonce,
        timestamp,
    }));
}

export function buildServerAuthSignedPayload(
    serverPublicKeySig: Uint8Array,
    correlationId: string,
    nonce: string,
    timestamp: number,
    sessionTicket?: string
): Buffer {
    return Buffer.from(JSON.stringify({
        status: 'handshake_complete',
        serverPublicKeySig: encodeBinary(serverPublicKeySig),
        correlationId,
        nonce,
        timestamp,
        sessionTicket: sessionTicket ?? null,
    }));
}

export function toErrorEnvelope(code: string, message: string, correlationId?: string): ErrorEnvelope {
    return { code, message, correlationId };
}
