import { WireMessage, MessageType } from './protocol';

const HANDSHAKE_TYPES: MessageType[] = [
    'client_hello', 'server_hello', 'client_auth_response', 'server_auth_response', 'session_resume',
];
const DATA_TYPES: MessageType[] = [
    'encrypted_data', 'heartbeat_ping', 'heartbeat_pong', 'close_notify',
];

function isNonEmptyString(v: unknown): v is string {
    return typeof v === 'string' && v.length > 0;
}

function isPositiveInt(v: unknown): v is number {
    return typeof v === 'number' && Number.isInteger(v) && v >= 0;
}

export class SchemaValidationError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'SchemaValidationError';
    }
}

export function validateWireMessage(msg: WireMessage): void {
    if (!msg.type) {
        throw new SchemaValidationError('Missing message type');
    }

    const allTypes = [...HANDSHAKE_TYPES, ...DATA_TYPES, 'handshake_error'];
    if (!allTypes.includes(msg.type)) {
        throw new SchemaValidationError(`Unknown message type: ${msg.type}`);
    }

    if (msg.protocolVersion !== undefined && msg.protocolVersion !== 1) {
        throw new SchemaValidationError(`Unsupported protocol version: ${msg.protocolVersion}`);
    }

    if (HANDSHAKE_TYPES.includes(msg.type) || DATA_TYPES.includes(msg.type)) {
        if (!isNonEmptyString(msg.correlationId)) {
            throw new SchemaValidationError(`${msg.type} requires correlationId`);
        }
        if (!isNonEmptyString(msg.nonce)) {
            throw new SchemaValidationError(`${msg.type} requires nonce`);
        }
        if (!isPositiveInt(msg.timestamp)) {
            throw new SchemaValidationError(`${msg.type} requires timestamp`);
        }
    }

    switch (msg.type) {
        case 'client_hello':
            break;
        case 'session_resume':
            if (!isNonEmptyString(msg.sessionTicket)) {
                throw new SchemaValidationError('session_resume requires sessionTicket');
            }
            break;
        case 'server_hello':
            if (!isNonEmptyString(msg.kemPublicKey) || !isNonEmptyString(msg.sigPublicKey) || !msg.certificate) {
                throw new SchemaValidationError('server_hello requires kemPublicKey, sigPublicKey, certificate');
            }
            break;
        case 'client_auth_response':
            if (!isNonEmptyString(msg.encapsulatedKey) || !isNonEmptyString(msg.signature) ||
                !isNonEmptyString(msg.clientPublicKeySig) || !isNonEmptyString(msg.kemPublicKey)) {
                throw new SchemaValidationError('client_auth_response missing required auth fields');
            }
            break;
        case 'server_auth_response':
            if (!isNonEmptyString(msg.signature) || !isNonEmptyString(msg.sigPublicKey)) {
                throw new SchemaValidationError('server_auth_response missing signature fields');
            }
            break;
        case 'encrypted_data':
            if (!isNonEmptyString(msg.data) || !isNonEmptyString(msg.iv) || !isNonEmptyString(msg.authTag)) {
                throw new SchemaValidationError('encrypted_data missing crypto fields');
            }
            if (!isPositiveInt(msg.sequence)) {
                throw new SchemaValidationError('encrypted_data requires sequence');
            }
            break;
        case 'heartbeat_ping':
        case 'heartbeat_pong':
            if (!isPositiveInt(msg.sequence)) {
                throw new SchemaValidationError(`${msg.type} requires sequence`);
            }
            break;
        case 'handshake_error':
            if (!isNonEmptyString(msg.error) && !isNonEmptyString(msg.errorCode)) {
                throw new SchemaValidationError('handshake_error requires error or errorCode');
            }
            break;
        case 'close_notify':
            break;
    }

    const allowedKeys = new Set([
        'type', 'protocolVersion', 'correlationId', 'nonce', 'timestamp', 'sequence',
        'sessionTicket', 'kemPublicKey', 'sigPublicKey', 'certificate', 'encapsulatedKey',
        'signature', 'clientPublicKeySig', 'data', 'iv', 'authTag', 'error', 'errorCode', 'serviceId',
    ]);
    for (const key of Object.keys(msg)) {
        if (!allowedKeys.has(key)) {
            throw new SchemaValidationError(`Unknown field: ${key}`);
        }
    }
}
