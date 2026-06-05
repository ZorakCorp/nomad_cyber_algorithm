import { Buffer } from 'buffer';
import { NomadConfig, loadConfig } from './config';

let maxMessageBytes = loadConfig().maxMessageBytes;

export function setMaxMessageBytes(bytes: number): void {
    maxMessageBytes = bytes;
}

export function configureFraming(config: NomadConfig): void {
    maxMessageBytes = config.maxMessageBytes;
}

export function frameMessage(message: Buffer): Buffer {
    if (message.length > maxMessageBytes) {
        throw new Error(`Message exceeds max frame size (${maxMessageBytes} bytes)`);
    }
    const lengthBuffer = Buffer.alloc(4);
    lengthBuffer.writeUInt32BE(message.length, 0);
    return Buffer.concat([lengthBuffer, message]);
}

export function parseMessages(buffer: Buffer, onMessage: (msg: Buffer) => void): Buffer {
    let cursor = 0;
    while (buffer.length - cursor >= 4) {
        const messageLength = buffer.readUInt32BE(cursor);
        if (messageLength === 0 || messageLength > maxMessageBytes) {
            throw new Error(`Invalid frame length: ${messageLength}`);
        }
        if (buffer.length - cursor >= 4 + messageLength) {
            const message = buffer.subarray(cursor + 4, cursor + 4 + messageLength);
            onMessage(message);
            cursor += 4 + messageLength;
        } else {
            break;
        }
    }
    return buffer.subarray(cursor);
}
