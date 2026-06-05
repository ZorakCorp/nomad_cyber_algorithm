import { Buffer } from 'buffer';

// Simple message framing for TCP streams
export function frameMessage(message: Buffer): Buffer {
    const lengthBuffer = Buffer.alloc(4);
    lengthBuffer.writeUInt32BE(message.length, 0);
    return Buffer.concat([lengthBuffer, message]);
}

export function parseMessages(buffer: Buffer, onMessage: (msg: Buffer) => void): Buffer {
    let cursor = 0;
    while (buffer.length - cursor >= 4) {
        const messageLength = buffer.readUInt32BE(cursor);
        if (buffer.length - cursor >= 4 + messageLength) {
            const message = buffer.subarray(cursor + 4, cursor + 4 + messageLength);
            onMessage(message);
            cursor += 4 + messageLength;
        } else {
            break; // Not enough data for the full message yet
        }
    }
    return buffer.subarray(cursor);
}
