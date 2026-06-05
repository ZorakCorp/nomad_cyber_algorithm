import { createHmac, timingSafeEqual } from 'crypto';

const MAX_CARTOUCHE_HEADER = 4096;

/**
 * Egyptian hieroglyph S-box + royal cartouche identity envelope.
 */

export function buildHieroglyphSbox(key: Buffer): Uint8Array {
    const sbox = new Uint8Array(256);
    for (let i = 0; i < 256; i++) sbox[i] = i;
    let j = 0;
    for (let i = 0; i < 256; i++) {
        j = (j + sbox[i] + key[i % key.length]) & 0xff;
        const tmp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = tmp;
    }
    return sbox;
}

export function hieroglyphEncipher(data: Buffer, sbox: Uint8Array): Buffer {
    const out = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) out[i] = sbox[data[i]];
    return out;
}

export function hieroglyphDecipher(data: Buffer, sbox: Uint8Array): Buffer {
    const inv = new Uint8Array(256);
    for (let i = 0; i < 256; i++) inv[sbox[i]] = i;
    const out = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) out[i] = inv[data[i]];
    return out;
}

export function wrapCartouche(data: Buffer, subject: string, correlationId: string, key: Buffer): Buffer {
    const seal = createHmac('sha256', key)
        .update('cartouche')
        .update(subject)
        .update(correlationId)
        .update(data)
        .digest();
    const header = Buffer.from(JSON.stringify({ subject, correlationId, seal: seal.toString('hex') }));
    const len = Buffer.alloc(2);
    len.writeUInt16BE(header.length, 0);
    return Buffer.concat([len, header, data]);
}

export function unwrapCartouche(wrapped: Buffer, key: Buffer): Buffer {
    if (wrapped.length < 2) {
        throw new Error('Cartouche frame too short');
    }
    const headerLen = wrapped.readUInt16BE(0);
    if (headerLen === 0 || headerLen > MAX_CARTOUCHE_HEADER || wrapped.length < 2 + headerLen) {
        throw new Error('Invalid cartouche header length');
    }
    const header = JSON.parse(wrapped.subarray(2, 2 + headerLen).toString('utf8')) as {
        subject: string;
        correlationId: string;
        seal: string;
    };
    const body = wrapped.subarray(2 + headerLen);
    const expected = createHmac('sha256', key)
        .update('cartouche')
        .update(header.subject)
        .update(header.correlationId)
        .update(body)
        .digest();
    const sealBuf = Buffer.from(header.seal, 'hex');
    if (sealBuf.length !== expected.length || !timingSafeEqual(sealBuf, expected)) {
        throw new Error('Cartouche seal violated — message authority invalid.');
    }
    return body;
}
