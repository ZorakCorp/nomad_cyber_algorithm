import { createHmac, timingSafeEqual } from 'crypto';

const SEAL_BYTES = 32;
const MAGIC = Buffer.from('NOMD');

/**
 * Persian/Roman tamper-evident wax seal — HMAC binding over imperial body.
 */

export function applyPersianSeal(body: Buffer, key: Buffer): Buffer {
    const seal = createHmac('sha256', key).update('persian-seal').update(body).digest();
    return Buffer.concat([MAGIC, seal, body]);
}

export function verifyPersianSeal(sealed: Buffer, key: Buffer): Buffer {
    if (sealed.length < MAGIC.length + SEAL_BYTES) {
        throw new Error('Persian seal frame too short.');
    }
    if (!sealed.subarray(0, 4).equals(MAGIC)) {
        throw new Error('Imperial magic header missing — not a sealed dispatch.');
    }
    const seal = sealed.subarray(4, 4 + SEAL_BYTES);
    const body = sealed.subarray(4 + SEAL_BYTES);
    const expected = createHmac('sha256', key).update('persian-seal').update(body).digest();
    if (!timingSafeEqual(seal, expected)) {
        throw new Error('Persian seal broken — dispatch opened in transit.');
    }
    return body;
}
