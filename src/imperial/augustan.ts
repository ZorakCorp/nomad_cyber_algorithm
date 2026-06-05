/**
 * Roman Augustan rotation — position-dependent Caesar on bytes.
 * Julius Caesar shifted by 3; Augustus used variable offsets in practice.
 */

export function augustanEncipher(data: Buffer, key: Buffer): Buffer {
    const out = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) {
        const shift = 1 + (key[i % key.length] % 127);
        out[i] = (data[i] + shift) & 0xff;
    }
    return out;
}

export function augustanDecipher(data: Buffer, key: Buffer): Buffer {
    const out = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) {
        const shift = 1 + (key[i % key.length] % 127);
        out[i] = (data[i] - shift + 256) & 0xff;
    }
    return out;
}
