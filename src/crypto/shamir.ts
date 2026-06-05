/**
 * Shamir Secret Sharing over GF(256) for M-of-N key ceremony.
 * Used to split QS-CA root keys across custodians — no single party holds full secret.
 */

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);

function gfMultiply(a: number, b: number): number {
    let p = 0;
    for (let i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        const hi = a & 0x80;
        a = (a << 1) & 0xff;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

(function initGf256(): void {
    let x = 1;
    for (let i = 0; i < 255; i++) {
        EXP[i] = x;
        LOG[x] = i;
        x = gfMultiply(x, 3);
    }
    for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();

function gfAdd(a: number, b: number): number {
    return a ^ b;
}

function gfMul(a: number, b: number): number {
    if (a === 0 || b === 0) return 0;
    return EXP[(LOG[a] + LOG[b]) % 255];
}

function gfDiv(a: number, b: number): number {
    if (b === 0) throw new Error('GF division by zero');
    if (a === 0) return 0;
    return EXP[(LOG[a] - LOG[b] + 255) % 255];
}

function evalPoly(coeffs: number[], x: number): number {
    let result = 0;
    for (let i = coeffs.length - 1; i >= 0; i--) {
        result = gfAdd(gfMul(result, x), coeffs[i]);
    }
    return result;
}

export interface ShamirShare {
    index: number;
    data: Buffer;
}

export function splitSecret(secret: Buffer, threshold: number, shares: number): ShamirShare[] {
    if (threshold < 2) throw new Error('Threshold must be >= 2');
    if (shares < threshold) throw new Error('Shares must be >= threshold');
    const result: ShamirShare[] = [];
    for (let x = 1; x <= shares; x++) {
        result.push({ index: x, data: Buffer.alloc(secret.length) });
    }
    for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
        const coeffs = [secret[byteIdx]];
        for (let i = 1; i < threshold; i++) {
            coeffs.push(Math.floor(Math.random() * 256));
        }
        for (let x = 1; x <= shares; x++) {
            result[x - 1].data[byteIdx] = evalPoly(coeffs, x);
        }
    }
    return result;
}

export function combineShares(shares: ShamirShare[]): Buffer {
    if (shares.length === 0) throw new Error('No shares provided');
    const len = shares[0].data.length;
    const out = Buffer.alloc(len);
    for (let byteIdx = 0; byteIdx < len; byteIdx++) {
        let value = 0;
        for (let i = 0; i < shares.length; i++) {
            let basis = 1;
            const xi = shares[i].index;
            const yi = shares[i].data[byteIdx];
            for (let j = 0; j < shares.length; j++) {
                if (i === j) continue;
                const xj = shares[j].index;
                basis = gfMul(basis, gfDiv(xj, gfAdd(xi, xj)));
            }
            value = gfAdd(value, gfMul(yi, basis));
        }
        out[byteIdx] = value;
    }
    return out;
}
