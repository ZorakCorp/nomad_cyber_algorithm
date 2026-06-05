/**
 * Spartan Scytale — keyed columnar transposition with length prefix.
 * Ancient: strip on rod. Modern: bytes written row-wise, read column-wise.
 */

export function scytaleEncipher(data: Buffer, columns: number): Buffer {
    if (columns < 2) {
        const len = Buffer.alloc(4);
        len.writeUInt32BE(data.length, 0);
        return Buffer.concat([len, data]);
    }

    const rows = Math.ceil(data.length / columns);
    const padded = Buffer.alloc(rows * columns);
    data.copy(padded);

    const transposed = Buffer.alloc(padded.length);
    let idx = 0;
    for (let col = 0; col < columns; col++) {
        for (let row = 0; row < rows; row++) {
            transposed[idx++] = padded[row * columns + col];
        }
    }

    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length, 0);
    return Buffer.concat([len, transposed]);
}

export function scytaleDecipher(data: Buffer, columns: number): Buffer {
    if (data.length < 4) throw new Error('Scytale frame too short');
    const origLen = data.readUInt32BE(0);
    const body = data.subarray(4);

    if (columns < 2) {
        return body.subarray(0, origLen);
    }

    const rows = Math.ceil(origLen / columns);
    const expected = rows * columns;
    if (body.length < expected) {
        throw new Error('Scytale body truncated');
    }

    const transposed = body.subarray(0, expected);
    const restored = Buffer.alloc(expected);
    let idx = 0;
    for (let col = 0; col < columns; col++) {
        for (let row = 0; row < rows; row++) {
            restored[row * columns + col] = transposed[idx++];
        }
    }
    return restored.subarray(0, origLen);
}
