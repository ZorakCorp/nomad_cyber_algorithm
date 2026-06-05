/** Best-effort zeroing of sensitive buffers. */

export function secureZero(buffer: Uint8Array | Buffer | null | undefined): void {
    if (!buffer || buffer.length === 0) return;
    if (Buffer.isBuffer(buffer)) {
        buffer.fill(0);
        return;
    }
    buffer.fill(0);
}

export function secureZeroMany(...buffers: Array<Uint8Array | Buffer | null | undefined>): void {
    for (const buf of buffers) {
        secureZero(buf);
    }
}
