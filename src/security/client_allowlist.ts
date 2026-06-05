import { encodeBinary } from '../protocol';

export class ClientAllowlist {
    private allowed = new Set<string>();

    constructor(allowedPublicKeys: string[] = []) {
        for (const key of allowedPublicKeys) {
            this.allowed.add(key.trim());
        }
    }

    register(publicKey: Uint8Array): void {
        this.allowed.add(encodeBinary(publicKey));
    }

    isAllowed(publicKey: Uint8Array): boolean {
        if (this.allowed.size === 0) {
            return true;
        }
        return this.allowed.has(encodeBinary(publicKey));
    }

    size(): number {
        return this.allowed.size;
    }
}
