/** Client-side session cache — pairs opaque tickets with locally held channel keys. */

export interface CachedSession {
    aesKey: Buffer;
    correlationId: string;
    serverSigPublicKey: string;
    savedAt: number;
}

export class ClientSessionCache {
    private sessions = new Map<string, CachedSession>();

    save(ticket: string, aesKey: Buffer, correlationId: string, serverSigPublicKey: string): void {
        this.sessions.set(ticket, { aesKey, correlationId, serverSigPublicKey, savedAt: Date.now() });
    }

    load(ticket: string, ttlMs: number): CachedSession | null {
        const session = this.sessions.get(ticket);
        if (!session) return null;
        if (Date.now() - session.savedAt > ttlMs) {
            this.sessions.delete(ticket);
            return null;
        }
        return session;
    }

    clear(ticket: string): void {
        this.sessions.delete(ticket);
    }
}
