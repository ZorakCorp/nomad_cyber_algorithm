import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';
import * as path from 'path';

export type KeyWorkerRequest =
    | { type: 'sign'; id: string; keyId: string; message: Uint8Array }
    | { type: 'decapsulate'; id: string; keyId: string; ciphertext: Uint8Array }
    | { type: 'shutdown'; id: string };

export type KeyWorkerResponse =
    | { type: 'sign'; id: string; signature: Uint8Array }
    | { type: 'decapsulate'; id: string; sharedSecret: Uint8Array }
    | { type: 'error'; id: string; message: string };

interface WorkerKeyMaterial {
    sigPrivate: Map<string, Uint8Array>;
    kemPrivate: Map<string, Uint8Array>;
}

/** Worker thread entry — private keys live only in isolated V8 heap. */
if (!isMainThread && parentPort) {
    const keys = workerData as WorkerKeyMaterial;
    parentPort.on('message', async (req: KeyWorkerRequest) => {
        try {
            if (req.type === 'shutdown') {
                keys.sigPrivate.clear();
                keys.kemPrivate.clear();
                process.exit(0);
            }
            if (req.type === 'sign') {
                const priv = keys.sigPrivate.get(req.keyId);
                if (!priv) throw new Error(`SIG key ${req.keyId} not in worker`);
                const { createHmac } = await import('crypto');
                const sig = createHmac('sha256', Buffer.from(priv)).update(Buffer.from(req.message)).digest();
                parentPort!.postMessage({ type: 'sign', id: req.id, signature: new Uint8Array(sig) } satisfies KeyWorkerResponse);
                return;
            }
            if (req.type === 'decapsulate') {
                const priv = keys.kemPrivate.get(req.keyId);
                if (!priv) throw new Error(`KEM key ${req.keyId} not in worker`);
                const { createHash } = await import('crypto');
                const secret = createHash('sha256').update(Buffer.from(priv)).update(Buffer.from(req.ciphertext)).digest();
                parentPort!.postMessage({ type: 'decapsulate', id: req.id, sharedSecret: new Uint8Array(secret) } satisfies KeyWorkerResponse);
            }
        } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            parentPort!.postMessage({ type: 'error', id: req.id, message } satisfies KeyWorkerResponse);
        }
    });
}

export class KeyWorkerSandbox {
    private worker: Worker;
    private pending = new Map<string, { resolve: (v: KeyWorkerResponse) => void; reject: (e: Error) => void }>();

    constructor(sigKeys: Record<string, Uint8Array>, kemKeys: Record<string, Uint8Array>) {
        const workerPath = path.join(__dirname, 'key_worker.js');
        this.worker = new Worker(workerPath, {
            workerData: {
                sigPrivate: new Map(Object.entries(sigKeys)),
                kemPrivate: new Map(Object.entries(kemKeys)),
            },
        });
        this.worker.on('message', (res: KeyWorkerResponse) => {
            const pending = this.pending.get(res.id);
            if (!pending) return;
            this.pending.delete(res.id);
            if (res.type === 'error') pending.reject(new Error(res.message));
            else pending.resolve(res);
        });
    }

    private send(req: KeyWorkerRequest): Promise<KeyWorkerResponse> {
        return new Promise((resolve, reject) => {
            this.pending.set(req.id, { resolve, reject });
            this.worker.postMessage(req);
        });
    }

    async sign(keyId: string, message: Uint8Array): Promise<Uint8Array> {
        const id = `${Date.now()}-${Math.random()}`;
        const res = await this.send({ type: 'sign', id, keyId, message });
        if (res.type !== 'sign') throw new Error('Unexpected worker response');
        return res.signature;
    }

    async decapsulate(keyId: string, ciphertext: Uint8Array): Promise<Uint8Array> {
        const id = `${Date.now()}-${Math.random()}`;
        const res = await this.send({ type: 'decapsulate', id, keyId, ciphertext });
        if (res.type !== 'decapsulate') throw new Error('Unexpected worker response');
        return res.sharedSecret;
    }

    async shutdown(): Promise<void> {
        await this.send({ type: 'shutdown', id: 'shutdown' });
        await this.worker.terminate();
    }
}
