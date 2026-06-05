import * as net from 'net';
import { attachSecurityFields, serializeMessage } from '../protocol';
import { frameMessage } from '../utils';

export class GracefulShutdown {
    private shuttingDown = false;
    private activeSockets = new Set<net.Socket>();

    track(socket: net.Socket): void {
        this.activeSockets.add(socket);
        socket.once('close', () => this.activeSockets.delete(socket));
    }

    isShuttingDown(): boolean {
        return this.shuttingDown;
    }

    async shutdown(timeoutMs: number): Promise<void> {
        if (this.shuttingDown) return;
        this.shuttingDown = true;

        for (const socket of this.activeSockets) {
            try {
                const notify = attachSecurityFields({ type: 'close_notify' }, 'shutdown');
                socket.write(frameMessage(serializeMessage(notify)));
            } catch {
                // ignore
            }
        }

        await new Promise<void>((resolve) => {
            const deadline = setTimeout(() => {
                for (const socket of this.activeSockets) {
                    socket.destroy();
                }
                resolve();
            }, timeoutMs);

            const check = setInterval(() => {
                if (this.activeSockets.size === 0) {
                    clearTimeout(deadline);
                    clearInterval(check);
                    resolve();
                }
            }, 100);
        });
    }

    activeCount(): number {
        return this.activeSockets.size;
    }
}
