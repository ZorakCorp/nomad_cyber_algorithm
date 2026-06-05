import { WireMessage, attachSecurityFields, serializeMessage } from '../protocol';
import { frameMessage } from '../utils';
import * as net from 'net';

export class HeartbeatManager {
    private timer: NodeJS.Timeout | null = null;
    private sequence = 0;
    private lastPongAt = Date.now();

    constructor(
        private intervalMs: number,
        private onDead: () => void,
        private deadThresholdMs: number = intervalMs * 3
    ) {}

    start(send: (msg: Buffer) => void, correlationId: string): void {
        this.stop();
        this.timer = setInterval(() => {
            if (Date.now() - this.lastPongAt > this.deadThresholdMs) {
                this.onDead();
                this.stop();
                return;
            }
            this.sequence++;
            const ping = attachSecurityFields({
                type: 'heartbeat_ping',
                sequence: this.sequence,
            }, correlationId);
            send(frameMessage(serializeMessage(ping)));
        }, this.intervalMs);
    }

    handlePong(): void {
        this.lastPongAt = Date.now();
    }

    sendPong(socket: net.Socket, correlationId: string, sequence: number): void {
        const pong = attachSecurityFields({
            type: 'heartbeat_pong',
            sequence,
        }, correlationId);
        socket.write(frameMessage(serializeMessage(pong)));
    }

    stop(): void {
        if (this.timer) {
            clearInterval(this.timer);
            this.timer = null;
        }
    }
}
