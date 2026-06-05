import * as net from 'net';
import { PQCClientService } from '../pqc_client_service';
import { NomadConfig } from '../config';
import { StructuredLogger } from '../ops/logger';

/**
 * Transparent TCP sidecar: accepts local plaintext connections and
 * forwards payloads through an established PQC client channel.
 */
export class PQCSidecar {
    private server: net.Server | null = null;
    private client: PQCClientService | null = null;

    constructor(
        private listenPort: number,
        private upstreamHost: string,
        private upstreamPort: number,
        private config: NomadConfig,
        private logger: StructuredLogger
    ) {}

    async start(): Promise<void> {
        this.client = new PQCClientService(this.upstreamHost, this.upstreamPort, undefined, this.config);
        await this.client.connect();
        await this.client.waitForHandshake();

        this.server = net.createServer((localSocket) => {
            localSocket.on('data', async (chunk) => {
                try {
                    await this.client!.sendRaw(Buffer.from(chunk.toString('utf8')), 'sidecar');
                } catch (err) {
                    this.logger.error('Sidecar forward failed', {
                        component: 'sidecar',
                        error: err instanceof Error ? err.message : String(err),
                    });
                    localSocket.end();
                }
            });
        });

        this.server.listen(this.listenPort, '127.0.0.1', () => {
            this.logger.info('PQC sidecar listening', { component: 'sidecar', port: this.listenPort });
        });
    }

    async stop(): Promise<void> {
        this.client?.disconnect();
        this.server?.close();
    }
}
