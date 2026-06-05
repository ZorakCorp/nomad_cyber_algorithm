import * as net from 'net';
import { PQCClientService } from '../pqc_client_service';
import { NomadConfig } from '../config';
import { QuantumSafeCA } from '../crypto/qs_ca';
import { StructuredLogger } from '../ops/logger';

/**
 * Transparent TCP sidecar — one isolated PQC session per local connection.
 */
export class PQCSidecar {
    private server: net.Server | null = null;
    private activeClients = new Set<PQCClientService>();

    constructor(
        private listenPort: number,
        private upstreamHost: string,
        private upstreamPort: number,
        private qsCa: QuantumSafeCA,
        private config: NomadConfig,
        private logger: StructuredLogger
    ) {}

    async start(): Promise<void> {
        if (!this.qsCa) {
            throw new Error('QS-CA is required for sidecar upstream trust.');
        }

        this.server = net.createServer((localSocket) => {
            void this.handleLocalConnection(localSocket);
        });

        this.server.listen(this.listenPort, '127.0.0.1', () => {
            this.logger.info('PQC sidecar listening', { component: 'sidecar', port: this.listenPort });
        });
    }

    private async handleLocalConnection(localSocket: net.Socket): Promise<void> {
        let localClosed = false;
        const client = new PQCClientService(this.upstreamHost, this.upstreamPort, this.qsCa, this.config);
        this.activeClients.add(client);

        try {
            await client.connect();
            await client.waitForHandshake();

            client.setApplicationResponseHandler((body, serviceId) => {
                if (localClosed || serviceId !== 'sidecar') return;
                localSocket.write(body);
            });

            localSocket.on('data', async (chunk) => {
                try {
                    await client.sendRaw(Buffer.from(chunk), 'sidecar');
                } catch (err) {
                    this.logger.error('Sidecar forward failed', {
                        component: 'sidecar',
                        error: err instanceof Error ? err.message : String(err),
                    });
                    localSocket.end();
                }
            });
        } catch (err) {
            this.logger.error('Sidecar PQC session failed', {
                component: 'sidecar',
                error: err instanceof Error ? err.message : String(err),
            });
            localSocket.end();
            await client.disconnect();
            this.activeClients.delete(client);
            return;
        }

        const cleanup = async () => {
            localClosed = true;
            this.activeClients.delete(client);
            await client.disconnect();
        };

        localSocket.on('close', () => { void cleanup(); });
        localSocket.on('error', () => { void cleanup(); });
    }

    async stop(): Promise<void> {
        await Promise.all([...this.activeClients].map((c) => c.disconnect()));
        this.activeClients.clear();
        this.server?.close();
    }
}
