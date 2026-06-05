import { loadConfig, loadTrustedRootFromPath } from './config';
import { QuantumSafeCA } from './crypto/qs_ca';
import { CryptoService } from './crypto/crypto_service';
import { PQCSidecar } from './sidecar/sidecar';
import { StructuredLogger } from './ops/logger';

async function main() {
    const config = loadConfig();
    const listenPort = parseInt(process.env.NOMAD_SIDECAR_PORT ?? '9443', 10);
    const upstreamHost = process.env.NOMAD_SIDECAR_UPSTREAM_HOST ?? '127.0.0.1';
    const upstreamPort = parseInt(process.env.NOMAD_SIDECAR_UPSTREAM_PORT ?? String(config.port), 10);

    const crypto = new CryptoService(config.algorithmSuite);
    const qsCa = config.qsCaRootPath
        ? QuantumSafeCA.fromTrustedRoot(crypto, loadTrustedRootFromPath(config.qsCaRootPath))
        : new QuantumSafeCA(crypto);

    const sidecar = new PQCSidecar(
        listenPort,
        upstreamHost,
        upstreamPort,
        qsCa,
        config,
        new StructuredLogger(config.logLevel)
    );
    await sidecar.start();

    process.on('SIGINT', async () => {
        await sidecar.stop();
        process.exit(0);
    });
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
