import { loadConfig } from './config';
import { PQCServerService } from './pqc_server_service';
import { PQCClientService } from './pqc_client_service';
import { IMPERIAL_CIPHER_CORPUS } from './imperial/research_corpus';
import { verifyLiboqsIntegrity } from './startup/verify_deps';

async function runPQC_MicroserviceDemo() {
    verifyLiboqsIntegrity();
    if (process.env.NODE_ENV !== 'production' && !process.env.NOMAD_DEV_MODE) {
        process.env.NOMAD_DEV_MODE = 'true';
    }
    const config = loadConfig();
    console.log('--- Nomad Cyber Algorithm — Imperial PQC + Aureon Occult Veil Demo ---\n');
    console.log(`[AUREON] Imperial cipher doctrine loaded: ${IMPERIAL_CIPHER_CORPUS.length} civilizational mappings`);
    console.log(`[AUREON] Layers active: Greek Scytale, Roman Augustan, Persian Seal, Egyptian Cartouche, Occult Veil`);
    console.log(`[CHAOS] Unpredictable cipher mode: ${config.chaosModeEnabled ? 'ACTIVE (no wire patterns)' : 'off'}\n`);

    const server = new PQCServerService(config);
    server.getRouter().register('nightingale', async (body) => {
        return Buffer.from(`[nightingale] Cleared: ${body.toString('utf8').slice(0, 40)}...`);
    });

    const qsCa = server.getQuantumSafeCA();
    const client = new PQCClientService('127.0.0.1', config.port, qsCa, config);
    server.registerClient(client.getClientSigPublicKey());
    server.start();

    try {
        await client.connect();
        await client.waitForHandshake();

        const secretMessage =
            'Access to Project Nightingale data requires Level 5 clearance. Quantum-resistant encryption validated.';
        await client.sendEncryptedMessage(secretMessage, 'nightingale');

        await new Promise((resolve) => setTimeout(resolve, 1500));

        const ticket = client.getSessionTicket();
        if (ticket) {
            console.log(`\n[DEMO] Session ticket issued (${ticket.slice(0, 24)}...). Resumption-ready.`);
        }

        console.log('\n[DEMO] Server metrics:', JSON.stringify(server.getMetrics(), null, 2));
    } catch (error) {
        console.error(`\n[DEMO] Failed: ${error instanceof Error ? error.message : String(error)}`);
        process.exitCode = 1;
    } finally {
        await client.disconnect();
        await server.stop();
    }
}

runPQC_MicroserviceDemo();
