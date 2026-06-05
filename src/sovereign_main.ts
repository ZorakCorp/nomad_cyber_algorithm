import { loadConfig } from './config';
import { SovereignStack } from './sovereign_stack';
import { PQCClientService } from './pqc_client_service';
import { generateTotp } from './console/console_auth';
import { IMPERIAL_CIPHER_CORPUS } from './imperial/research_corpus';
import { applyTestConsoleEnv, TEST_CONSOLE_PASSWORD, TEST_CONSOLE_TOTP } from './tests/test_credentials';

async function runSovereignDemo() {
    applyTestConsoleEnv();
    const config = loadConfig();
    console.log('--- Nomad Sovereign Organism — Interlocking Security Organs ---\n');
    console.log(`[AUREON] Civilizational mappings: ${IMPERIAL_CIPHER_CORPUS.length}`);
    console.log(`[CHAOS] Unpredictable layer order, padding, timing jitter: ${config.chaosModeEnabled ? 'ACTIVE' : 'off'}`);
    console.log(`[STACK] Gateway :${config.gatewayPort} | Console :${config.consolePort} | PQC :${config.port}\n`);

    const stack = await SovereignStack.create(config);
    console.log(`[ORGANISM] Vital: ${stack.organism.isVital()} | Fingerprint: ${stack.organism.getFingerprint().slice(0, 16)}...`);
    console.log(`[ORGANISM] Organs: ${stack.organism.getVitalsReport().organs.map((o) => `${o.name}=${o.state}`).join(' · ')}\n`);
    stack.getPqc().getRouter().register('sovereign', async (body) => {
        return Buffer.from(`[sovereign] ${body.length} bytes through chaos cipher.`);
    });

    const qsCa = stack.getPqc().getQuantumSafeCA();
    const client = new PQCClientService('127.0.0.1', config.port, qsCa, config);
    stack.getPqc().registerClient(client.getClientSigPublicKey());
    stack.start();

    try {
        await client.connect();
        await client.waitForHandshake();
        await client.sendEncryptedMessage('Sovereign channel — no wire patterns.', 'sovereign');
        await new Promise((r) => setTimeout(r, 500));

        const login = await stack.consoleAuth.login('admin', TEST_CONSOLE_PASSWORD);
        if (login?.mfaRequired) {
            const totp = generateTotp(TEST_CONSOLE_TOTP);
            stack.consoleAuth.verifyMfa(login.sessionToken, totp);
            console.log('[CONSOLE] MFA verified');
        }

        const sealed = stack.dbVault.encryptField('demo', 'secret', 'Project Nightingale', 'tenant-1');
        console.log(`[DB VAULT] Field sealed (${sealed.slice(0, 24)}...)`);

        const objectId = await stack.fileVault.store('briefing.txt', Buffer.from('Classified payload'), 'admin');
        console.log(`[FILE VAULT] Stored object ${objectId}`);

        console.log('\n[DEMO] Metrics:', JSON.stringify(stack.getPqc().getMetrics(), null, 2));
    } catch (err) {
        console.error(`\n[DEMO] Failed: ${err instanceof Error ? err.message : String(err)}`);
        process.exitCode = 1;
    } finally {
        await client.disconnect();
        await stack.stop();
    }
}

runSovereignDemo();
