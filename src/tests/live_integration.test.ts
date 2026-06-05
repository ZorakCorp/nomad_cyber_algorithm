import * as http from 'http';
import { loadConfig } from '../config';
import { SovereignStack } from '../sovereign_stack';
import { PQCClientService } from '../pqc_client_service';
import { generateTotp } from '../console/console_auth';
import { assert, runTests, TestCase } from './test_runner';
import { applyTestConsoleEnv, TEST_CONSOLE_PASSWORD, TEST_CONSOLE_TOTP } from './test_credentials';
import { verifyLiboqsIntegrity } from '../startup/verify_deps';

function httpGet(port: number, path: string, headers: Record<string, string> = {}): Promise<{ status: number; body: string }> {
    return new Promise((resolve, reject) => {
        const req = http.request(
            { hostname: '127.0.0.1', port, path, method: 'GET', headers },
            (res) => {
                const chunks: Buffer[] = [];
                res.on('data', (c) => chunks.push(c));
                res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
            }
        );
        req.on('error', reject);
        req.end();
    });
}

function httpPost(port: number, path: string, payload: unknown, headers: Record<string, string> = {}): Promise<{ status: number; body: string }> {
    return new Promise((resolve, reject) => {
        const data = JSON.stringify(payload);
        const req = http.request(
            {
                hostname: '127.0.0.1',
                port,
                path,
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data), ...headers },
            },
            (res) => {
                const chunks: Buffer[] = [];
                res.on('data', (c) => chunks.push(c));
                res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
            }
        );
        req.on('error', reject);
        req.write(data);
        req.end();
    });
}

const tests: TestCase[] = [
    {
        name: 'live: sovereign stack health + auth + PQC round-trip',
        fn: async () => {
            verifyLiboqsIntegrity();
            applyTestConsoleEnv();
            process.env.NOMAD_PORT = '18443';
            process.env.NOMAD_GATEWAY_PORT = '18080';
            process.env.NOMAD_CONSOLE_PORT = '18081';
            process.env.NOMAD_HEALTH_PORT = '19090';

            const config = loadConfig();
            const stack = await SovereignStack.create(config);
            const qsCa = stack.getPqc().getQuantumSafeCA();
            const client = new PQCClientService('127.0.0.1', config.port, qsCa, config);
            stack.getPqc().registerClient(client.getClientSigPublicKey());
            stack.start();

            try {
                const health = await httpGet(config.gatewayPort, '/health');
                assert(health.status === 200, 'health ok');
                assert(health.body.includes('chaosMode'), 'health reports chaos');

                const forged = await httpGet(config.gatewayPort, '/api/audit', {
                    Authorization: 'Bearer attacker:admin',
                });
                assert(forged.status === 403, 'forged bearer rejected');

                const login = await httpPost(config.consolePort, '/console/login', {
                    username: 'admin',
                    password: TEST_CONSOLE_PASSWORD,
                });
                assert(login.status === 200, 'console login');
                const loginJson = JSON.parse(login.body) as { sessionToken: string; mfaRequired: boolean };
                assert(!!loginJson.sessionToken, 'session token issued');

                if (loginJson.mfaRequired) {
                    const totp = generateTotp(process.env.NOMAD_CONSOLE_ADMIN_TOTP ?? 'NOMAD-DEV-TOTP-SECRET');
                    const mfa = await httpPost(config.consolePort, '/console/mfa', {
                        sessionToken: loginJson.sessionToken,
                        code: totp,
                    });
                    assert(mfa.status === 200, 'MFA ok');
                }

                const authed = await httpGet(config.gatewayPort, '/metrics', {
                    Authorization: `Bearer ${loginJson.sessionToken}`,
                });
                assert(authed.status === 200, 'valid session reaches metrics');

                await client.connect();
                await client.waitForHandshake();
                await client.sendEncryptedMessage('live integration probe', 'default');
                await new Promise((r) => setTimeout(r, 300));
                await client.disconnect();

                const metrics = stack.getPqc().getMetrics();
                assert(metrics.handshakesSucceeded >= 1, 'PQC handshake succeeded');
            } finally {
                await stack.stop();
            }
        },
    },
    {
        name: 'live: vault download rejects invalid object id',
        fn: async () => {
            applyTestConsoleEnv();
            process.env.NOMAD_PORT = '28443';
            process.env.NOMAD_GATEWAY_PORT = '28080';
            process.env.NOMAD_CONSOLE_PORT = '28081';
            process.env.NOMAD_HEALTH_PORT = '29090';

            const config = loadConfig();
            const stack = await SovereignStack.create(config);
            stack.start();

            try {
                const login = await httpPost(config.consolePort, '/console/login', {
                    username: 'admin',
                    password: TEST_CONSOLE_PASSWORD,
                });
                const { sessionToken, mfaRequired } = JSON.parse(login.body) as { sessionToken: string; mfaRequired: boolean };
                if (mfaRequired) {
                    const totp = generateTotp(TEST_CONSOLE_TOTP);
                    await httpPost(config.consolePort, '/console/mfa', { sessionToken, code: totp });
                }

                const bad = await httpGet(config.gatewayPort, '/vault/download?id=../../etc/passwd', {
                    Authorization: `Bearer ${sessionToken}`,
                });
                assert(bad.status === 400, 'path traversal blocked');
            } finally {
                await stack.stop();
            }
        },
    },
];

runTests(tests);
