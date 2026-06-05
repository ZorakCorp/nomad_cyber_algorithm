/**
 * Battle Test — red-team assault against the Sovereign Organism.
 * Simulates simultaneous attack vectors; organism must survive or lock down completely.
 */

import * as http from 'http';
import * as net from 'net';
import { randomBytes } from 'crypto';
import { loadConfig } from '../config';
import { SovereignStack } from '../sovereign_stack';
import { PQCClientService } from '../pqc_client_service';
import { generateTotp } from '../console/console_auth';
import { assert, runTests, TestCase } from './test_runner';
import { applyTestConsoleEnv, TEST_CONSOLE_PASSWORD, TEST_CONSOLE_TOTP } from './test_credentials';

const BATTLE_PORTS = { pqc: 38443, gw: 38080, console: 38081, health: 39090 };

function httpReq(
    port: number,
    method: string,
    path: string,
    payload?: unknown,
    headers: Record<string, string> = {}
): Promise<{ status: number; body: string }> {
    return new Promise((resolve, reject) => {
        const data = payload ? JSON.stringify(payload) : '';
        const req = http.request(
            {
                hostname: '127.0.0.1',
                port,
                path,
                method,
                headers: {
                    ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}),
                    ...headers,
                },
            },
            (res) => {
                const chunks: Buffer[] = [];
                res.on('data', (c) => chunks.push(c));
                res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
            }
        );
        req.on('error', reject);
        if (data) req.write(data);
        req.end();
    });
}

async function bootStack(): Promise<{ stack: SovereignStack; config: ReturnType<typeof loadConfig> }> {
    applyTestConsoleEnv();
    process.env.NOMAD_PORT = String(BATTLE_PORTS.pqc);
    process.env.NOMAD_GATEWAY_PORT = String(BATTLE_PORTS.gw);
    process.env.NOMAD_CONSOLE_PORT = String(BATTLE_PORTS.console);
    process.env.NOMAD_HEALTH_PORT = String(BATTLE_PORTS.health);
    process.env.NOMAD_ORGANISM_PULSE_MS = '60000';
    const config = loadConfig();
    const stack = await SovereignStack.create(config);
    stack.start();
    return { stack, config };
}

async function loginAdmin(consolePort: number): Promise<string> {
    const login = await httpReq(consolePort, 'POST', '/console/login', {
        username: 'admin',
        password: TEST_CONSOLE_PASSWORD,
    });
    assert(login.status === 200, 'battle login');
    const { sessionToken, mfaRequired } = JSON.parse(login.body) as { sessionToken: string; mfaRequired: boolean };
    if (mfaRequired) {
        const mfa = await httpReq(consolePort, 'POST', '/console/mfa', {
            sessionToken,
            code: generateTotp(TEST_CONSOLE_TOTP),
        });
        assert(mfa.status === 200, 'battle MFA');
    }
    return sessionToken;
}

const tests: TestCase[] = [
    {
        name: 'BATTLE: forged bearer tokens rejected at gateway',
        fn: async () => {
            const { stack, config } = await bootStack();
            try {
                const attacks = [
                    'Bearer attacker:admin',
                    'Bearer admin:sovereign',
                    'Bearer ' + 'x'.repeat(64),
                    'Bearer ../../../etc/passwd',
                ];
                for (const auth of attacks) {
                    const res = await httpReq(config.gatewayPort, 'GET', '/api/audit', undefined, { Authorization: auth });
                    assert(res.status === 403, `forged rejected: ${auth.slice(0, 30)}`);
                }
            } finally {
                await stack.stop();
            }
        },
    },
    {
        name: 'BATTLE: wrong password + wrong TOTP assault fails',
        fn: async () => {
            const { stack, config } = await bootStack();
            try {
                for (let i = 0; i < 5; i++) {
                    const bad = await httpReq(config.consolePort, 'POST', '/console/login', {
                        username: 'admin',
                        password: 'TotallyWrongPassword123!!',
                    });
                    assert(bad.status === 401, `bad password attempt ${i}`);
                }
                const ok = await httpReq(config.consolePort, 'POST', '/console/login', {
                    username: 'admin',
                    password: TEST_CONSOLE_PASSWORD,
                });
                const { sessionToken } = JSON.parse(ok.body) as { sessionToken: string };
                for (let i = 0; i < 3; i++) {
                    const badMfa = await httpReq(config.consolePort, 'POST', '/console/mfa', {
                        sessionToken,
                        code: '000000',
                    });
                    assert(badMfa.status === 401, `bad TOTP attempt ${i}`);
                }
            } finally {
                await stack.stop();
            }
        },
    },
    {
        name: 'BATTLE: unauthenticated gateway routes blocked',
        fn: async () => {
            const { stack, config } = await bootStack();
            try {
                const protectedRoutes: Array<[string, string]> = [
                    ['GET', '/metrics'],
                    ['GET', '/api/audit'],
                    ['POST', '/api/encrypt'],
                    ['GET', '/vault/download?id=abc'],
                ];
                for (const [method, path] of protectedRoutes) {
                    const res = await httpReq(config.gatewayPort, method, path, method === 'POST' ? {} : undefined);
                    assert(res.status === 403, `unauth blocked: ${method} ${path}`);
                }
                const vitals = await httpReq(config.gatewayPort, 'GET', '/organism/vitals');
                assert(vitals.status === 200, 'vitals public');
                assert(vitals.body.includes('doctrine'), 'vitals exposes doctrine');
            } finally {
                await stack.stop();
            }
        },
    },
    {
        name: 'BATTLE: audit tamper triggers organism lockdown — all routes die',
        fn: async () => {
            const { stack, config } = await bootStack();
            try {
                const token = await loginAdmin(config.consolePort);
                assert(stack.organism.isVital(), 'vital before tamper');

                const events = stack.audit.query(10);
                const last = events[events.length - 1];
                last.entryMac = 'ff'.repeat(32);
                (stack.audit as unknown as { entries: typeof events }).entries[events.length - 1] = last;

                await stack.organism.pulse();
                assert(!stack.organism.isVital(), 'lockdown after audit tamper');

                const metrics = await httpReq(config.gatewayPort, 'GET', '/metrics', undefined, {
                    Authorization: `Bearer ${token}`,
                });
                assert(metrics.status === 503, 'gateway lockdown 503');
                assert(metrics.body.includes('ORGANISM_LOCKDOWN'), 'lockdown message');

                let vaultThrew = false;
                try {
                    stack.dbVault.encryptField('battle', 'field', 'secret', 'attacker');
                } catch (err) {
                    vaultThrew = (err instanceof Error ? err.message : '').includes('ORGANISM_LOCKDOWN');
                }
                assert(vaultThrew, 'vault blocked under lockdown');

                let pqcRejected = false;
                await new Promise<void>((resolve) => {
                    const socket = net.connect(config.port, '127.0.0.1');
                    socket.on('connect', () => setTimeout(() => {
                        pqcRejected = !socket.readable;
                        socket.destroy();
                        resolve();
                    }, 200));
                    socket.on('error', () => { pqcRejected = true; resolve(); });
                });
                assert(pqcRejected, 'PQC rejects under lockdown');
            } finally {
                await stack.stop();
            }
        },
    },
    {
        name: 'BATTLE: path traversal + SQLi probes rejected',
        fn: async () => {
            const { stack, config } = await bootStack();
            try {
                const token = await loginAdmin(config.consolePort);
                const probes = [
                    '/vault/download?id=../../etc/passwd',
                    '/vault/download?id=%00deadbeef',
                    `/vault/download?id=${encodeURIComponent("' OR 1=1--")}`,
                    '/vault/download?id=not-hex!',
                ];
                for (const path of probes) {
                    let status = 0;
                    try {
                        const res = await httpReq(config.gatewayPort, 'GET', path, undefined, {
                            Authorization: `Bearer ${token}`,
                        });
                        status = res.status;
                    } catch {
                        status = 0;
                    }
                    assert(
                        status === 0 || status === 400 || status === 403 || status === 404,
                        `probe blocked: ${path} (status ${status})`
                    );
                }
            } finally {
                await stack.stop();
            }
        },
    },
    {
        name: 'BATTLE: oversized payload rejected',
        fn: async () => {
            const { stack, config } = await bootStack();
            try {
                const token = await loginAdmin(config.consolePort);
                const huge = { field: 'x', value: 'A'.repeat(200_000) };
                let blocked = false;
                try {
                    const res = await httpReq(config.gatewayPort, 'POST', '/api/encrypt', huge, {
                        Authorization: `Bearer ${token}`,
                    });
                    blocked = res.status === 413 || res.status === 403;
                } catch {
                    blocked = true;
                }
                assert(blocked, 'oversized payload rejected or connection dropped');
            } finally {
                await stack.stop();
            }
        },
    },
    {
        name: 'BATTLE: concurrent PQC handshake storm (5 clients)',
        fn: async () => {
            const { stack, config } = await bootStack();
            const qsCa = stack.getPqc().getQuantumSafeCA();
            const clients: PQCClientService[] = [];
            try {
                for (let i = 0; i < 5; i++) {
                    const client = new PQCClientService('127.0.0.1', config.port, qsCa, config);
                    stack.getPqc().registerClient(client.getClientSigPublicKey());
                    clients.push(client);
                }
                const results = await Promise.allSettled(
                    clients.map(async (c, i) => {
                        await c.connect();
                        await c.waitForHandshake();
                        await c.sendEncryptedMessage(`storm-${i}`, 'default');
                        await c.disconnect();
                    })
                );
                const succeeded = results.filter((r) => r.status === 'fulfilled').length;
                assert(succeeded >= 3, `at least 3/5 handshakes succeeded (got ${succeeded})`);
                assert(stack.getPqc().getMetrics().handshakesSucceeded >= 3, 'metrics reflect storm');
            } finally {
                for (const c of clients) {
                    try { await c.disconnect(); } catch { /* ignore */ }
                }
                await stack.stop();
            }
        },
    },
    {
        name: 'BATTLE: DDoS connection storm — server survives and stays vital',
        fn: async () => {
            const { stack, config } = await bootStack();
            try {
                const burst = 150;
                const results = await Promise.all(
                    Array.from({ length: burst }, () =>
                        httpReq(config.gatewayPort, 'GET', '/health').catch(() => ({ status: 0, body: '' }))
                    )
                );
                const ok = results.filter((r) => r.status === 200).length;
                const throttled = results.filter((r) => r.status === 429).length;
                const responded = ok + throttled;
                const crashed = results.filter((r) => r.status === 0).length;
                assert(responded > burst * 0.85, `server responded to flood (${responded}/${burst}, ${throttled} throttled)`);
                assert(crashed < burst * 0.05, `minimal crash under storm (${crashed} errors)`);
                assert(stack.organism.isVital(), 'organism still vital after DDoS storm');
                const post = await httpReq(config.gatewayPort, 'GET', '/organism/vitals');
                assert(post.status === 200 && post.body.includes('"vital":true'), 'vitals confirm survival');
            } finally {
                await stack.stop();
            }
        },
    },
    {
        name: 'BATTLE: full happy-path survives assault then operates',
        fn: async () => {
            const { stack, config } = await bootStack();
            const qsCa = stack.getPqc().getQuantumSafeCA();
            const client = new PQCClientService('127.0.0.1', config.port, qsCa, config);
            stack.getPqc().registerClient(client.getClientSigPublicKey());
            try {
                assert(stack.organism.isVital(), 'organism vital');
                const vitals = JSON.parse((await httpReq(config.gatewayPort, 'GET', '/organism/vitals')).body) as {
                    vital: boolean;
                    organs: Array<{ state: string }>;
                };
                assert(vitals.vital, 'vitals report vital');
                assert(vitals.organs.length === 11, '11 organs');

                const token = await loginAdmin(config.consolePort);
                await client.connect();
                await client.waitForHandshake();
                await client.sendEncryptedMessage('battle probe', 'default');

                const sealed = stack.dbVault.encryptField('battle', 'secret', 'classified', 'admin');
                assert(sealed.length > 20, 'vault seal works');
                const objectId = await stack.fileVault.store('battle.txt', Buffer.from('payload'), 'admin');
                assert(objectId.length === 24, 'file vault store');

                const dl = await httpReq(config.gatewayPort, 'GET', `/vault/download?id=${objectId}`, undefined, {
                    Authorization: `Bearer ${token}`,
                });
                assert(dl.status === 200, 'vault download via gateway');

                const chain = stack.audit.verifyChain();
                assert(chain.valid, 'audit chain intact after battle');
            } finally {
                await client.disconnect();
                await stack.stop();
            }
        },
    },
];

console.log('\n╔══════════════════════════════════════════════════════════╗');
console.log('║  NOMAD BATTLE TEST — Red Team vs Sovereign Organism      ║');
console.log('╚══════════════════════════════════════════════════════════╝\n');

void runTests(tests).then(() => {
    console.log('\n[BATTLE] Red-team assault complete.\n');
});
