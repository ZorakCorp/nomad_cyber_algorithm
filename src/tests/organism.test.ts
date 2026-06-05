import { randomBytes } from 'crypto';
import { assert, runTests, TestCase } from './test_runner';
import { AuditLog } from '../ops/audit_log';
import { loadConfig } from '../config';
import { applyTestConsoleEnv } from './test_credentials';
import { SovereignOrganism } from '../organism/sovereign_organism';
import { CryptoService } from '../crypto/crypto_service';
import { QuantumSafeCA } from '../crypto/qs_ca';
import { StructuredLogger } from '../ops/logger';
import { organActivationOrder, dependenciesSatisfied, ORGAN_DEPENDENCIES } from '../organism/organ_registry';
import { LockdownGuard } from '../organism/vital_guard';
import { ConsoleAuthService } from '../console/console_auth';

const tests: TestCase[] = [
    {
        name: 'organism: activation order respects dependency graph',
        fn: () => {
            const order = organActivationOrder();
            for (const organId of order) {
                const deps = ORGAN_DEPENDENCIES[organId];
                for (const dep of deps) {
                    assert(order.indexOf(dep) < order.indexOf(organId), `${dep} must precede ${organId}`);
                }
            }
        },
    },
    {
        name: 'organism: awakens with all organs vital in dev mode',
        fn: async () => {
            applyTestConsoleEnv();
            const config = loadConfig();
            const audit = new AuditLog(null);
            const crypto = new CryptoService(config.algorithmSuite);
            const qsCa = new QuantumSafeCA(crypto);
            const logger = new StructuredLogger('error');
            const consoleAuth = await ConsoleAuthService.create(config, audit);
            const organism = new SovereignOrganism(
                config,
                { audit, ctLog: qsCa.ctLog, webauthnReady: () => consoleAuth.webauthn.hasCredentials('admin') },
                logger
            );
            await organism.awaken();
            assert(organism.isVital(), 'organism vital after awaken');
            const report = organism.getVitalsReport();
            assert(report.organs.length === 11, 'eleven organs registered');
            assert(report.organs.every((o) => o.state === 'vital' || o.state === 'dormant'), 'all organs healthy');
            organism.stopPulse();
        },
    },
    {
        name: 'organism: lockdown blocks all protected operations',
        fn: () => {
            const guard = new LockdownGuard('simulated multi-organ breach');
            assert(!guard.isVital(), 'not vital');
            let threw = false;
            try {
                guard.requireVital('test.operation');
            } catch {
                threw = true;
            }
            assert(threw, 'requireVital throws under lockdown');
        },
    },
    {
        name: 'organism: audit chain break triggers lockdown on pulse',
        fn: async () => {
            applyTestConsoleEnv();
            const config = loadConfig();
            process.env.NOMAD_AUDIT_CHAIN_KEY = randomBytes(32).toString('hex');
            const audit = new AuditLog(null);
            audit.record('handshake_started', { detail: 'probe' });
            const crypto = new CryptoService(config.algorithmSuite);
            const qsCa = new QuantumSafeCA(crypto);
            const logger = new StructuredLogger('error');
            const organism = new SovereignOrganism(config, { audit, ctLog: qsCa.ctLog }, logger);
            await organism.pulse();
            assert(organism.isVital(), 'intact chain is vital');

            const events = audit.query(10);
            const tampered = events[events.length - 1];
            tampered.entryMac = 'deadbeef'.repeat(8);
            (audit as unknown as { entries: typeof events }).entries[events.length - 1] = tampered;

            await organism.pulse();
            assert(!organism.isVital(), 'tampered audit triggers lockdown');
            organism.stopPulse();
        },
    },
    {
        name: 'organism: dependenciesSatisfied requires parent organs',
        fn: () => {
            const statuses = new Map();
            for (const id of organActivationOrder()) {
                statuses.set(id, {
                    id,
                    name: id,
                    role: id,
                    state: 'pending' as const,
                    dependsOn: ORGAN_DEPENDENCIES[id],
                    lastPulse: '',
                });
            }
            assert(!dependenciesSatisfied('pqc_lungs', statuses), 'pqc blocked without parents');
            statuses.get('crypto_core')!.state = 'vital';
            statuses.get('audit_immune')!.state = 'vital';
            statuses.get('tpm_skeletal')!.state = 'dormant';
            statuses.get('hsm_heart')!.state = 'dormant';
            statuses.get('ca_liver')!.state = 'vital';
            assert(dependenciesSatisfied('pqc_lungs', statuses), 'pqc allowed when parents vital/dormant');
        },
    },
];

void runTests(tests);
