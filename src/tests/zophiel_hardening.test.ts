import { randomBytes } from 'crypto';
import { validateStartupSecretsOrThrow } from '../console/console_auth';
import { DbVault } from '../data/db_vault';
import { AuditLog } from '../ops/audit_log';
import { SessionStore } from '../session/session_store';
import { verifyLiboqsIntegrity } from '../startup/verify_deps';
import { applyTestConsoleEnv, TEST_CONSOLE_PASSWORD, TEST_CONSOLE_TOTP } from './test_credentials';
import { assert, assertThrows, runTests, TestCase } from './test_runner';

const tests: TestCase[] = [
    {
        name: 'zophiel: liboqs integrity self-test passes',
        fn: () => {
            verifyLiboqsIntegrity();
        },
    },
    {
        name: 'zophiel: rejects missing console password',
        fn: () => {
            delete process.env.NOMAD_CONSOLE_ADMIN_PASSWORD;
            process.env.NOMAD_CONSOLE_ADMIN_TOTP = TEST_CONSOLE_TOTP;
            assertThrows(() => validateStartupSecretsOrThrow(), 'missing password');
        },
    },
    {
        name: 'zophiel: rejects short console password',
        fn: () => {
            process.env.NOMAD_CONSOLE_ADMIN_PASSWORD = 'short';
            process.env.NOMAD_CONSOLE_ADMIN_TOTP = TEST_CONSOLE_TOTP;
            assertThrows(() => validateStartupSecretsOrThrow(), 'short password');
        },
    },
    {
        name: 'zophiel: rejects forbidden password substrings',
        fn: () => {
            process.env.NOMAD_CONSOLE_ADMIN_PASSWORD = 'ThisIsAVeryLongDefaultPassword!!';
            process.env.NOMAD_CONSOLE_ADMIN_TOTP = TEST_CONSOLE_TOTP;
            assertThrows(() => validateStartupSecretsOrThrow(), 'forbidden word');
        },
    },
    {
        name: 'zophiel: accepts valid startup secrets',
        fn: () => {
            applyTestConsoleEnv();
            const result = validateStartupSecretsOrThrow();
            assert(result.password === TEST_CONSOLE_PASSWORD, 'password ok');
            assert(result.totp === TEST_CONSOLE_TOTP, 'totp ok');
        },
    },
    {
        name: 'zophiel: session store fromEnv works in dev',
        fn: () => {
            process.env.NOMAD_DEV_MODE = 'true';
            delete process.env.NOMAD_SESSION_MASTER_KEY;
            const store = SessionStore.fromEnv();
            const ticket = store.issue('c', Buffer.alloc(32), 'cpk', 'spk', 60_000);
            assert(!!store.redeem(ticket), 'ticket round-trip');
        },
    },
    {
        name: 'zophiel: db vault ephemeral dev warning path',
        fn: () => {
            const audit = new AuditLog(null);
            const vault = new DbVault({ audit, devMode: true });
            const sealed = vault.encryptField('t', 'c', 'value', 'tenant');
            assert(sealed.length > 0, 'sealed');
        },
    },
    {
        name: 'zophiel: session generateKey returns 64 hex chars',
        fn: () => {
            const key = SessionStore.generateKey();
            assert(/^[0-9a-f]{64}$/.test(key), 'hex key');
        },
    },
];

runTests(tests);
